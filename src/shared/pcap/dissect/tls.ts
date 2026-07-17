import type { Dissection, TlsInfo } from '../model'

function versionName(v: number): string {
  switch (v) {
    case 0x0300:
      return 'SSL 3.0'
    case 0x0301:
      return 'TLS 1.0'
    case 0x0302:
      return 'TLS 1.1'
    case 0x0303:
      return 'TLS 1.2'
    case 0x0304:
      return 'TLS 1.3'
    default:
      return `0x${v.toString(16)}`
  }
}

// A subset of common cipher suites; unknowns are shown by hex value. Weakness is
// classified by keyword so we don't need the full IANA registry.
const CIPHER_NAMES: Record<number, string> = {
  0x0000: 'TLS_NULL_WITH_NULL_NULL',
  0x0004: 'TLS_RSA_WITH_RC4_128_MD5',
  0x0005: 'TLS_RSA_WITH_RC4_128_SHA',
  0x000a: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
  0x002f: 'TLS_RSA_WITH_AES_128_CBC_SHA',
  0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
  0x009c: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
  0x009d: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
  0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
  0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
  0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
  0x1301: 'TLS_AES_128_GCM_SHA256',
  0x1302: 'TLS_AES_256_GCM_SHA384',
  0x1303: 'TLS_CHACHA20_POLY1305_SHA256'
}

function cipherName(v: number): string {
  return CIPHER_NAMES[v] ?? `0x${v.toString(16).padStart(4, '0')}`
}

function isWeakCipher(v: number): boolean {
  const name = CIPHER_NAMES[v]
  if (name && /RC4|3DES|_DES_|NULL|EXPORT|MD5|_CBC_SHA$/.test(name)) return true
  // Known weak/export ranges without explicit names.
  if (v >= 0x0001 && v <= 0x000b) return true
  return false
}

export function dissectTls(d: Dissection, payload: Buffer, full: boolean): boolean {
  if (payload.length < 6) return false
  const contentType = payload[0]
  if (contentType !== 0x16) return false // only handshake records
  const recVersion = payload.readUInt16BE(1)
  if (recVersion < 0x0300 || recVersion > 0x0304) return false
  const hsType = payload[5]
  if (hsType !== 1 && hsType !== 2) {
    // Handshake but not Client/ServerHello.
    d.protocol = 'TLS'
    d.info = 'TLS handshake'
    return true
  }

  let offeredVersion = recVersion
  let sni: string | undefined
  const cipherSuites: string[] = []
  let chosenCipher: string | undefined
  let weak = false

  try {
    // Handshake body starts at offset 9 (record hdr 5 + hs hdr 4).
    let p = 9
    const bodyVersion = payload.readUInt16BE(p)
    offeredVersion = bodyVersion
    p += 2
    p += 32 // random
    const sidLen = payload[p]
    p += 1 + sidLen

    if (hsType === 1) {
      // ClientHello
      const csLen = payload.readUInt16BE(p)
      p += 2
      for (let i = 0; i + 1 < csLen; i += 2) {
        const cs = payload.readUInt16BE(p + i)
        cipherSuites.push(cipherName(cs))
        if (isWeakCipher(cs)) weak = true
      }
      p += csLen
      const compLen = payload[p]
      p += 1 + compLen
      if (p + 2 <= payload.length) {
        const extLen = payload.readUInt16BE(p)
        p += 2
        const parsed = parseExtensions(payload, p, p + extLen)
        if (parsed.sni) sni = parsed.sni
        if (parsed.supportedMax) offeredVersion = parsed.supportedMax
      }
    } else {
      // ServerHello
      const cs = payload.readUInt16BE(p)
      chosenCipher = cipherName(cs)
      if (isWeakCipher(cs)) weak = true
      p += 3 // cipher(2) + compression(1)
      if (p + 2 <= payload.length) {
        const extLen = payload.readUInt16BE(p)
        p += 2
        const parsed = parseExtensions(payload, p, p + extLen)
        if (parsed.supportedMax) offeredVersion = parsed.supportedMax
      }
    }
  } catch {
    /* tolerate truncation */
  }

  if (offeredVersion < 0x0303) weak = true

  const tls: TlsInfo = {
    kind: hsType === 1 ? 'client-hello' : 'server-hello',
    sni,
    version: versionName(offeredVersion),
    versionRaw: offeredVersion,
    cipherSuites,
    chosenCipher,
    weak
  }
  d.tls = tls
  d.protocol = 'TLS'
  d.info =
    hsType === 1
      ? `Client Hello${sni ? ` (SNI: ${sni})` : ''} ${versionName(offeredVersion)}`
      : `Server Hello ${versionName(offeredVersion)}${chosenCipher ? ` ${chosenCipher}` : ''}`

  if (full) {
    const fields = [
      { label: 'Handshake', value: hsType === 1 ? 'Client Hello' : 'Server Hello' },
      { label: 'Version', value: versionName(offeredVersion) }
    ]
    if (sni) fields.push({ label: 'Server Name (SNI)', value: sni })
    if (chosenCipher) fields.push({ label: 'Cipher', value: chosenCipher })
    if (cipherSuites.length)
      fields.push({ label: 'Cipher Suites', value: `${cipherSuites.length} offered` })
    if (weak) fields.push({ label: '⚠ Weak', value: 'Obsolete version or weak cipher' })
    d.layers.push({ name: 'TLS', summary: d.info, fields })
  }
  return true
}

function parseExtensions(
  buf: Buffer,
  start: number,
  end: number
): { sni?: string; supportedMax?: number } {
  let p = start
  let sni: string | undefined
  let supportedMax: number | undefined
  while (p + 4 <= end && p + 4 <= buf.length) {
    const type = buf.readUInt16BE(p)
    const len = buf.readUInt16BE(p + 2)
    p += 4
    if (p + len > buf.length) break
    if (type === 0x0000 && len > 5) {
      // SNI: list length(2), name type(1), name length(2), name
      const nameLen = buf.readUInt16BE(p + 3)
      if (p + 5 + nameLen <= buf.length) {
        sni = buf.toString('ascii', p + 5, p + 5 + nameLen)
      }
    } else if (type === 0x002b && len >= 1) {
      // supported_versions: list length(1) then 2-byte versions
      const listLen = buf[p]
      let best = 0
      for (let i = 1; i + 1 <= listLen && p + i + 1 < buf.length; i += 2) {
        const v = buf.readUInt16BE(p + 1 + i - 1)
        if (v >= 0x0300 && v <= 0x0304 && v > best) best = v
      }
      if (best) supportedMax = best
    }
    p += len
  }
  return { sni, supportedMax }
}
