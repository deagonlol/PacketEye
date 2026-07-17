import type { CleartextInfo, Dissection } from '../model'
import { asciiPreview } from './util'

/** Strip Telnet IAC command sequences (0xFF ...) leaving typed text. */
function stripTelnet(payload: Buffer): string {
  const out: number[] = []
  for (let i = 0; i < payload.length; i++) {
    if (payload[i] === 0xff) {
      i += 2 // skip IAC + command (+ option handled loosely)
      continue
    }
    out.push(payload[i])
  }
  return asciiPreview(Buffer.from(out), 200)
}

export function dissectCleartext(
  d: Dissection,
  payload: Buffer,
  srcPort: number,
  dstPort: number,
  full: boolean
): boolean {
  if (payload.length === 0) return false
  const port = wellKnown(srcPort, dstPort)
  if (!port) return false

  let info: CleartextInfo | null = null
  switch (port) {
    case 21:
      info = ftp(payload)
      break
    case 23:
      info = telnet(payload)
      break
    case 25:
    case 587:
      info = mail('SMTP', payload)
      break
    case 110:
      info = mail('POP3', payload)
      break
    case 143:
      info = mail('IMAP', payload)
      break
    case 22:
      info = ssh(payload)
      break
  }
  if (!info) return false

  d.cleartext = info
  d.protocol = info.protocol
  d.info = info.summary
  if (full) {
    d.layers.push({
      name: info.protocol,
      summary: info.summary,
      fields: [
        { label: 'Data', value: info.summary },
        ...(info.credentialText ? [{ label: '⚠ Credential', value: info.credentialText }] : [])
      ]
    })
  }
  return true
}

function wellKnown(a: number, b: number): number | null {
  const set = new Set([21, 23, 25, 587, 110, 143, 22])
  if (set.has(a)) return a
  if (set.has(b)) return b
  return null
}

function ftp(payload: Buffer): CleartextInfo {
  const text = asciiPreview(payload, 200).trim()
  const upper = text.toUpperCase()
  let credentialText: string | undefined
  let isCredential = false
  if (upper.startsWith('USER ') || upper.startsWith('PASS ')) {
    credentialText = text
    isCredential = true
  }
  return { protocol: 'FTP', summary: `FTP: ${text}`, credentialText, isCredential }
}

function telnet(payload: Buffer): CleartextInfo {
  const text = stripTelnet(payload).trim()
  const isCredential = /login:|password:|user(name)?:/i.test(text) || (text.length > 0 && text.length < 40)
  return {
    protocol: 'Telnet',
    summary: text ? `Telnet: ${text}` : 'Telnet data',
    credentialText: isCredential && text ? text : undefined,
    isCredential
  }
}

function mail(proto: string, payload: Buffer): CleartextInfo {
  const text = asciiPreview(payload, 200).trim()
  const upper = text.toUpperCase()
  let isCredential = false
  let credentialText: string | undefined
  if (
    upper.startsWith('USER ') ||
    upper.startsWith('PASS ') ||
    upper.startsWith('AUTH ') ||
    upper.startsWith('LOGIN ') ||
    /\bLOGIN\b/.test(upper)
  ) {
    isCredential = true
    credentialText = text
  }
  return { protocol: proto, summary: `${proto}: ${text}`, credentialText, isCredential }
}

function ssh(payload: Buffer): CleartextInfo | null {
  const text = asciiPreview(payload, 80).trim()
  if (!/^SSH-\d/.test(text)) return null
  return { protocol: 'SSH', summary: `SSH banner: ${text}`, isCredential: false }
}

/** SNMP v1/v2c community string extraction (BER). Returns null if not SNMP. */
export function dissectSnmp(d: Dissection, payload: Buffer, full: boolean): boolean {
  if (payload.length < 8 || payload[0] !== 0x30) return false // SEQUENCE
  try {
    let p = 2
    if (payload[1] & 0x80) p = 2 + (payload[1] & 0x7f) // long-form length
    if (payload[p] !== 0x02) return false // version INTEGER
    const vlen = payload[p + 1]
    const version = payload[p + 1 + vlen]
    p += 2 + vlen
    if (payload[p] !== 0x04) return false // community OCTET STRING
    const clen = payload[p + 1]
    const community = payload.toString('ascii', p + 2, p + 2 + clen)
    const verName = version === 0 ? 'v1' : version === 1 ? 'v2c' : `v${version}`
    d.cleartext = {
      protocol: 'SNMP',
      summary: `SNMP ${verName} community="${community}"`,
      credentialText: `community string: ${community}`,
      isCredential: true
    }
    d.protocol = 'SNMP'
    d.info = d.cleartext.summary
    if (full) {
      d.layers.push({
        name: 'SNMP',
        summary: d.info,
        fields: [
          { label: 'Version', value: verName },
          { label: '⚠ Community', value: community }
        ]
      })
    }
    return true
  } catch {
    return false
  }
}
