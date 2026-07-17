// Application-layer payload builders for synthetic captures.

/** Encode a DNS name as a sequence of length-prefixed labels + root. */
function encodeName(name: string): Buffer {
  const parts = name.split('.').filter(Boolean)
  const bufs = parts.map((p) => {
    const b = Buffer.alloc(1 + p.length)
    b[0] = p.length
    b.write(p, 1, 'ascii')
    return b
  })
  return Buffer.concat([...bufs, Buffer.from([0])])
}

const DNS_TYPE: Record<string, number> = { A: 1, AAAA: 28, TXT: 16, CNAME: 5, NULL: 10, MX: 15 }

export function dnsQuery(id: number, name: string, type: keyof typeof DNS_TYPE = 'A'): Buffer {
  const header = Buffer.alloc(12)
  header.writeUInt16BE(id, 0)
  header.writeUInt16BE(0x0100, 2) // standard query, RD
  header.writeUInt16BE(1, 4) // qdcount
  const q = Buffer.concat([
    encodeName(name),
    (() => {
      const b = Buffer.alloc(4)
      b.writeUInt16BE(DNS_TYPE[type], 0)
      b.writeUInt16BE(1, 2) // class IN
      return b
    })()
  ])
  return Buffer.concat([header, q])
}

export function dnsResponse(
  id: number,
  name: string,
  answerIp: string,
  rcode = 0,
  type: keyof typeof DNS_TYPE = 'A'
): Buffer {
  const header = Buffer.alloc(12)
  header.writeUInt16BE(id, 0)
  header.writeUInt16BE(0x8180 | (rcode & 0x0f), 2) // response, RD, RA + rcode
  header.writeUInt16BE(1, 4) // qdcount
  header.writeUInt16BE(rcode === 0 ? 1 : 0, 6) // ancount
  const question = Buffer.concat([
    encodeName(name),
    (() => {
      const b = Buffer.alloc(4)
      b.writeUInt16BE(DNS_TYPE[type], 0)
      b.writeUInt16BE(1, 2)
      return b
    })()
  ])
  if (rcode !== 0) return Buffer.concat([header, question])
  const ipParts = answerIp.split('.').map(Number)
  const answer = Buffer.concat([
    Buffer.from([0xc0, 0x0c]), // name pointer to question
    (() => {
      const b = Buffer.alloc(10)
      b.writeUInt16BE(DNS_TYPE[type], 0)
      b.writeUInt16BE(1, 2) // class IN
      b.writeUInt32BE(300, 4) // TTL
      b.writeUInt16BE(4, 8) // rdlength
      return b
    })(),
    Buffer.from(ipParts)
  ])
  return Buffer.concat([header, question, answer])
}

export function httpRequest(
  method: string,
  path: string,
  host: string,
  headers: Record<string, string> = {},
  body = ''
): Buffer {
  const lines = [`${method} ${path} HTTP/1.1`, `Host: ${host}`]
  for (const [k, v] of Object.entries(headers)) lines.push(`${k}: ${v}`)
  lines.push('', body)
  return Buffer.from(lines.join('\r\n'), 'utf-8')
}

export function httpResponse(status: number, statusText: string, body = ''): Buffer {
  const lines = [
    `HTTP/1.1 ${status} ${statusText}`,
    'Server: nginx',
    `Content-Length: ${Buffer.byteLength(body)}`,
    '',
    body
  ]
  return Buffer.from(lines.join('\r\n'), 'utf-8')
}

export function ascii(text: string): Buffer {
  return Buffer.from(text, 'ascii')
}

/** Build a TLS ClientHello record with the given legacy version, SNI, ciphers. */
export function tlsClientHello(version: number, sni: string, ciphers: number[]): Buffer {
  const random = Buffer.alloc(32, 0x11)
  const sessionId = Buffer.from([0]) // length 0

  const cs = Buffer.alloc(2 + ciphers.length * 2)
  cs.writeUInt16BE(ciphers.length * 2, 0)
  ciphers.forEach((c, i) => cs.writeUInt16BE(c, 2 + i * 2))

  const compression = Buffer.from([1, 0]) // len 1, null

  // SNI extension
  const host = Buffer.from(sni, 'ascii')
  const sniBody = Buffer.alloc(5 + host.length)
  sniBody.writeUInt16BE(3 + host.length, 0) // server_name_list length
  sniBody.writeUInt8(0, 2) // type host_name
  sniBody.writeUInt16BE(host.length, 3)
  host.copy(sniBody, 5)
  const sniExt = Buffer.alloc(4 + sniBody.length)
  sniExt.writeUInt16BE(0x0000, 0) // extension type SNI
  sniExt.writeUInt16BE(sniBody.length, 2)
  sniBody.copy(sniExt, 4)

  const extensions = Buffer.concat([
    (() => {
      const b = Buffer.alloc(2)
      b.writeUInt16BE(sniExt.length, 0)
      return b
    })(),
    sniExt
  ])

  const body = Buffer.concat([
    (() => {
      const b = Buffer.alloc(2)
      b.writeUInt16BE(version, 0)
      return b
    })(),
    random,
    sessionId,
    cs,
    compression,
    extensions
  ])

  const hs = Buffer.alloc(4 + body.length)
  hs[0] = 0x01 // ClientHello
  hs.writeUIntBE(body.length, 1, 3)
  body.copy(hs, 4)

  const record = Buffer.alloc(5 + hs.length)
  record[0] = 0x16 // handshake
  record.writeUInt16BE(version, 1)
  record.writeUInt16BE(hs.length, 3)
  hs.copy(record, 5)
  return record
}

/** Build a minimal DHCP (BOOTP) message with a message-type option. */
export function dhcpMessage(
  op: number,
  msgType: number,
  clientMac: string,
  serverId?: string
): Buffer {
  const b = Buffer.alloc(240)
  b[0] = op // 1=request 2=reply
  b[1] = 1 // htype ethernet
  b[2] = 6 // hlen
  b.writeUInt32BE(0x3903f326, 4) // xid
  const mac = clientMac.split(':').map((h) => parseInt(h, 16))
  for (let i = 0; i < 6; i++) b[28 + i] = mac[i]
  b.writeUInt32BE(0x63825363, 236) // magic cookie
  const opts: number[] = [53, 1, msgType]
  if (serverId) {
    const s = serverId.split('.').map(Number)
    opts.push(54, 4, ...s)
  }
  opts.push(255)
  return Buffer.concat([b, Buffer.from(opts)])
}
