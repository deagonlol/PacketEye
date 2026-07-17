import type { Dissection, DnsInfo } from '../model'
import { ipv4ToStr, ipv6ToStr } from './util'

const TYPE_NAMES: Record<number, string> = {
  1: 'A',
  2: 'NS',
  5: 'CNAME',
  6: 'SOA',
  10: 'NULL',
  12: 'PTR',
  15: 'MX',
  16: 'TXT',
  28: 'AAAA',
  33: 'SRV',
  255: 'ANY',
  65: 'HTTPS'
}

const RCODE_NAMES: Record<number, string> = {
  0: 'NOERROR',
  1: 'FORMERR',
  2: 'SERVFAIL',
  3: 'NXDOMAIN',
  4: 'NOTIMP',
  5: 'REFUSED'
}

function typeName(t: number): string {
  return TYPE_NAMES[t] ?? `TYPE${t}`
}

/** Parse a DNS name starting at `off`, following compression pointers. */
function readName(buf: Buffer, off: number): { name: string; next: number } {
  const labels: string[] = []
  let pos = off
  let next = -1
  let jumps = 0
  while (pos < buf.length && jumps < 20) {
    const len = buf[pos]
    if (len === 0) {
      pos++
      if (next < 0) next = pos
      break
    }
    if ((len & 0xc0) === 0xc0) {
      // Compression pointer.
      if (pos + 1 >= buf.length) break
      const ptr = ((len & 0x3f) << 8) | buf[pos + 1]
      if (next < 0) next = pos + 2
      pos = ptr
      jumps++
      continue
    }
    pos++
    if (pos + len > buf.length) break
    labels.push(buf.toString('ascii', pos, pos + len))
    pos += len
  }
  return { name: labels.join('.') || '<root>', next: next < 0 ? pos : next }
}

export function dissectDns(
  d: Dissection,
  payload: Buffer,
  srcPort: number,
  dstPort: number,
  full: boolean
): boolean {
  if (payload.length < 12) return false
  const id = payload.readUInt16BE(0)
  const flags = payload.readUInt16BE(2)
  const qd = payload.readUInt16BE(4)
  const an = payload.readUInt16BE(6)
  // Sanity: counts shouldn't be absurd for a valid DNS message.
  if (qd > 100 || an > 200) return false
  const isResponse = (flags & 0x8000) !== 0
  const rcode = flags & 0x000f

  const transport: DnsInfo['transport'] =
    dstPort === 5353 || srcPort === 5353
      ? 'mdns'
      : dstPort === 5355 || srcPort === 5355
        ? 'llmnr'
        : dstPort === 137 || srcPort === 137
          ? 'nbns'
          : 'dns'

  const questions: DnsInfo['questions'] = []
  const answers: DnsInfo['answers'] = []
  let pos = 12
  try {
    for (let i = 0; i < qd && pos < payload.length; i++) {
      const { name, next } = readName(payload, pos)
      pos = next
      if (pos + 4 > payload.length) break
      const type = payload.readUInt16BE(pos)
      pos += 4
      questions.push({ name, type: typeName(type) })
    }
    for (let i = 0; i < an && pos < payload.length; i++) {
      const { name, next } = readName(payload, pos)
      pos = next
      if (pos + 10 > payload.length) break
      const type = payload.readUInt16BE(pos)
      const rdlength = payload.readUInt16BE(pos + 8)
      const rdStart = pos + 10
      let data = ''
      if (type === 1 && rdlength === 4 && rdStart + 4 <= payload.length) {
        data = ipv4ToStr(payload, rdStart)
      } else if (type === 28 && rdlength === 16 && rdStart + 16 <= payload.length) {
        data = ipv6ToStr(payload, rdStart)
      } else if (type === 5 || type === 12 || type === 2) {
        data = readName(payload, rdStart).name
      } else if (type === 16) {
        data = payload.toString('ascii', rdStart + 1, Math.min(rdStart + rdlength, payload.length))
      }
      answers.push({ name, type: typeName(type), data })
      pos = rdStart + rdlength
    }
  } catch {
    /* tolerate truncation */
  }

  const dns: DnsInfo = {
    isQuery: !isResponse,
    id,
    rcode,
    rcodeName: RCODE_NAMES[rcode] ?? `RCODE${rcode}`,
    questions,
    answers,
    transport
  }
  d.dns = dns

  const label =
    transport === 'mdns' ? 'mDNS' : transport === 'llmnr' ? 'LLMNR' : transport === 'nbns' ? 'NBNS' : 'DNS'
  d.protocol = label

  const qName = questions[0]?.name ?? answers[0]?.name ?? ''
  if (isResponse) {
    const ans = answers.find((a) => a.data)
    d.info = `Response ${qName}${ans ? ` → ${ans.data}` : ''}${rcode !== 0 ? ` [${dns.rcodeName}]` : ''}`
  } else {
    d.info = `Query ${questions.map((q) => `${q.type} ${q.name}`).join(', ') || qName}`
  }

  if (full) {
    d.layers.push({
      name: label,
      summary: d.info,
      fields: [
        { label: 'Transaction ID', value: `0x${id.toString(16).padStart(4, '0')}` },
        { label: 'Type', value: isResponse ? 'response' : 'query' },
        ...(isResponse ? [{ label: 'Response Code', value: dns.rcodeName }] : []),
        ...questions.map((q) => ({ label: 'Query', value: `${q.type} ${q.name}` })),
        ...answers.map((a) => ({ label: `Answer (${a.type})`, value: `${a.name} → ${a.data}` }))
      ]
    })
  }
  return true
}
