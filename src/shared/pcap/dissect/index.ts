import type { PacketLayer } from '../../types'
import { LINKTYPE } from '../reader'
import { type Dissection, emptyDissection, type TcpFlags } from '../model'
import {
  ipProtoName,
  ipv4ToStr,
  ipv6ToStr,
  macToStr,
  serviceName
} from './util'
import { dissectAppLayer } from './app'

const ETH_IPV4 = 0x0800
const ETH_IPV6 = 0x86dd
const ETH_ARP = 0x0806
const ETH_VLAN = 0x8100
const ETH_VLAN_QINQ = 0x88a8

/**
 * Dissect one captured frame. `full` controls whether the full layer tree is
 * built (for the detail view) or just enough for summary/analysis.
 */
export function dissect(frame: Buffer, linkType: number, full = true): Dissection {
  const d = emptyDissection()
  try {
    const l3 = dissectLinkLayer(frame, linkType, d, full)
    if (!l3) return finalize(d, frame)

    const { etherType, offset } = l3
    if (etherType === ETH_ARP) {
      dissectArp(frame, offset, d, full)
    } else if (etherType === ETH_IPV4) {
      dissectIPv4(frame, offset, d, full)
    } else if (etherType === ETH_IPV6) {
      dissectIPv6(frame, offset, d, full)
    } else {
      d.protocol = d.protocol === 'Unknown' ? `Ethertype 0x${etherType.toString(16)}` : d.protocol
    }
  } catch {
    // Truncated / malformed packet — keep whatever we decoded.
  }
  return finalize(d, frame)
}

function finalize(d: Dissection, frame: Buffer): Dissection {
  if (!d.info) d.info = d.protocol
  if (!d.srcAddr && d.macSrc) {
    d.srcAddr = d.macSrc
    d.dstAddr = d.macDst ?? ''
  }
  return d
}

// ---- Link layer ----

function dissectLinkLayer(
  frame: Buffer,
  linkType: number,
  d: Dissection,
  full: boolean
): { etherType: number; offset: number } | null {
  switch (linkType) {
    case LINKTYPE.ETHERNET: {
      if (frame.length < 14) return null
      d.macDst = macToStr(frame, 0)
      d.macSrc = macToStr(frame, 6)
      let etherType = frame.readUInt16BE(12)
      let offset = 14
      const vlans: number[] = []
      while (etherType === ETH_VLAN || etherType === ETH_VLAN_QINQ) {
        if (frame.length < offset + 4) break
        const tci = frame.readUInt16BE(offset)
        vlans.push(tci & 0x0fff)
        etherType = frame.readUInt16BE(offset + 2)
        offset += 4
      }
      if (full) {
        const fields = [
          { label: 'Destination', value: d.macDst },
          { label: 'Source', value: d.macSrc },
          { label: 'EtherType', value: `0x${etherType.toString(16).padStart(4, '0')}` }
        ]
        if (vlans.length) fields.push({ label: 'VLAN', value: vlans.join(', ') })
        d.layers.push({ name: 'Ethernet II', summary: `${d.macSrc} → ${d.macDst}`, fields })
      }
      return { etherType, offset }
    }
    case LINKTYPE.LINUX_SLL: {
      if (frame.length < 16) return null
      const etherType = frame.readUInt16BE(14)
      if (full)
        d.layers.push({ name: 'Linux cooked v1', summary: '', fields: [] })
      return { etherType, offset: 16 }
    }
    case LINKTYPE.LINUX_SLL2: {
      if (frame.length < 20) return null
      const etherType = frame.readUInt16BE(0)
      if (full) d.layers.push({ name: 'Linux cooked v2', summary: '', fields: [] })
      return { etherType, offset: 20 }
    }
    case LINKTYPE.NULL:
    case LINKTYPE.LOOP: {
      if (frame.length < 4) return null
      const fam =
        linkType === LINKTYPE.LOOP ? frame.readUInt32BE(0) : frame.readUInt32LE(0)
      const etherType = fam === 2 ? ETH_IPV4 : fam === 24 || fam === 28 || fam === 30 ? ETH_IPV6 : 0
      return { etherType, offset: 4 }
    }
    case LINKTYPE.RAW:
    case LINKTYPE.RAW_ALT1:
    case LINKTYPE.RAW_ALT2: {
      if (frame.length < 1) return null
      const version = frame[0] >> 4
      return { etherType: version === 6 ? ETH_IPV6 : ETH_IPV4, offset: 0 }
    }
    default:
      d.protocol = `LinkType ${linkType}`
      return null
  }
}

// ---- ARP ----

function dissectArp(frame: Buffer, off: number, d: Dissection, full: boolean): void {
  if (frame.length < off + 28) return
  const opcode = frame.readUInt16BE(off + 6)
  const senderMac = macToStr(frame, off + 8)
  const senderIp = ipv4ToStr(frame, off + 14)
  const targetMac = macToStr(frame, off + 18)
  const targetIp = ipv4ToStr(frame, off + 24)
  d.arp = { opcode, senderMac, senderIp, targetMac, targetIp }
  d.protocol = 'ARP'
  d.srcAddr = senderIp
  d.dstAddr = targetIp
  if (opcode === 1) {
    d.info = `Who has ${targetIp}? Tell ${senderIp}`
  } else if (opcode === 2) {
    d.info = `${senderIp} is at ${senderMac}`
  } else {
    d.info = `ARP opcode ${opcode}`
  }
  if (full) {
    d.layers.push({
      name: 'ARP',
      summary: d.info,
      fields: [
        { label: 'Opcode', value: opcode === 1 ? 'request (1)' : opcode === 2 ? 'reply (2)' : String(opcode) },
        { label: 'Sender MAC', value: senderMac },
        { label: 'Sender IP', value: senderIp },
        { label: 'Target MAC', value: targetMac },
        { label: 'Target IP', value: targetIp }
      ]
    })
  }
}

// ---- IPv4 ----

function dissectIPv4(frame: Buffer, off: number, d: Dissection, full: boolean): void {
  if (frame.length < off + 20) return
  const ihl = (frame[off] & 0x0f) * 4
  const totalLen = frame.readUInt16BE(off + 2)
  const flagsFrag = frame.readUInt16BE(off + 6)
  const moreFrag = (flagsFrag & 0x2000) !== 0
  const fragOffset = flagsFrag & 0x1fff
  const ttl = frame[off + 8]
  const proto = frame[off + 9]
  const src = ipv4ToStr(frame, off + 12)
  const dst = ipv4ToStr(frame, off + 16)

  d.isIp = true
  d.ipVersion = 4
  d.ipProto = proto
  d.ttl = ttl
  d.srcAddr = src
  d.dstAddr = dst
  d.fragmented = moreFrag || fragOffset > 0
  d.protocol = ipProtoName(proto)

  if (full) {
    d.layers.push({
      name: 'IPv4',
      summary: `${src} → ${dst}`,
      fields: [
        { label: 'Source', value: src },
        { label: 'Destination', value: dst },
        { label: 'Protocol', value: `${ipProtoName(proto)} (${proto})` },
        { label: 'TTL', value: String(ttl) },
        { label: 'Total Length', value: String(totalLen) },
        ...(d.fragmented ? [{ label: 'Fragment', value: `offset ${fragOffset}${moreFrag ? ', MF' : ''}` }] : [])
      ]
    })
  }

  const l4off = off + ihl
  if (d.fragmented && fragOffset > 0) {
    d.info = `Fragmented IP protocol (proto=${proto}, off=${fragOffset})`
    return
  }
  dissectTransport(frame, l4off, proto, d, full)
}

// ---- IPv6 ----

function dissectIPv6(frame: Buffer, off: number, d: Dissection, full: boolean): void {
  if (frame.length < off + 40) return
  let nextHeader = frame[off + 6]
  const hopLimit = frame[off + 7]
  const src = ipv6ToStr(frame, off + 8)
  const dst = ipv6ToStr(frame, off + 24)

  d.isIp = true
  d.ipVersion = 6
  d.ttl = hopLimit
  d.srcAddr = src
  d.dstAddr = dst
  d.protocol = ipProtoName(nextHeader)

  if (full) {
    d.layers.push({
      name: 'IPv6',
      summary: `${src} → ${dst}`,
      fields: [
        { label: 'Source', value: src },
        { label: 'Destination', value: dst },
        { label: 'Next Header', value: `${ipProtoName(nextHeader)} (${nextHeader})` },
        { label: 'Hop Limit', value: String(hopLimit) }
      ]
    })
  }

  let l4off = off + 40
  // Skip a few common extension headers.
  const EXT = new Set([0, 43, 44, 60])
  let guard = 0
  while (EXT.has(nextHeader) && frame.length >= l4off + 2 && guard++ < 8) {
    const hdrLen = (frame[l4off + 1] + 1) * 8
    nextHeader = frame[l4off]
    l4off += hdrLen
  }
  d.ipProto = nextHeader
  dissectTransport(frame, l4off, nextHeader, d, full)
}

// ---- Transport ----

function dissectTransport(
  frame: Buffer,
  off: number,
  proto: number,
  d: Dissection,
  full: boolean
): void {
  if (proto === 6) dissectTcp(frame, off, d, full)
  else if (proto === 17) dissectUdp(frame, off, d, full)
  else if (proto === 1) dissectIcmp(frame, off, d, full, false)
  else if (proto === 58) dissectIcmp(frame, off, d, full, true)
  else {
    d.transport = 'other'
  }
}

function readTcpFlags(byte: number): TcpFlags {
  return {
    fin: (byte & 0x01) !== 0,
    syn: (byte & 0x02) !== 0,
    rst: (byte & 0x04) !== 0,
    psh: (byte & 0x08) !== 0,
    ack: (byte & 0x10) !== 0,
    urg: (byte & 0x20) !== 0
  }
}

function flagsToStr(f: TcpFlags): string {
  const parts: string[] = []
  if (f.syn) parts.push('SYN')
  if (f.ack) parts.push('ACK')
  if (f.fin) parts.push('FIN')
  if (f.rst) parts.push('RST')
  if (f.psh) parts.push('PSH')
  if (f.urg) parts.push('URG')
  return parts.join(', ') || 'none'
}

function dissectTcp(frame: Buffer, off: number, d: Dissection, full: boolean): void {
  if (frame.length < off + 20) return
  const srcPort = frame.readUInt16BE(off)
  const dstPort = frame.readUInt16BE(off + 2)
  const seq = frame.readUInt32BE(off + 4)
  const ack = frame.readUInt32BE(off + 8)
  const dataOffset = (frame[off + 12] >> 4) * 4
  const flags = readTcpFlags(frame[off + 13])
  const window = frame.readUInt16BE(off + 14)

  d.transport = 'tcp'
  d.srcPort = srcPort
  d.dstPort = dstPort
  d.tcpFlags = flags
  d.tcpSeq = seq
  d.tcpAck = ack

  const payloadStart = off + dataOffset
  const payload = frame.subarray(Math.min(payloadStart, frame.length))
  d.payloadLen = payload.length
  d.protocol = 'TCP'

  if (full) {
    d.layers.push({
      name: 'TCP',
      summary: `${srcPort} → ${dstPort} [${flagsToStr(flags)}]`,
      fields: [
        { label: 'Source Port', value: `${srcPort}${labelPort(srcPort)}` },
        { label: 'Destination Port', value: `${dstPort}${labelPort(dstPort)}` },
        { label: 'Flags', value: flagsToStr(flags) },
        { label: 'Seq', value: String(seq) },
        { label: 'Ack', value: String(ack) },
        { label: 'Window', value: String(window) },
        { label: 'Payload', value: `${payload.length} bytes` }
      ]
    })
  }

  const svc = serviceName(dstPort) ?? serviceName(srcPort)
  d.info = `${srcPort} → ${dstPort} [${flagsToStr(flags)}] Seq=${seq} Win=${window} Len=${payload.length}`

  dissectAppLayer(d, payload, srcPort, dstPort, 'tcp', full)

  if (d.protocol === 'TCP' && svc) d.protocol = svc
}

function dissectUdp(frame: Buffer, off: number, d: Dissection, full: boolean): void {
  if (frame.length < off + 8) return
  const srcPort = frame.readUInt16BE(off)
  const dstPort = frame.readUInt16BE(off + 2)
  const len = frame.readUInt16BE(off + 4)
  const payload = frame.subarray(off + 8, Math.min(off + Math.max(len, 8), frame.length))

  d.transport = 'udp'
  d.srcPort = srcPort
  d.dstPort = dstPort
  d.payloadLen = payload.length
  d.protocol = 'UDP'

  if (full) {
    d.layers.push({
      name: 'UDP',
      summary: `${srcPort} → ${dstPort}`,
      fields: [
        { label: 'Source Port', value: `${srcPort}${labelPort(srcPort)}` },
        { label: 'Destination Port', value: `${dstPort}${labelPort(dstPort)}` },
        { label: 'Length', value: String(len) }
      ]
    })
  }

  const svc = serviceName(dstPort) ?? serviceName(srcPort)
  d.info = `${srcPort} → ${dstPort} Len=${payload.length}`

  dissectAppLayer(d, payload, srcPort, dstPort, 'udp', full)

  if (d.protocol === 'UDP' && svc) d.protocol = svc
}

function dissectIcmp(
  frame: Buffer,
  off: number,
  d: Dissection,
  full: boolean,
  v6: boolean
): void {
  if (frame.length < off + 4) return
  const type = frame[off]
  const code = frame[off + 1]
  d.transport = 'other'
  d.protocol = v6 ? 'ICMPv6' : 'ICMP'
  const summary = icmpSummary(type, v6)
  d.icmp = { type, code, summary }
  d.info = summary
  if (full) {
    d.layers.push({
      name: d.protocol,
      summary,
      fields: [
        { label: 'Type', value: `${type} (${summary})` },
        { label: 'Code', value: String(code) }
      ]
    })
  }
}

function icmpSummary(type: number, v6: boolean): string {
  if (!v6) {
    switch (type) {
      case 0:
        return 'Echo reply'
      case 3:
        return 'Destination unreachable'
      case 5:
        return 'Redirect'
      case 8:
        return 'Echo request (ping)'
      case 11:
        return 'Time exceeded'
      default:
        return `ICMP type ${type}`
    }
  }
  switch (type) {
    case 128:
      return 'Echo request'
    case 129:
      return 'Echo reply'
    case 133:
      return 'Router solicitation'
    case 134:
      return 'Router advertisement'
    case 135:
      return 'Neighbor solicitation'
    case 136:
      return 'Neighbor advertisement'
    default:
      return `ICMPv6 type ${type}`
  }
}

function labelPort(port: number): string {
  const s = serviceName(port)
  return s ? ` (${s})` : ''
}

export function buildHex(frame: Buffer): { hex: string; ascii: string } {
  const bytes: string[] = []
  let ascii = ''
  for (let i = 0; i < frame.length; i++) {
    bytes.push(frame[i].toString(16).padStart(2, '0').toUpperCase())
    const c = frame[i]
    ascii += c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : '.'
  }
  return { hex: bytes.join(' '), ascii }
}
