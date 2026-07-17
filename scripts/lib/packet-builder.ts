// Helpers to construct Ethernet/IP/TCP/UDP/ARP frames byte-by-byte for building
// deterministic synthetic captures. Not production code — test-fixture tooling.

export function macBytes(mac: string): Buffer {
  return Buffer.from(mac.split(':').map((h) => parseInt(h, 16)))
}

export function ipBytes(ip: string): Buffer {
  return Buffer.from(ip.split('.').map((n) => parseInt(n, 10)))
}

function checksum(buf: Buffer): number {
  let sum = 0
  for (let i = 0; i < buf.length; i += 2) {
    sum += (buf[i] << 8) | (buf[i + 1] ?? 0)
  }
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16)
  return ~sum & 0xffff
}

export function ethernet(dstMac: string, srcMac: string, etherType: number, payload: Buffer): Buffer {
  const hdr = Buffer.alloc(14)
  macBytes(dstMac).copy(hdr, 0)
  macBytes(srcMac).copy(hdr, 6)
  hdr.writeUInt16BE(etherType, 12)
  return Buffer.concat([hdr, payload])
}

export function ipv4(
  src: string,
  dst: string,
  proto: number,
  payload: Buffer,
  ttl = 64
): Buffer {
  const hdr = Buffer.alloc(20)
  hdr[0] = 0x45 // version 4, IHL 5
  hdr[1] = 0x00
  hdr.writeUInt16BE(20 + payload.length, 2) // total length
  hdr.writeUInt16BE(0, 4) // id
  hdr.writeUInt16BE(0x4000, 6) // flags: DF
  hdr[8] = ttl
  hdr[9] = proto
  hdr.writeUInt16BE(0, 10) // checksum placeholder
  ipBytes(src).copy(hdr, 12)
  ipBytes(dst).copy(hdr, 16)
  hdr.writeUInt16BE(checksum(hdr), 10)
  return Buffer.concat([hdr, payload])
}

export interface TcpOpts {
  srcPort: number
  dstPort: number
  seq?: number
  ack?: number
  flags?: Partial<{ syn: boolean; ack: boolean; fin: boolean; rst: boolean; psh: boolean }>
  window?: number
  payload?: Buffer
}

export function tcp(o: TcpOpts): Buffer {
  const payload = o.payload ?? Buffer.alloc(0)
  const hdr = Buffer.alloc(20)
  hdr.writeUInt16BE(o.srcPort, 0)
  hdr.writeUInt16BE(o.dstPort, 2)
  hdr.writeUInt32BE(o.seq ?? 0, 4)
  hdr.writeUInt32BE(o.ack ?? 0, 8)
  hdr[12] = 0x50 // data offset 5 words
  let flags = 0
  const f = o.flags ?? {}
  if (f.fin) flags |= 0x01
  if (f.syn) flags |= 0x02
  if (f.rst) flags |= 0x04
  if (f.psh) flags |= 0x08
  if (f.ack) flags |= 0x10
  hdr[13] = flags
  hdr.writeUInt16BE(o.window ?? 64240, 14)
  hdr.writeUInt16BE(0, 16) // checksum (0 = unset, fine for analysis)
  return Buffer.concat([hdr, payload])
}

export interface UdpOpts {
  srcPort: number
  dstPort: number
  payload?: Buffer
}

export function udp(o: UdpOpts): Buffer {
  const payload = o.payload ?? Buffer.alloc(0)
  const hdr = Buffer.alloc(8)
  hdr.writeUInt16BE(o.srcPort, 0)
  hdr.writeUInt16BE(o.dstPort, 2)
  hdr.writeUInt16BE(8 + payload.length, 4)
  hdr.writeUInt16BE(0, 6)
  return Buffer.concat([hdr, payload])
}

export function arp(
  opcode: number,
  senderMac: string,
  senderIp: string,
  targetMac: string,
  targetIp: string
): Buffer {
  const b = Buffer.alloc(28)
  b.writeUInt16BE(1, 0) // htype ethernet
  b.writeUInt16BE(0x0800, 2) // ptype IPv4
  b[4] = 6 // hlen
  b[5] = 4 // plen
  b.writeUInt16BE(opcode, 6)
  macBytes(senderMac).copy(b, 8)
  ipBytes(senderIp).copy(b, 14)
  macBytes(targetMac).copy(b, 18)
  ipBytes(targetIp).copy(b, 24)
  return b
}

export const ETH = { IPV4: 0x0800, IPV6: 0x86dd, ARP: 0x0806 }
export const IPPROTO = { ICMP: 1, TCP: 6, UDP: 17 }
