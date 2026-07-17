import { describe, it, expect } from 'vitest'
import { buildMixedCapture } from '../../../scripts/scenarios'
import { iterateCapture } from './parse'
import { detectFormat } from './reader'
import { dissect } from './dissect'

function parseAll(buf: Buffer): ReturnType<typeof dissect>[] {
  const out: ReturnType<typeof dissect>[] = []
  const iter = iterateCapture(buf)
  let r = iter.next()
  let linkType = 1
  while (!r.done) {
    linkType = r.value.linkType
    const frame = buf.subarray(r.value.frameOffset, r.value.frameOffset + r.value.capLen)
    out.push(dissect(frame, linkType, true))
    r = iter.next()
  }
  return out
}

describe('capture format detection', () => {
  it('detects classic pcap (LE microsecond)', () => {
    const buf = buildMixedCapture().toBuffer()
    const info = detectFormat(buf)
    expect(info).not.toBeNull()
    expect(info?.format).toBe('pcap')
    expect(info?.swapped).toBe(false)
  })

  it('rejects non-capture data', () => {
    expect(detectFormat(Buffer.from('not a pcap file at all'))).toBeNull()
  })
})

describe('pcap iteration + L2-L4 dissection', () => {
  const buf = buildMixedCapture().toBuffer()
  const packets = parseAll(buf)

  it('parses every packet without loss', () => {
    // buildMixedCapture reports its own frame count; parsing must match.
    expect(packets.length).toBe(buildMixedCapture().count)
    expect(packets.length).toBeGreaterThan(50)
  })

  it('decodes Ethernet + IPv4 addressing', () => {
    const ipPkts = packets.filter((p) => p.isIp && p.ipVersion === 4)
    expect(ipPkts.length).toBeGreaterThan(0)
    for (const p of ipPkts) {
      expect(p.srcAddr).toMatch(/^\d+\.\d+\.\d+\.\d+$/)
      expect(p.dstAddr).toMatch(/^\d+\.\d+\.\d+\.\d+$/)
    }
  })

  it('decodes ARP packets', () => {
    const arps = packets.filter((p) => p.protocol === 'ARP')
    expect(arps.length).toBeGreaterThan(0)
    expect(arps.some((a) => a.arp?.opcode === 1)).toBe(true)
    expect(arps.some((a) => a.arp?.opcode === 2)).toBe(true)
  })

  it('decodes ICMP echo', () => {
    const icmp = packets.filter((p) => p.protocol === 'ICMP')
    expect(icmp.length).toBeGreaterThanOrEqual(2)
    expect(icmp.some((p) => /Echo request/i.test(p.info))).toBe(true)
  })

  it('extracts TCP ports and flags', () => {
    const syns = packets.filter((p) => p.transport === 'tcp' && p.tcpFlags?.syn && !p.tcpFlags?.ack)
    expect(syns.length).toBeGreaterThan(0)
    const scanPorts = new Set(syns.map((p) => p.dstPort))
    // The port scan targets many distinct ports.
    expect(scanPorts.size).toBeGreaterThanOrEqual(10)
  })

  it('produces a per-packet layer tree for the detail view', () => {
    const tcp = packets.find((p) => p.transport === 'tcp')
    expect(tcp).toBeDefined()
    const names = tcp!.layers.map((l) => l.name)
    expect(names).toContain('Ethernet II')
    expect(names).toContain('IPv4')
    expect(names).toContain('TCP')
  })
})
