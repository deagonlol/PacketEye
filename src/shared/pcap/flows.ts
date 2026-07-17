import type { Flow, TcpFlowState } from '../types'
import type { Dissection } from './model'

interface MutableFlow extends Flow {
  timestamps: number[] // for beaconing analysis (capped)
}

const MAX_SAMPLE_PACKETS = 8
const MAX_TIMESTAMPS = 2000

/**
 * Aggregates packets into bidirectional flows keyed by a normalized 5-tuple.
 * Endpoint A is the lexicographically smaller (addr,port) so both directions
 * map to the same flow.
 */
export class FlowTracker {
  private flows = new Map<string, MutableFlow>()

  add(d: Dissection, packetNumber: number, tsSec: number, length: number): void {
    if (!d.srcAddr || !d.dstAddr) return
    const proto: Flow['proto'] =
      d.transport === 'tcp' ? 'tcp' : d.transport === 'udp' ? 'udp' : 'other'

    const srcPort = d.srcPort ?? 0
    const dstPort = d.dstPort ?? 0

    const aFirst = compareEndpoints(d.srcAddr, srcPort, d.dstAddr, dstPort) <= 0
    const addrA = aFirst ? d.srcAddr : d.dstAddr
    const portA = aFirst ? srcPort : dstPort
    const addrB = aFirst ? d.dstAddr : d.srcAddr
    const portB = aFirst ? dstPort : srcPort

    const key = `${proto}|${addrA}:${portA}|${addrB}:${portB}`
    let flow = this.flows.get(key)
    if (!flow) {
      flow = {
        id: key,
        addrA,
        portA,
        addrB,
        portB,
        proto,
        appProtocol: undefined,
        packetsAtoB: 0,
        packetsBtoA: 0,
        bytesAtoB: 0,
        bytesBtoA: 0,
        firstTs: tsSec,
        lastTs: tsSec,
        tcpState: proto === 'tcp' ? 'syn-sent' : 'n/a',
        synCount: 0,
        finCount: 0,
        rstCount: 0,
        samplePackets: [],
        timestamps: []
      }
      this.flows.set(key, flow)
    }

    const aToB = d.srcAddr === addrA && srcPort === portA
    if (aToB) {
      flow.packetsAtoB++
      flow.bytesAtoB += length
    } else {
      flow.packetsBtoA++
      flow.bytesBtoA += length
    }
    if (tsSec < flow.firstTs) flow.firstTs = tsSec
    if (tsSec > flow.lastTs) flow.lastTs = tsSec

    // Track an app-protocol label if the dissection found one.
    if (!flow.appProtocol && isAppLabel(d.protocol, proto)) {
      flow.appProtocol = d.protocol
    }

    if (d.tcpFlags) {
      if (d.tcpFlags.syn) flow.synCount++
      if (d.tcpFlags.fin) flow.finCount++
      if (d.tcpFlags.rst) flow.rstCount++
      flow.tcpState = deriveTcpState(flow)
    }

    if (flow.samplePackets.length < MAX_SAMPLE_PACKETS) flow.samplePackets.push(packetNumber)
    if (flow.timestamps.length < MAX_TIMESTAMPS) flow.timestamps.push(tsSec)
  }

  getFlows(): MutableFlow[] {
    return [...this.flows.values()]
  }
}

function deriveTcpState(f: MutableFlow): TcpFlowState {
  if (f.rstCount > 0) return 'reset'
  if (f.finCount >= 1 && f.packetsBtoA > 0) return 'closed'
  if (f.packetsAtoB > 0 && f.packetsBtoA > 0) return 'established'
  return 'syn-sent'
}

function isAppLabel(protocol: string, proto: Flow['proto']): boolean {
  if (proto === 'tcp' && (protocol === 'TCP' || protocol === 'Unknown')) return false
  if (proto === 'udp' && (protocol === 'UDP' || protocol === 'Unknown')) return false
  return true
}

function compareEndpoints(a: string, ap: number, b: string, bp: number): number {
  if (a < b) return -1
  if (a > b) return 1
  return ap - bp
}
