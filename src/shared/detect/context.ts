// Lightweight per-packet record retained for the detection engine. Holds just
// the fields rules need, avoiding a second full pass over the capture.
import type { Dissection } from '../pcap/model'

export interface DetectPacket {
  number: number
  tsSec: number
  srcAddr: string
  dstAddr: string
  srcPort?: number
  dstPort?: number
  transport?: 'tcp' | 'udp' | 'other'
  protocol: string
  isIp: boolean
  ipVersion?: 4 | 6
  length: number
  payloadLen: number
  tcpFlags?: Dissection['tcpFlags']
  // Selected app-layer extractions (shallow copies kept for detection).
  dns?: Dissection['dns']
  http?: Dissection['http']
  tls?: Dissection['tls']
  cleartext?: Dissection['cleartext']
  dhcp?: Dissection['dhcp']
  arp?: Dissection['arp']
  icmp?: Dissection['icmp']
}

export function toDetectPacket(d: Dissection, number: number, tsSec: number, length: number): DetectPacket {
  return {
    number,
    tsSec,
    srcAddr: d.srcAddr,
    dstAddr: d.dstAddr,
    srcPort: d.srcPort,
    dstPort: d.dstPort,
    transport: d.transport,
    protocol: d.protocol,
    isIp: d.isIp,
    ipVersion: d.ipVersion,
    length,
    payloadLen: d.payloadLen,
    tcpFlags: d.tcpFlags,
    dns: d.dns,
    http: d.http,
    tls: d.tls,
    cleartext: d.cleartext,
    dhcp: d.dhcp,
    arp: d.arp,
    icmp: d.icmp
  }
}
