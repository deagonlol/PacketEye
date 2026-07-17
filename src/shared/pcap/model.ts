// Internal per-packet dissection model. Dissectors fill this in layer by layer;
// the flow tracker, detection engine, and app-summary builders read from it.
import type { PacketLayer } from '../types'

export interface TcpFlags {
  syn: boolean
  ack: boolean
  fin: boolean
  rst: boolean
  psh: boolean
  urg: boolean
}

export interface DnsInfo {
  isQuery: boolean
  id: number
  rcode: number
  rcodeName: string
  questions: { name: string; type: string }[]
  answers: { name: string; type: string; data: string }[]
  transport: 'mdns' | 'llmnr' | 'nbns' | 'dns'
}

export interface HttpInfo {
  kind: 'request' | 'response'
  method?: string
  path?: string
  host?: string
  userAgent?: string
  status?: number
  headers: Record<string, string>
  hasBasicAuth: boolean
  basicAuthDecoded?: string
  cookie?: string
  bodyPreview?: string
  passwordLikeBody?: boolean
}

export interface TlsInfo {
  kind: 'client-hello' | 'server-hello' | 'other'
  sni?: string
  version: string // negotiated / offered highest
  versionRaw: number
  cipherSuites: string[]
  chosenCipher?: string
  weak: boolean
}

export interface CleartextInfo {
  protocol: string // FTP, TELNET, SMTP, POP3, IMAP, SSH, SNMP
  summary: string
  credentialText?: string // e.g. "USER admin", community string, etc.
  isCredential: boolean
}

export interface DhcpInfo {
  messageType: string
  isServer: boolean
  clientMac?: string
  requestedIp?: string
  serverId?: string
}

/** Result of dissecting a single frame. */
export interface Dissection {
  layers: PacketLayer[]

  // Addressing (L2/L3)
  macSrc?: string
  macDst?: string
  srcAddr: string
  dstAddr: string
  isIp: boolean
  ipVersion?: 4 | 6
  ipProto?: number
  ttl?: number
  fragmented?: boolean

  // Transport
  transport?: 'tcp' | 'udp' | 'other'
  srcPort?: number
  dstPort?: number
  tcpFlags?: TcpFlags
  tcpSeq?: number
  tcpAck?: number
  payloadLen: number

  // Top-level label + one-line info (Wireshark-style)
  protocol: string
  info: string

  // App-layer extractions (populated by app dissectors)
  dns?: DnsInfo
  http?: HttpInfo
  tls?: TlsInfo
  cleartext?: CleartextInfo
  dhcp?: DhcpInfo
  arp?: { opcode: number; senderMac: string; senderIp: string; targetMac: string; targetIp: string }
  icmp?: { type: number; code: number; summary: string }
}

export function emptyDissection(): Dissection {
  return {
    layers: [],
    srcAddr: '',
    dstAddr: '',
    isIp: false,
    payloadLen: 0,
    protocol: 'Unknown',
    info: ''
  }
}
