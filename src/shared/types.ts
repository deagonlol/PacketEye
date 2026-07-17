// Shared types used across main, preload, worker, and renderer.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export type FindingCategory =
  | 'credentials'
  | 'insecure-protocol'
  | 'weak-crypto'
  | 'recon'
  | 'spoofing'
  | 'c2-exfil'
  | 'dos'
  | 'hygiene'

/** A decoded layer entry for the packet detail tree. */
export interface LayerField {
  label: string
  value: string
}

export interface PacketLayer {
  name: string
  summary?: string
  fields: LayerField[]
}

/**
 * Lightweight per-packet record kept in the worker's index. Raw bytes are NOT
 * stored — only the file offset/length so the hex view can be read lazily.
 */
export interface PacketSummary {
  number: number // 1-based index in capture order
  tsSec: number // epoch seconds (float, sub-second in fraction)
  timeOffset: number // seconds since first packet
  srcAddr: string
  dstAddr: string
  srcPort?: number
  dstPort?: number
  protocol: string // top-most decoded protocol label e.g. "TLS", "DNS", "TCP"
  length: number // captured length in bytes
  info: string // human-readable one-line summary
  // Location of the packet's raw data within the source file.
  fileOffset: number
  rawLength: number
}

export interface FlowKey {
  addrA: string
  portA: number
  addrB: string
  portB: number
  proto: 'tcp' | 'udp' | 'other'
}

export type TcpFlowState = 'syn-sent' | 'established' | 'reset' | 'closed' | 'n/a'

export interface Flow {
  id: string
  addrA: string
  portA: number
  addrB: string
  portB: number
  proto: 'tcp' | 'udp' | 'other'
  appProtocol?: string
  packetsAtoB: number
  packetsBtoA: number
  bytesAtoB: number
  bytesBtoA: number
  firstTs: number
  lastTs: number
  tcpState: TcpFlowState
  synCount: number
  finCount: number
  rstCount: number
  // packet numbers (first few) for evidence linking
  samplePackets: number[]
}

export interface ProtocolCount {
  protocol: string
  packets: number
  bytes: number
}

export interface TalkerStat {
  addr: string
  packets: number
  bytes: number
}

export interface TimeBucket {
  timeOffset: number // seconds since capture start (bucket start)
  packets: number
  bytes: number
}

export interface DnsSummaryEntry {
  name: string
  types: string[]
  responseCodes: string[]
  count: number
  addresses: string[]
  suspicious?: boolean
}

export interface HttpSummaryEntry {
  method: string
  host: string
  path: string
  userAgent?: string
  status?: number
  hasBasicAuth?: boolean
  packetNumber: number
}

export interface TlsSummaryEntry {
  sni?: string
  version: string
  cipherSuites: string[]
  packetNumber: number
  weak?: boolean
}

export interface CaptureStats {
  fileName: string
  fileSizeBytes: number
  format: 'pcap' | 'pcapng'
  linkType: string
  packetCount: number
  totalBytes: number
  startTime: number // epoch seconds
  endTime: number
  durationSec: number
  protocolHierarchy: ProtocolCount[]
  topTalkers: TalkerStat[]
  timeline: TimeBucket[]
  hostCount: number
}

export interface Finding {
  id: string
  severity: Severity
  category: FindingCategory
  title: string
  description: string
  evidence: number[] // packet numbers
  affectedHosts: string[]
  remediation: string
  mitre?: string // ATT&CK tactic/technique hint
  detail?: string // extra machine-generated context (e.g. domain, port)
}

export interface AppSummaries {
  dns: DnsSummaryEntry[]
  http: HttpSummaryEntry[]
  tls: TlsSummaryEntry[]
}

/** Full analysis payload sent from worker to renderer after parsing. */
export interface CaptureAnalysis {
  stats: CaptureStats
  flows: Flow[]
  findings: Finding[]
  summaries: AppSummaries
}

/** Compact structure sent to the LLM. Never includes raw packet bytes. */
export interface CaptureDigest {
  meta: {
    fileName: string
    packetCount: number
    durationSec: number
    startTime: string
    hostCount: number
    totalBytes: number
  }
  protocolHierarchy: ProtocolCount[]
  topTalkers: TalkerStat[]
  topConversations: {
    endpoints: string
    proto: string
    appProtocol?: string
    packets: number
    bytes: number
  }[]
  dns: { name: string; types: string[]; rcodes: string[]; count: number; suspicious?: boolean }[]
  http: { method: string; host: string; path: string; basicAuth?: boolean; status?: number }[]
  tls: { sni?: string; version: string; weak?: boolean }[]
  findings: {
    severity: Severity
    category: FindingCategory
    title: string
    description: string
    affectedHosts: string[]
    detail?: string
  }[]
}

// ---- Parse progress ----
export interface ParseProgress {
  phase: 'reading' | 'analyzing' | 'done' | 'error'
  bytesRead: number
  totalBytes: number
  packets: number
  message?: string
}

// ---- Paged packet queries ----
export interface PacketQuery {
  offset: number
  limit: number
  filter?: string // simple filter text
}

export interface PacketPage {
  total: number
  filtered: number
  packets: PacketSummary[]
}

export interface PacketDetail {
  summary: PacketSummary
  layers: PacketLayer[]
  hex: string // uppercase hex bytes, space-separated
  ascii: string
}

// ---- Settings ----
export type GroqModel = 'llama-3.1-8b-instant' | 'llama-3.3-70b-versatile'

export interface AppSettings {
  groqApiKey: string
  model: GroqModel
  redactPayloads: boolean
}

// ---- AI streaming ----
export interface AiChunk {
  requestId: string
  type: 'delta' | 'done' | 'error'
  text?: string
  error?: string
}

export interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
}
