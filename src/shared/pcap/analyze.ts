// Accumulates capture-wide statistics and application-layer summaries as each
// packet is dissected.
import type {
  AppSummaries,
  CaptureStats,
  DnsSummaryEntry,
  HttpSummaryEntry,
  ProtocolCount,
  TalkerStat,
  TimeBucket,
  TlsSummaryEntry
} from '../types'
import type { Dissection } from './model'

const TIMELINE_BUCKETS = 120

export class Analyzer {
  private protoBytes = new Map<string, { packets: number; bytes: number }>()
  private talkerBytes = new Map<string, { packets: number; bytes: number }>()
  private hosts = new Set<string>()

  private startTs = Infinity
  private endTs = -Infinity
  private totalBytes = 0
  private packetCount = 0

  // Raw timed samples; bucketed at the end once duration is known.
  private timeline: { ts: number; bytes: number }[] = []

  // App summaries keyed for dedup.
  private dnsMap = new Map<string, DnsSummaryEntry>()
  private http: HttpSummaryEntry[] = []
  private tls: TlsSummaryEntry[] = []

  add(d: Dissection, tsSec: number, length: number, packetNumber: number): void {
    this.packetCount++
    this.totalBytes += length
    if (tsSec > 0) {
      if (tsSec < this.startTs) this.startTs = tsSec
      if (tsSec > this.endTs) this.endTs = tsSec
    }

    const proto = d.protocol || 'Unknown'
    const pc = this.protoBytes.get(proto) ?? { packets: 0, bytes: 0 }
    pc.packets++
    pc.bytes += length
    this.protoBytes.set(proto, pc)

    if (d.isIp) {
      this.hosts.add(d.srcAddr)
      this.hosts.add(d.dstAddr)
      this.bumpTalker(d.srcAddr, length)
      this.bumpTalker(d.dstAddr, length)
    }

    this.timeline.push({ ts: tsSec, bytes: length })

    // ---- App-layer summaries ----
    if (d.dns) {
      for (const q of d.dns.questions.length ? d.dns.questions : d.dns.answers) {
        const key = q.name.toLowerCase()
        const entry = this.dnsMap.get(key) ?? {
          name: q.name,
          types: [],
          responseCodes: [],
          count: 0,
          addresses: [],
          suspicious: false
        }
        entry.count++
        if (!entry.types.includes(q.type)) entry.types.push(q.type)
        if (!entry.responseCodes.includes(d.dns.rcodeName))
          entry.responseCodes.push(d.dns.rcodeName)
        for (const a of d.dns.answers) {
          if ((a.type === 'A' || a.type === 'AAAA') && !entry.addresses.includes(a.data))
            entry.addresses.push(a.data)
        }
        this.dnsMap.set(key, entry)
      }
    }
    if (d.http && d.http.kind === 'request') {
      this.http.push({
        method: d.http.method ?? '?',
        host: d.http.host ?? d.dstAddr,
        path: d.http.path ?? '',
        userAgent: d.http.userAgent,
        hasBasicAuth: d.http.hasBasicAuth,
        packetNumber
      })
    }
    if (d.tls && d.tls.kind === 'client-hello') {
      this.tls.push({
        sni: d.tls.sni,
        version: d.tls.version,
        cipherSuites: d.tls.cipherSuites,
        packetNumber,
        weak: d.tls.weak
      })
    }
  }

  private bumpTalker(addr: string, length: number): void {
    const t = this.talkerBytes.get(addr) ?? { packets: 0, bytes: 0 }
    t.packets++
    t.bytes += length
    this.talkerBytes.set(addr, t)
  }

  markDnsSuspicious(name: string): void {
    const e = this.dnsMap.get(name.toLowerCase())
    if (e) e.suspicious = true
  }

  getSummaries(): AppSummaries {
    return {
      dns: [...this.dnsMap.values()].sort((a, b) => b.count - a.count),
      http: this.http,
      tls: this.tls
    }
  }

  private protocolHierarchy(): ProtocolCount[] {
    return [...this.protoBytes.entries()]
      .map(([protocol, v]) => ({ protocol, packets: v.packets, bytes: v.bytes }))
      .sort((a, b) => b.packets - a.packets)
  }

  private topTalkers(): TalkerStat[] {
    return [...this.talkerBytes.entries()]
      .map(([addr, v]) => ({ addr, packets: v.packets, bytes: v.bytes }))
      .sort((a, b) => b.bytes - a.bytes)
      .slice(0, 20)
  }

  private buildTimeline(startTs: number, durationSec: number): TimeBucket[] {
    if (durationSec <= 0 || this.timeline.length === 0) {
      const bytes = this.timeline.reduce((s, x) => s + x.bytes, 0)
      return [{ timeOffset: 0, packets: this.timeline.length, bytes }]
    }
    const bucketDur = durationSec / TIMELINE_BUCKETS
    const buckets: TimeBucket[] = Array.from({ length: TIMELINE_BUCKETS }, (_, i) => ({
      timeOffset: i * bucketDur,
      packets: 0,
      bytes: 0
    }))
    for (const x of this.timeline) {
      if (x.ts <= 0) continue
      let idx = Math.floor((x.ts - startTs) / bucketDur)
      if (idx < 0) idx = 0
      if (idx >= TIMELINE_BUCKETS) idx = TIMELINE_BUCKETS - 1
      buckets[idx].packets++
      buckets[idx].bytes += x.bytes
    }
    return buckets
  }

  finalize(base: {
    fileName: string
    fileSizeBytes: number
    format: CaptureStats['format']
    linkType: string
  }): CaptureStats {
    const start = this.startTs === Infinity ? 0 : this.startTs
    const end = this.endTs === -Infinity ? 0 : this.endTs
    const duration = end > start ? end - start : 0
    return {
      ...base,
      packetCount: this.packetCount,
      totalBytes: this.totalBytes,
      startTime: start,
      endTime: end,
      durationSec: duration,
      protocolHierarchy: this.protocolHierarchy(),
      topTalkers: this.topTalkers(),
      timeline: this.buildTimeline(start, duration),
      hostCount: this.hosts.size
    }
  }
}
