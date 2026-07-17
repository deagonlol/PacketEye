import type { CaptureAnalysis, CaptureDigest } from '../../shared/types'

const MAX_DNS = 40
const MAX_HTTP = 40
const MAX_TLS = 30
const MAX_CONVERSATIONS = 25

/**
 * Condense a full analysis into a few-KB JSON structure suitable for an LLM
 * prompt. Never includes raw packet bytes. When `redact` is true, payload-ish
 * strings (HTTP paths, DNS names) are trimmed to reduce sensitive leakage.
 */
export function buildDigest(analysis: CaptureAnalysis, redact: boolean): CaptureDigest {
  const { stats, flows, findings, summaries } = analysis

  const topConversations = [...flows]
    .sort((a, b) => b.bytesAtoB + b.bytesBtoA - (a.bytesAtoB + a.bytesBtoA))
    .slice(0, MAX_CONVERSATIONS)
    .map((f) => ({
      endpoints: `${f.addrA}:${f.portA} <-> ${f.addrB}:${f.portB}`,
      proto: f.proto,
      appProtocol: f.appProtocol,
      packets: f.packetsAtoB + f.packetsBtoA,
      bytes: f.bytesAtoB + f.bytesBtoA
    }))

  const dns = summaries.dns.slice(0, MAX_DNS).map((d) => ({
    name: redact ? redactHost(d.name) : d.name,
    types: d.types,
    rcodes: d.responseCodes,
    count: d.count,
    suspicious: d.suspicious
  }))

  const http = summaries.http.slice(0, MAX_HTTP).map((h) => ({
    method: h.method,
    host: redact ? redactHost(h.host) : h.host,
    path: redact ? '[redacted]' : h.path,
    basicAuth: h.hasBasicAuth,
    status: h.status
  }))

  const tls = summaries.tls.slice(0, MAX_TLS).map((t) => ({
    sni: redact ? redactHost(t.sni ?? '') : t.sni,
    version: t.version,
    weak: t.weak
  }))

  return {
    meta: {
      fileName: stats.fileName,
      packetCount: stats.packetCount,
      durationSec: Math.round(stats.durationSec * 1000) / 1000,
      startTime: new Date(stats.startTime * 1000).toISOString(),
      hostCount: stats.hostCount,
      totalBytes: stats.totalBytes
    },
    protocolHierarchy: stats.protocolHierarchy,
    topTalkers: stats.topTalkers.slice(0, 15),
    topConversations,
    dns,
    http,
    tls,
    findings: findings.map((f) => ({
      severity: f.severity,
      category: f.category,
      title: f.title,
      description: f.description,
      affectedHosts: f.affectedHosts,
      detail: f.detail
    }))
  }
}

function redactHost(host: string): string {
  if (!host) return host
  // Keep the registrable-ish tail, redact deeper labels.
  const parts = host.split('.')
  if (parts.length <= 2) return host
  return `***.${parts.slice(-2).join('.')}`
}
