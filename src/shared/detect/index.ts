// Threat-detection engine entry. Runs each deterministic rule over the parsed
// capture and returns findings sorted by severity.
import type { Finding, Flow, Severity } from '../types'
import type { Analyzer } from '../pcap/analyze'
import type { DetectPacket } from './context'
import { ALL_RULES } from './rules'

export type DetectFlow = Flow & { timestamps?: number[] }

export interface DetectionInput {
  packets: DetectPacket[]
  flows: DetectFlow[]
  analyzer: Analyzer
}

const SEV_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4
}

export function runDetection(input: DetectionInput): Finding[] {
  const findings: Finding[] = []
  for (const rule of ALL_RULES) {
    try {
      findings.push(...rule(input))
    } catch (err) {
      // A single misbehaving rule must not abort the whole analysis.
      console.error('detection rule failed:', err)
    }
  }
  // Assign stable ids and sort by severity then title.
  findings.forEach((f, i) => {
    if (!f.id) f.id = `finding-${i + 1}`
  })
  return findings.sort(
    (a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || a.title.localeCompare(b.title)
  )
}
