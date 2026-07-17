// Pure report-markdown formatting, shared by the export handler and tests.
import type { CaptureAnalysis, Severity } from './types'

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export function findingsMarkdown(analysis: CaptureAnalysis): string {
  const { stats, findings } = analysis
  const lines: string[] = []
  lines.push(`# PacketEye Report — ${stats.fileName}`)
  lines.push('')
  lines.push(`- **Packets:** ${stats.packetCount.toLocaleString()}`)
  lines.push(`- **Bytes:** ${stats.totalBytes.toLocaleString()}`)
  lines.push(`- **Duration:** ${stats.durationSec.toFixed(2)} s`)
  lines.push(`- **Hosts:** ${stats.hostCount}`)
  lines.push(`- **Captured:** ${new Date(stats.startTime * 1000).toISOString()}`)
  lines.push('')

  const bySev = SEV_ORDER.map(
    (s) => `${findings.filter((f) => f.severity === s).length} ${s}`
  ).join(' · ')
  lines.push(`**Findings:** ${bySev}`)
  lines.push('')
  lines.push('## Detected Findings')
  lines.push('')
  if (findings.length === 0) {
    lines.push('_No findings were flagged by the detection engine._')
  }
  const sorted = [...findings].sort(
    (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
  )
  for (const f of sorted) {
    lines.push(`### [${f.severity.toUpperCase()}] ${f.title}`)
    lines.push('')
    lines.push(f.description)
    lines.push('')
    if (f.affectedHosts.length) lines.push(`- **Affected hosts:** ${f.affectedHosts.join(', ')}`)
    if (f.evidence.length)
      lines.push(`- **Evidence packets:** ${f.evidence.slice(0, 20).join(', ')}`)
    if (f.mitre) lines.push(`- **MITRE ATT&CK:** ${f.mitre}`)
    lines.push(`- **Remediation:** ${f.remediation}`)
    lines.push('')
  }
  return lines.join('\n')
}

/** Build the full exportable report markdown (findings + optional AI section). */
export function buildReportMarkdown(analysis: CaptureAnalysis, aiMarkdown: string): string {
  let content = findingsMarkdown(analysis)
  if (aiMarkdown && aiMarkdown.trim()) {
    content += '\n\n---\n\n# AI Threat Assessment\n\n' + aiMarkdown.trim() + '\n'
  }
  return content
}
