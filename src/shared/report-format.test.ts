import { describe, it, expect } from 'vitest'
import { buildMixedCapture } from '../../scripts/scenarios'
import { analyzeCapture } from './pcap/analyze-capture'
import { buildReportMarkdown } from './report-format'

const { analysis } = analyzeCapture(buildMixedCapture().toBuffer(), { fileName: 'mixed-threats.pcap' })

describe('report markdown export', () => {
  const md = buildReportMarkdown(analysis, '')

  it('includes capture metadata and a findings section', () => {
    expect(md).toContain('# PacketEye Report — mixed-threats.pcap')
    expect(md).toContain('## Detected Findings')
    expect(md).toMatch(/\*\*Packets:\*\* \d/)
  })

  it('lists each finding with severity, remediation, and evidence', () => {
    expect(md).toMatch(/### \[CRITICAL\] .*ARP spoofing/)
    expect(md).toContain('**Remediation:**')
    expect(md).toContain('**Evidence packets:**')
    expect(md).toContain('**MITRE ATT&CK:**')
  })

  it('appends the AI assessment section when provided', () => {
    const withAi = buildReportMarkdown(analysis, '## Executive Summary\nAll bad.')
    expect(withAi).toContain('# AI Threat Assessment')
    expect(withAi).toContain('All bad.')
  })

  it('omits the AI section when no report is given', () => {
    expect(md).not.toContain('# AI Threat Assessment')
  })
})
