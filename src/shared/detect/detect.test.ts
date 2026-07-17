import { describe, it, expect } from 'vitest'
import { buildMixedCapture, buildBenignCapture } from '../../../scripts/scenarios'
import { analyzeCapture } from '../pcap/analyze-capture'
import type { Finding, FindingCategory } from '../types'

function analyze(buf: Buffer): Finding[] {
  return analyzeCapture(buf, { fileName: 'test.pcap' }).analysis.findings
}

const mixed = analyze(buildMixedCapture().toBuffer())
const benign = analyze(buildBenignCapture().toBuffer())

function byCategory(findings: Finding[], cat: FindingCategory): Finding[] {
  return findings.filter((f) => f.category === cat)
}
function titled(findings: Finding[], re: RegExp): Finding | undefined {
  return findings.find((f) => re.test(f.title))
}

describe('detection engine — mixed threat capture', () => {
  it('flags cleartext credentials (Telnet + HTTP Basic auth)', () => {
    const creds = byCategory(mixed, 'credentials')
    expect(creds.length).toBeGreaterThan(0)
    expect(titled(creds, /Telnet/i)).toBeDefined()
    expect(titled(creds, /Basic Auth/i)).toBeDefined()
    // Credentials are the highest severity.
    expect(creds.every((f) => f.severity === 'critical')).toBe(true)
  })

  it('flags insecure protocols (HTTP, Telnet)', () => {
    const insec = byCategory(mixed, 'insecure-protocol')
    expect(titled(insec, /HTTP/i)).toBeDefined()
    expect(titled(insec, /Telnet/i)).toBeDefined()
  })

  it('flags weak/obsolete TLS', () => {
    const weak = byCategory(mixed, 'weak-crypto')
    expect(weak.length).toBe(1)
    expect(weak[0].description).toMatch(/TLS 1\.0/)
  })

  it('flags the TCP port scan', () => {
    const recon = byCategory(mixed, 'recon')
    const scan = titled(recon, /port scan/i)
    expect(scan).toBeDefined()
    expect(scan!.severity).toBe('high')
    expect(scan!.evidence.length).toBeGreaterThan(0)
  })

  it('flags ARP spoofing with multiple MACs', () => {
    const spoof = titled(byCategory(mixed, 'spoofing'), /ARP spoofing/i)
    expect(spoof).toBeDefined()
    expect(spoof!.severity).toBe('critical')
    expect(spoof!.affectedHosts).toContain('192.168.1.1')
  })

  it('flags rogue DHCP (multiple servers)', () => {
    const dhcp = titled(byCategory(mixed, 'spoofing'), /DHCP/i)
    expect(dhcp).toBeDefined()
    expect(dhcp!.detail).toMatch(/2 servers/)
  })

  it('flags DNS tunneling', () => {
    const tunnel = titled(byCategory(mixed, 'c2-exfil'), /DNS tunneling/i)
    expect(tunnel).toBeDefined()
    expect(tunnel!.detail).toContain('evil-c2.com')
  })

  it('every finding has evidence packets, hosts, and remediation', () => {
    for (const f of mixed) {
      expect(f.remediation.length).toBeGreaterThan(10)
      expect(f.title.length).toBeGreaterThan(0)
      // Evidence may be empty only for capture-wide hygiene findings.
      if (f.category !== 'hygiene') {
        expect(f.evidence.length).toBeGreaterThan(0)
      }
    }
  })

  it('sorts findings by severity (critical first)', () => {
    const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
    for (let i = 1; i < mixed.length; i++) {
      expect(rank[mixed[i].severity]).toBeGreaterThanOrEqual(rank[mixed[i - 1].severity])
    }
  })
})

describe('detection engine — benign capture (false-positive guard)', () => {
  it('does not flag scans, spoofing, credentials, or tunneling', () => {
    expect(byCategory(benign, 'credentials')).toHaveLength(0)
    expect(byCategory(benign, 'recon')).toHaveLength(0)
    expect(byCategory(benign, 'spoofing')).toHaveLength(0)
    expect(byCategory(benign, 'c2-exfil')).toHaveLength(0)
    expect(byCategory(benign, 'weak-crypto')).toHaveLength(0)
  })
})
