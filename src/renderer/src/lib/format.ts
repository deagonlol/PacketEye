import type { Finding, Severity } from '@shared/types'

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(v < 10 ? 2 : 1)} ${units[i]}`
}

export function formatNumber(n: number): string {
  return n.toLocaleString()
}

export function formatDuration(sec: number): string {
  if (sec < 1) return `${(sec * 1000).toFixed(0)} ms`
  if (sec < 60) return `${sec.toFixed(2)} s`
  const m = Math.floor(sec / 60)
  const s = Math.round(sec % 60)
  return `${m}m ${s}s`
}

export function formatTimeOffset(sec: number): string {
  return sec.toFixed(6)
}

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info'
}

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: '#c92a2a',
  high: '#e66a00',
  medium: '#d39e00',
  low: '#7f9f16',
  info: '#3d9860'
}

export type ScanHealthLevel = 'healthy' | Severity

export interface ScanHealth {
  level: ScanHealthLevel
  label: string
  color: string
  surface: string
  border: string
  description: string
  findingCount: number
}

const HEALTH_META: Record<ScanHealthLevel, Omit<ScanHealth, 'level' | 'findingCount'>> = {
  healthy: {
    label: 'Healthy',
    color: '#218739',
    surface: '#e8f5ea',
    border: '#92c89c',
    description: 'No security findings were detected in this capture.'
  },
  info: {
    label: 'Informational',
    color: SEVERITY_COLOR.info,
    surface: '#e7f4ec',
    border: '#9bc9ac',
    description: 'Only informational signals were detected.'
  },
  low: {
    label: 'Low risk',
    color: SEVERITY_COLOR.low,
    surface: '#f1f5df',
    border: '#bdcc7d',
    description: 'Low-severity findings are available for review.'
  },
  medium: {
    label: 'Moderate risk',
    color: SEVERITY_COLOR.medium,
    surface: '#fff6d8',
    border: '#e8c75d',
    description: 'Medium-severity findings should be reviewed.'
  },
  high: {
    label: 'High risk',
    color: SEVERITY_COLOR.high,
    surface: '#fff0df',
    border: '#eca86b',
    description: 'High-severity findings need prompt attention.'
  },
  critical: {
    label: 'Critical risk',
    color: SEVERITY_COLOR.critical,
    surface: '#fdeaea',
    border: '#df9292',
    description: 'Critical findings need immediate investigation.'
  }
}

/** Returns capture health based on the highest-severity finding present. */
export function getScanHealth(findings: Finding[]): ScanHealth {
  const level: ScanHealthLevel =
    SEVERITY_ORDER.find((severity) => findings.some((finding) => finding.severity === severity)) ?? 'healthy'
  return { level, findingCount: findings.length, ...HEALTH_META[level] }
}

export const SEVERITY_TEXT_CLASS: Record<Severity, string> = {
  critical: 'text-sev-critical',
  high: 'text-sev-high',
  medium: 'text-sev-medium',
  low: 'text-sev-low',
  info: 'text-sev-info'
}

export const SEVERITY_BG_CLASS: Record<Severity, string> = {
  critical: 'bg-sev-critical/15 text-sev-critical border-sev-critical/30',
  high: 'bg-sev-high/15 text-sev-high border-sev-high/30',
  medium: 'bg-sev-medium/15 text-sev-medium border-sev-medium/30',
  low: 'bg-sev-low/15 text-sev-low border-sev-low/30',
  info: 'bg-sev-info/15 text-sev-info border-sev-info/30'
}
