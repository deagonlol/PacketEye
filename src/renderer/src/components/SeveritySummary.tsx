import type { Finding, Severity } from '@shared/types'
import { SEVERITY_COLOR, SEVERITY_LABEL, SEVERITY_ORDER } from '../lib/format'

export function severityCounts(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  }
  for (const f of findings) counts[f.severity]++
  return counts
}

export function SeveritySummary({
  findings,
  onSelect,
  compact = false
}: {
  findings: Finding[]
  onSelect?: (sev: Severity) => void
  compact?: boolean
}): JSX.Element {
  const counts = severityCounts(findings)
  return (
    <div className={compact ? 'space-y-2' : 'grid grid-cols-5 gap-2'}>
      {SEVERITY_ORDER.map((sev) => {
        const n = counts[sev]
        const active = n > 0
        return (
          <button
            key={sev}
            disabled={!onSelect}
            onClick={() => onSelect?.(sev)}
            className={[
              compact ? 'flex w-full items-center rounded-[2px] border px-3 py-2 text-left transition-colors' : 'rounded-[2px] border p-3 text-left transition-colors',
              active ? 'border-border bg-bg-elevated' : 'border-border-subtle bg-bg-panel',
              onSelect ? 'hover:bg-bg-hover' : 'cursor-default'
            ].join(' ')}
          >
            <div className="flex items-center gap-2">
              <span
                className="h-2 w-2 rounded-full"
                style={{ backgroundColor: active ? SEVERITY_COLOR[sev] : '#a0a8af' }}
              />
              <span className="text-[11px] font-medium uppercase tracking-wide text-text-muted">
                {SEVERITY_LABEL[sev]}
              </span>
            </div>
            <div
              className={compact ? 'ml-auto text-sm font-bold tabular-nums' : 'mt-1 text-2xl font-semibold tabular-nums'}
              style={{ color: active ? SEVERITY_COLOR[sev] : '#77818a' }}
            >
              {n}
            </div>
          </button>
        )
      })}
    </div>
  )
}
