import { useState } from 'react'
import { ChevronRight, ShieldCheck, ArrowRight, Target, Wrench, Server } from 'lucide-react'
import type { Finding } from '@shared/types'
import { navigate, useStore } from '../store'
import { PageHeader, SeverityBadge, EmptyState } from '../components/ui'
import { SeveritySummary } from '../components/SeveritySummary'
import { SEVERITY_COLOR, SEVERITY_ORDER } from '../lib/format'

export function Findings(): JSX.Element {
  const analysis = useStore((s) => s.analysis)
  const [expanded, setExpanded] = useState<Set<string>>(new Set())

  if (!analysis) {
    return (
      <div className="flex h-full flex-col">
        <PageHeader title="Findings" />
        <div className="flex-1 px-6 py-5 text-sm text-text-secondary">No capture loaded.</div>
      </div>
    )
  }

  const { findings } = analysis
  const toggle = (id: string): void =>
    setExpanded((prev) => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })

  if (findings.length === 0) {
    return (
      <div className="flex h-full flex-col">
        <PageHeader title="Findings" subtitle="0 issues detected" />
        <EmptyState
          icon={<ShieldCheck className="h-12 w-12 text-[#218739]" />}
          title="No threats detected"
          message="The detection engine did not flag any threats, insecure practices, or suspicious activity in this capture."
        />
      </div>
    )
  }

  const grouped = SEVERITY_ORDER.map((sev) => ({
    sev,
    items: findings.filter((f) => f.severity === sev)
  })).filter((g) => g.items.length > 0)

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="Findings"
        subtitle={`${findings.length} issue${findings.length === 1 ? '' : 's'} detected`}
      />
      <div className="flex-1 overflow-y-auto px-6 py-5">
        <div className="mx-auto max-w-4xl space-y-5">
          <SeveritySummary findings={findings} />

          {grouped.map((group) => (
            <div key={group.sev} className="space-y-2">
              {group.items.map((f) => (
                <FindingCard
                  key={f.id}
                  finding={f}
                  open={expanded.has(f.id)}
                  onToggle={() => toggle(f.id)}
                />
              ))}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function FindingCard({
  finding,
  open,
  onToggle
}: {
  finding: Finding
  open: boolean
  onToggle: () => void
}): JSX.Element {
  return (
    <div
      className="card overflow-hidden"
      style={{ borderLeft: `3px solid ${SEVERITY_COLOR[finding.severity]}` }}
    >
      <button
        onClick={onToggle}
        className="flex w-full items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-bg-hover"
      >
        <ChevronRight
          className={`h-4 w-4 shrink-0 text-text-muted transition-transform ${open ? 'rotate-90' : ''}`}
        />
        <SeverityBadge severity={finding.severity} />
        <span className="flex-1 text-sm font-medium text-text-primary">{finding.title}</span>
        <span className="shrink-0 text-xs text-text-muted">{finding.evidence.length} pkts</span>
      </button>

      {open && (
        <div className="space-y-4 border-t border-border-subtle px-4 py-4 pl-11">
          <p className="text-sm leading-relaxed text-text-secondary">{finding.description}</p>

          {finding.affectedHosts.length > 0 && (
            <Detail icon={<Server className="h-3.5 w-3.5" />} label="Affected hosts">
              <div className="flex flex-wrap gap-1.5">
                {finding.affectedHosts.map((h) => (
                  <span
                    key={h}
                    className="rounded border border-border-subtle bg-bg-base px-1.5 py-0.5 font-mono text-xs text-text-secondary"
                  >
                    {h}
                  </span>
                ))}
              </div>
            </Detail>
          )}

          {finding.evidence.length > 0 && (
            <Detail icon={<Target className="h-3.5 w-3.5" />} label="Evidence packets">
              <div className="flex flex-wrap gap-1.5">
                {finding.evidence.slice(0, 24).map((n) => (
                  <button
                    key={n}
                    onClick={() => navigate('packets', n)}
                    className="rounded border border-accent/30 bg-accent/10 px-1.5 py-0.5 font-mono text-xs text-accent transition-colors hover:bg-accent/20"
                  >
                    #{n}
                  </button>
                ))}
                {finding.evidence.length > 24 && (
                  <span className="px-1 py-0.5 text-xs text-text-muted">
                    +{finding.evidence.length - 24} more
                  </span>
                )}
              </div>
            </Detail>
          )}

          <Detail icon={<Wrench className="h-3.5 w-3.5" />} label="Remediation">
            <p className="text-sm leading-relaxed text-text-secondary">{finding.remediation}</p>
          </Detail>

          {finding.mitre && (
            <div className="flex items-center gap-2 text-xs text-text-muted">
              <span className="font-medium">MITRE ATT&CK:</span>
              <span className="font-mono">{finding.mitre}</span>
            </div>
          )}

          <button
            onClick={() => navigate('packets', finding.evidence[0])}
            className="inline-flex items-center gap-1 text-xs text-accent hover:underline"
          >
            Inspect evidence in packet list <ArrowRight className="h-3 w-3" />
          </button>
        </div>
      )}
    </div>
  )
}

function Detail({
  icon,
  label,
  children
}: {
  icon: JSX.Element
  label: string
  children: JSX.Element
}): JSX.Element {
  return (
    <div>
      <div className="mb-1.5 flex items-center gap-1.5 text-xs font-medium uppercase tracking-wide text-text-muted">
        {icon}
        {label}
      </div>
      {children}
    </div>
  )
}
