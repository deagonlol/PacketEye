import type { ReactNode } from 'react'
import type { Severity } from '@shared/types'
import { SEVERITY_BG_CLASS, SEVERITY_LABEL } from '../lib/format'

export function PageHeader({
  title,
  subtitle,
  actions
}: {
  title: string
  subtitle?: string
  actions?: ReactNode
}): JSX.Element {
  return (
    <div className="flex min-h-[48px] items-center justify-between border-b border-border bg-bg-panel px-4 py-2">
      <div>
        <h1 className="text-[15px] font-semibold leading-tight text-text-primary">{title}</h1>
        {subtitle && <p className="mt-0.5 text-[11px] text-text-secondary">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  )
}

export function SeverityBadge({ severity }: { severity: Severity }): JSX.Element {
  return (
    <span
      className={`inline-flex items-center rounded-[2px] border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.04em] ${SEVERITY_BG_CLASS[severity]}`}
    >
      {SEVERITY_LABEL[severity]}
    </span>
  )
}

export function StatCard({
  label,
  value,
  hint,
  accent
}: {
  label: string
  value: ReactNode
  hint?: string
  accent?: string
}): JSX.Element {
  return (
    <div className="card group relative overflow-hidden p-4">
      <div className="eyebrow">{label}</div>
      <div
        className="mt-2 text-[24px] font-semibold leading-none tracking-[-0.02em] text-text-primary"
        style={accent ? { color: accent } : undefined}
      >
        {value}
      </div>
      {hint && <div className="mt-2 text-xs text-text-secondary">{hint}</div>}
    </div>
  )
}

export function EmptyState({
  icon,
  title,
  message,
  action
}: {
  icon?: ReactNode
  title: string
  message?: string
  action?: ReactNode
}): JSX.Element {
  return (
    <div className="flex h-full flex-col items-center justify-center px-6 text-center">
      {icon && <div className="mb-4 text-text-muted">{icon}</div>}
      <h2 className="text-base font-semibold text-text-primary">{title}</h2>
      {message && <p className="mt-1 max-w-md text-sm text-text-secondary">{message}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}

export function Spinner({ className = '' }: { className?: string }): JSX.Element {
  return (
    <span
      className={`inline-block animate-spin rounded-full border-2 border-border border-t-accent ${className}`}
    />
  )
}
