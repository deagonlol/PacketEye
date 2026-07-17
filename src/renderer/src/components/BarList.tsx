import type { ReactNode } from 'react'

export interface BarItem {
  label: string
  value: number
  display: string
  sublabel?: string
  onClick?: () => void
}

/**
 * A compact horizontal bar list for single-measure comparisons (protocol
 * counts, top talkers). One hue — magnitude is encoded by bar length, identity
 * by the row label. Values wear text ink, not the bar color.
 */
export function BarList({
  items,
  accent = '#1f6fae',
  emptyText = 'No data'
}: {
  items: BarItem[]
  accent?: string
  emptyText?: string
}): JSX.Element {
  const max = Math.max(1, ...items.map((i) => i.value))
  if (items.length === 0) {
    return <div className="py-6 text-center text-sm text-text-muted">{emptyText}</div>
  }
  return (
    <div className="space-y-2.5">
      {items.map((item, i) => (
        <Row key={i} item={item} pct={(item.value / max) * 100} accent={accent} />
      ))}
    </div>
  )
}

function Row({ item, pct, accent }: { item: BarItem; pct: number; accent: string }): JSX.Element {
  const inner: ReactNode = (
    <>
      <div className="flex items-baseline justify-between gap-2">
        <span className="truncate font-mono text-xs text-text-primary">{item.label}</span>
        <span className="shrink-0 text-xs tabular-nums text-text-secondary">{item.display}</span>
      </div>
      <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-bg-elevated">
        <div
          className="h-full rounded-full"
          style={{ width: `${Math.max(2, pct)}%`, backgroundColor: accent }}
        />
      </div>
      {item.sublabel && <div className="mt-0.5 text-[11px] text-text-muted">{item.sublabel}</div>}
    </>
  )
  if (item.onClick) {
    return (
      <button
        onClick={item.onClick}
        className="block w-full rounded-[2px] px-1.5 py-1 text-left transition-colors hover:bg-bg-hover"
      >
        {inner}
      </button>
    )
  }
  return <div className="px-1 py-0.5">{inner}</div>
}
