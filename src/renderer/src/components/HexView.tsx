import { useMemo } from 'react'

/**
 * Wireshark-style hex dump: 16 bytes per row with offset gutter and ASCII
 * sidebar. `hex` is space-separated uppercase byte pairs; `ascii` is the full
 * decoded string (non-printables already replaced with '.').
 */
export function HexView({ hex, ascii }: { hex: string; ascii: string }): JSX.Element {
  const rows = useMemo(() => {
    const bytes = hex ? hex.split(' ') : []
    const out: { offset: string; cells: string[]; text: string }[] = []
    for (let i = 0; i < bytes.length; i += 16) {
      out.push({
        offset: i.toString(16).padStart(4, '0'),
        cells: bytes.slice(i, i + 16),
        text: ascii.slice(i, i + 16)
      })
    }
    return out
  }, [hex, ascii])

  if (rows.length === 0) {
    return <div className="p-3 text-xs text-text-muted">No raw bytes.</div>
  }

  return (
    <div className="min-w-max p-2 font-mono text-[10px] leading-[1.55]">
      {rows.map((row) => (
        <div key={row.offset} className="flex gap-3 whitespace-pre hover:bg-[#e6f0f8]">
          <span className="w-9 select-none text-right text-text-muted">{row.offset}</span>
          <span className="text-[#174f7a]">
            {row.cells.map((c, i) => (
              <span key={i}>
                {c}
                {i === 7 ? '  ' : ' '}
              </span>
            ))}
            {/* pad short final row for alignment */}
            {row.cells.length < 16
              ? ' '.repeat((16 - row.cells.length) * 3 + (row.cells.length <= 8 ? 1 : 0))
              : ''}
          </span>
          <span className="border-l border-border-subtle pl-2 text-text-primary">{row.text}</span>
        </div>
      ))}
    </div>
  )
}
