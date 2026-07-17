import { ScanSearch, ShieldCheck } from 'lucide-react'
import { useStore } from '../store'
import { formatBytes, formatNumber } from '../lib/format'

export function ParsingOverlay(): JSX.Element {
  const progress = useStore((s) => s.progress)
  const fileName = useStore((s) => s.fileName)

  const pct =
    progress && progress.totalBytes > 0
      ? Math.min(100, (progress.bytesRead / progress.totalBytes) * 100)
      : 0

  return (
    <div className="absolute inset-0 z-20 flex items-center justify-center bg-bg-base/75 p-6">
      <div className="card w-full max-w-md p-5 shadow-glow">
        <div className="flex items-start justify-between">
          <div><div className="eyebrow">Capture loading</div><div className="mt-1 text-base font-semibold text-text-primary">Analyzing capture</div><div className="mt-1 truncate text-xs text-text-secondary">{fileName}</div></div>
          <div className="flex h-9 w-9 items-center justify-center rounded-[3px] border border-border bg-bg-elevated text-accent"><ScanSearch className="h-4 w-4" /></div>
        </div>

        <div className="mt-5 h-3 overflow-hidden rounded-[2px] border border-border bg-bg-elevated">
          <div
            className="h-full bg-accent transition-all duration-200"
            style={{ width: `${pct || 3}%` }}
          />
        </div>

        <div className="mt-3 flex items-center justify-between text-[11px] text-text-secondary">
          <span>
            {progress ? formatNumber(progress.packets) : 0} packets
            {progress?.phase === 'analyzing' && ' · detecting threats…'}
          </span>
          <span>
            {progress
              ? `${formatBytes(progress.bytesRead)} / ${formatBytes(progress.totalBytes)}`
              : ''}
          </span>
        </div>
        <div className="mt-6 flex items-center gap-2 border-t border-border-subtle pt-4 text-[10px] text-text-muted"><ShieldCheck className="h-3.5 w-3.5 text-accent" /> Parsing locally. No packet data leaves this device.</div>
      </div>
    </div>
  )
}
