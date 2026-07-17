import { useEffect, useState } from 'react'
import { ChevronRight, X } from 'lucide-react'
import type { PacketDetail } from '@shared/types'
import { HexView } from './HexView'
import { Spinner } from './ui'

export function PacketDetailPane({
  packetNumber,
  onClose
}: {
  packetNumber: number
  onClose: () => void
}): JSX.Element {
  const [detail, setDetail] = useState<PacketDetail | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setDetail(null)
    window.packeteye.getPacketDetail(packetNumber).then((d) => {
      if (cancelled) return
      setDetail(d)
      setLoading(false)
    })
    return () => {
      cancelled = true
    }
  }, [packetNumber])

  return (
    <div className="flex h-full min-w-0 bg-bg-panel">
      <section className="flex min-w-0 flex-1 flex-col border-r border-border" aria-label="Packet details">
        <div className="flex h-6 shrink-0 items-center justify-between border-b border-border bg-[#e3e5e7] px-2">
          <div className="text-[10px] font-semibold text-text-secondary">Packet details · Frame {packetNumber}</div>
          <button onClick={onClose} className="p-0.5 text-text-muted hover:text-text-primary" aria-label="Close packet details">
            <X className="h-3.5 w-3.5" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto bg-white">
        {loading && (
          <div className="flex items-center gap-2 p-4 text-xs text-text-secondary">
            <Spinner className="h-3.5 w-3.5" /> Decoding…
          </div>
        )}
        {detail && (
          <>
            <div className="py-1">
              {detail.layers.map((layer, i) => (
                <LayerNode key={i} name={layer.name} summary={layer.summary} fields={layer.fields} />
              ))}
            </div>
          </>
        )}
        </div>
      </section>

      <section className="flex min-w-0 flex-1 flex-col" aria-label="Packet bytes">
        <div className="flex h-6 shrink-0 items-center border-b border-border bg-[#e3e5e7] px-2 text-[10px] font-semibold text-text-secondary">
          Packet bytes {detail ? `· ${detail.summary.rawLength} bytes` : ''}
        </div>
        <div className="flex-1 overflow-auto bg-white">
          {detail ? <HexView hex={detail.hex} ascii={detail.ascii} /> : null}
        </div>
      </section>
    </div>
  )
}

function LayerNode({
  name,
  summary,
  fields
}: {
  name: string
  summary?: string
  fields: { label: string; value: string }[]
}): JSX.Element {
  const [open, setOpen] = useState(true)
  return (
    <div className="border-b border-border-subtle bg-white">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-1 px-2 py-1 text-left hover:bg-bg-hover"
      >
        <ChevronRight className={`h-3 w-3 shrink-0 text-text-secondary transition-transform ${open ? 'rotate-90' : ''}`} />
        <span className="shrink-0 text-[11px] font-medium text-text-primary">{name}</span>
        {summary && <span className="truncate pl-1 text-[10px] text-text-muted">{summary}</span>}
      </button>
      {open && fields.length > 0 && (
        <div className="border-t border-border-subtle bg-[#f8f9fa] py-1 pl-6 pr-2">
          <table className="w-full">
            <tbody>
              {fields.map((f, i) => (
                <tr key={i} className="align-top">
                  <td className="w-40 py-px pr-3 text-[10px] text-text-muted">{f.label}</td>
                  <td className="py-px font-mono text-[10px] text-text-primary">{f.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
