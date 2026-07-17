import { useMemo, useState } from 'react'
import { ArrowUpDown } from 'lucide-react'
import type { Flow } from '@shared/types'
import { useStore } from '../store'
import { PageHeader } from '../components/ui'
import { formatBytes, formatDuration, formatNumber } from '../lib/format'

type SortKey = 'packets' | 'bytes' | 'duration' | 'endpoints'

const STATE_STYLE: Record<Flow['tcpState'], string> = {
  established: 'text-sev-low',
  closed: 'text-text-muted',
  reset: 'text-sev-high',
  'syn-sent': 'text-sev-medium',
  'n/a': 'text-text-muted'
}

export function Conversations(): JSX.Element {
  const analysis = useStore((s) => s.analysis)
  const [sort, setSort] = useState<SortKey>('bytes')
  const [query, setQuery] = useState('')

  const flows = analysis?.flows ?? []

  const rows = useMemo(() => {
    const filtered = query.trim()
      ? flows.filter((f) =>
          `${f.addrA}:${f.portA} ${f.addrB}:${f.portB} ${f.appProtocol ?? f.proto}`
            .toLowerCase()
            .includes(query.toLowerCase())
        )
      : flows
    const sorted = [...filtered]
    sorted.sort((a, b) => {
      switch (sort) {
        case 'packets':
          return b.packetsAtoB + b.packetsBtoA - (a.packetsAtoB + a.packetsBtoA)
        case 'bytes':
          return b.bytesAtoB + b.bytesBtoA - (a.bytesAtoB + a.bytesBtoA)
        case 'duration':
          return b.lastTs - b.firstTs - (a.lastTs - a.firstTs)
        case 'endpoints':
          return a.addrA.localeCompare(b.addrA)
      }
    })
    return sorted
  }, [flows, sort, query])

  if (!analysis) {
    return (
      <div className="flex h-full flex-col">
        <PageHeader title="Conversations" />
        <div className="flex-1 px-6 py-5 text-sm text-text-secondary">No capture loaded.</div>
      </div>
    )
  }

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="Conversations"
        subtitle={`${flows.length} flows`}
        actions={
          <input
            className="input w-64"
            placeholder="Filter by host or protocol…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        }
      />
      <div className="flex-1 overflow-auto px-6 py-4">
        <table className="w-full border-collapse text-sm">
          <thead className="sticky top-0 z-10 bg-bg-base">
            <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-text-muted">
              <Th onClick={() => setSort('endpoints')}>Endpoint A</Th>
              <Th>Endpoint B</Th>
              <Th>Protocol</Th>
              <Th onClick={() => setSort('packets')} active={sort === 'packets'} right>
                Packets
              </Th>
              <Th onClick={() => setSort('bytes')} active={sort === 'bytes'} right>
                Bytes
              </Th>
              <Th onClick={() => setSort('duration')} active={sort === 'duration'} right>
                Duration
              </Th>
              <Th>State</Th>
            </tr>
          </thead>
          <tbody>
            {rows.map((f) => (
              <tr
                key={f.id}
                className="border-b border-border-subtle hover:bg-bg-hover"
              >
                <td className="py-2 pr-3 font-mono text-xs text-text-primary">
                  {f.addrA}
                  <span className="text-text-muted">:{f.portA}</span>
                </td>
                <td className="py-2 pr-3 font-mono text-xs text-text-primary">
                  {f.addrB}
                  <span className="text-text-muted">:{f.portB}</span>
                </td>
                <td className="py-2 pr-3 text-xs text-text-secondary">
                  {f.appProtocol ?? f.proto.toUpperCase()}
                </td>
                <td className="py-2 pr-3 text-right text-xs tabular-nums text-text-secondary">
                  {formatNumber(f.packetsAtoB + f.packetsBtoA)}
                </td>
                <td className="py-2 pr-3 text-right text-xs tabular-nums text-text-secondary">
                  {formatBytes(f.bytesAtoB + f.bytesBtoA)}
                </td>
                <td className="py-2 pr-3 text-right text-xs tabular-nums text-text-secondary">
                  {formatDuration(Math.max(0, f.lastTs - f.firstTs))}
                </td>
                <td className={`py-2 text-xs ${STATE_STYLE[f.tcpState]}`}>
                  {f.tcpState === 'n/a' ? '—' : f.tcpState}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 && (
          <div className="py-8 text-center text-sm text-text-muted">No matching conversations.</div>
        )}
      </div>
    </div>
  )
}

function Th({
  children,
  onClick,
  active,
  right
}: {
  children: React.ReactNode
  onClick?: () => void
  active?: boolean
  right?: boolean
}): JSX.Element {
  return (
    <th
      onClick={onClick}
      className={[
        'py-2 pr-3 font-medium',
        right ? 'text-right' : 'text-left',
        onClick ? 'cursor-pointer select-none hover:text-text-secondary' : '',
        active ? 'text-accent' : ''
      ].join(' ')}
    >
      <span className={`inline-flex items-center gap-1 ${right ? 'flex-row-reverse' : ''}`}>
        {children}
        {onClick && <ArrowUpDown className="h-3 w-3 opacity-50" />}
      </span>
    </th>
  )
}
