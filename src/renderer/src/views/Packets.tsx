import { useEffect, useMemo, useRef, useState } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { ArrowDownToLine, ArrowUpToLine, Check, MousePointerClick, Search, X } from 'lucide-react'
import { setState, useStore } from '../store'
import { PageHeader } from '../components/ui'
import { PacketDetailPane } from '../components/PacketDetail'
import { usePacketData } from '../lib/usePacketData'
import { formatTimeOffset } from '../lib/format'

const ROW_HEIGHT = 24

const PROTO_COLOR: Record<string, string> = {
  DNS: '#155f8d',
  mDNS: '#155f8d',
  LLMNR: '#155f8d',
  NBNS: '#155f8d',
  HTTP: '#6b3f00',
  TLS: '#176a3b',
  HTTPS: '#176a3b',
  ARP: '#663785',
  ICMP: '#8a2e62',
  Telnet: '#9c2430',
  FTP: '#9c2430',
  DHCP: '#6f5a00',
  TCP: '#344450',
  UDP: '#344450'
}

const PROTO_ROW: Record<string, string> = {
  DNS: '#d9eef7',
  mDNS: '#d9eef7',
  LLMNR: '#d9eef7',
  NBNS: '#d9eef7',
  HTTP: '#f6e4c4',
  TLS: '#d8f0d2',
  HTTPS: '#d8f0d2',
  ARP: '#eadcf4',
  ICMP: '#f5dce9',
  Telnet: '#f5d4d4',
  FTP: '#f5d4d4',
  DHCP: '#f8edbd',
  TCP: '#e7edf2',
  UDP: '#e3eef6'
}

const QUICK_FILTERS = ['tcp', 'udp', 'dns', 'http', 'tls']

export function Packets(): JSX.Element {
  const analysis = useStore((s) => s.analysis)
  const focusPacket = useStore((s) => s.focusPacket)
  const [rawFilter, setRawFilter] = useState('')
  const [filter, setFilter] = useState('')
  const [selected, setSelected] = useState<number | null>(null)
  const parentRef = useRef<HTMLDivElement>(null)

  const data = usePacketData(filter)

  // Debounce the filter input to avoid a query per keystroke.
  useEffect(() => {
    const id = setTimeout(() => setFilter(rawFilter), 200)
    return () => clearTimeout(id)
  }, [rawFilter])

  const rowVirtualizer = useVirtualizer({
    count: data.filtered,
    getScrollElement: () => parentRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 20
  })

  const virtualItems = rowVirtualizer.getVirtualItems()
  const firstVisible = virtualItems.length > 0 ? virtualItems[0].index + 1 : 0
  const lastVisible = virtualItems.length > 0 ? virtualItems[virtualItems.length - 1].index + 1 : 0

  // Fetch the pages covering the visible window.
  useEffect(() => {
    if (virtualItems.length === 0) return
    data.ensureRange(virtualItems[0].index, virtualItems[virtualItems.length - 1].index)
  }, [virtualItems, data])

  // Cross-navigation: a finding's evidence link scrolls to & selects a packet.
  useEffect(() => {
    if (focusPacket == null) return
    setRawFilter('')
    setFilter('')
    setSelected(focusPacket)
    // Defer until the (unfiltered) list is sized.
    const id = setTimeout(() => {
      rowVirtualizer.scrollToIndex(Math.max(0, focusPacket - 1), { align: 'center' })
      setState({ focusPacket: null })
    }, 60)
    return () => clearTimeout(id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusPacket])

  const headerCols = useMemo(
    () => [
      { key: 'no', label: 'No.', w: 'w-16' },
      { key: 'time', label: 'Time', w: 'w-28' },
      { key: 'src', label: 'Source', w: 'w-48' },
      { key: 'dst', label: 'Destination', w: 'w-48' },
      { key: 'proto', label: 'Protocol', w: 'w-24' },
      { key: 'len', label: 'Length', w: 'w-20' }
    ],
    []
  )

  if (!analysis) {
    return (
      <div className="flex h-full flex-col">
        <PageHeader title="Packets" />
        <div className="flex-1 px-6 py-5 text-sm text-text-secondary">No capture loaded.</div>
      </div>
    )
  }

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="Packets"
        subtitle={
          filter
            ? `${data.filtered.toLocaleString()} of ${data.total.toLocaleString()} packets`
            : `${data.total.toLocaleString()} packets`
        }
      />

      <div className="flex items-center gap-2 border-b border-border bg-[#e8eaec] px-2 py-1.5">
        <span className="text-[11px] font-medium text-text-secondary">Display filter</span>
        <div className="relative min-w-0 flex-1">
          <Search className="absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-text-muted" />
          <input
            className="h-7 w-full rounded-[2px] border border-[#76a46a] bg-[#e8f4df] pl-7 pr-8 font-mono text-xs text-text-primary shadow-inner placeholder:text-[#71806b] focus:border-[#4a8d3f] focus:outline-none"
            placeholder="Apply a display filter… e.g. tcp, port 443, ip 10.0.0.1"
            value={rawFilter}
            onChange={(e) => {
              setRawFilter(e.target.value)
              setSelected(null)
            }}
            onKeyDown={(e) => {
              if (e.key === 'Escape') {
                setRawFilter('')
                setSelected(null)
              }
            }}
            aria-label="Display filter"
            spellCheck={false}
          />
          {rawFilter ? (
            <button className="absolute right-1 top-1/2 -translate-y-1/2 p-1 text-text-muted hover:text-text-primary" onClick={() => { setRawFilter(''); setSelected(null) }} aria-label="Clear filter" title="Clear filter (Esc)"><X className="h-3.5 w-3.5" /></button>
          ) : (
            <Check className="absolute right-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[#3d8335]" />
          )}
        </div>
        <div className="hidden items-center gap-1 2xl:flex" aria-label="Quick filters">
          {QUICK_FILTERS.map((quickFilter) => (
            <button
              key={quickFilter}
              onClick={() => { setRawFilter(quickFilter); setSelected(null) }}
              className={`h-7 rounded-[2px] border px-2 font-mono text-[10px] ${rawFilter === quickFilter ? 'border-[#76a46a] bg-[#e8f4df] text-[#376c30]' : 'border-border bg-white text-text-secondary hover:bg-bg-hover'}`}
              title={`Show ${quickFilter.toUpperCase()} packets`}
            >
              {quickFilter}
            </button>
          ))}
        </div>
      </div>

      <div className="flex min-h-0 flex-1 flex-col">
        {/* Packet table */}
        <div className="flex min-h-0 min-w-0 flex-1 flex-col">
          {/* column header */}
          <div className="flex h-6 border-b border-border bg-[#e3e5e7] px-2 text-[10px] font-semibold text-text-secondary">
            {headerCols.map((c) => (
              <div key={c.key} className={`${c.w} flex shrink-0 items-center border-r border-border px-1.5`}>
                {c.label}
              </div>
            ))}
            <div className="flex flex-1 items-center px-1.5">Info</div>
          </div>

          <div
            ref={parentRef}
            className="packet-scroll min-h-0 flex-1 overflow-x-auto overflow-y-scroll outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent"
            style={{ scrollbarGutter: 'stable' }}
            tabIndex={0}
            aria-label={`Scrollable packet list with ${data.filtered.toLocaleString()} packets`}
            onKeyDown={(e) => {
              if (e.key === 'Home') {
                e.preventDefault()
                rowVirtualizer.scrollToIndex(0, { align: 'start' })
              } else if (e.key === 'End') {
                e.preventDefault()
                rowVirtualizer.scrollToIndex(Math.max(0, data.filtered - 1), { align: 'end' })
              } else if (e.key === 'PageDown') {
                e.preventDefault()
                e.currentTarget.scrollBy({ top: e.currentTarget.clientHeight * 0.85, behavior: 'smooth' })
              } else if (e.key === 'PageUp') {
                e.preventDefault()
                e.currentTarget.scrollBy({ top: -e.currentTarget.clientHeight * 0.85, behavior: 'smooth' })
              }
            }}
          >
            <div style={{ height: rowVirtualizer.getTotalSize(), position: 'relative' }}>
              {virtualItems.map((vi) => {
                const pkt = data.get(vi.index)
                const number = pkt?.number ?? vi.index + 1
                const isSelected = selected === number
                return (
                  <div
                    key={vi.key}
                    onClick={() => pkt && setSelected(number)}
                    onKeyDown={(e) => {
                      if (pkt && (e.key === 'Enter' || e.key === ' ')) {
                        e.preventDefault()
                        setSelected(number)
                      }
                    }}
                    tabIndex={pkt ? 0 : -1}
                    role="button"
                    aria-label={pkt ? `Packet ${pkt.number}, ${pkt.protocol}, ${pkt.srcAddr} to ${pkt.dstAddr}` : undefined}
                    aria-pressed={isSelected}
                    title={pkt ? `Select packet ${pkt.number} to inspect its protocol layers and raw bytes` : undefined}
                    className={[
                      'absolute left-0 top-0 flex w-full items-center border-b border-black/[0.035] px-2 font-mono text-[11px]',
                      isSelected ? '!bg-[#2d6e9f] !text-white' : '',
                      pkt ? 'cursor-default hover:brightness-[0.96]' : 'text-text-muted'
                    ].join(' ')}
                    style={{
                      height: ROW_HEIGHT,
                      transform: `translateY(${vi.start}px)`,
                      backgroundColor: pkt ? (PROTO_ROW[pkt.protocol] ?? (vi.index % 2 ? '#f3f4f5' : '#ffffff')) : undefined
                    }}
                  >
                    {pkt ? (
                      <>
                        <div className={`w-16 shrink-0 px-1.5 text-right ${isSelected ? 'text-white' : 'text-text-muted'}`}>{pkt.number}</div>
                        <div className={`w-28 shrink-0 px-1.5 text-right ${isSelected ? 'text-white' : 'text-text-secondary'}`}>
                          {formatTimeOffset(pkt.timeOffset)}
                        </div>
                        <div className={`w-48 shrink-0 truncate px-1.5 ${isSelected ? 'text-white' : 'text-text-primary'}`}>
                          {pkt.srcAddr}
                          {pkt.srcPort ? <span className={isSelected ? 'text-white/80' : 'text-text-muted'}>:{pkt.srcPort}</span> : null}
                        </div>
                        <div className={`w-48 shrink-0 truncate px-1.5 ${isSelected ? 'text-white' : 'text-text-primary'}`}>
                          {pkt.dstAddr}
                          {pkt.dstPort ? <span className={isSelected ? 'text-white/80' : 'text-text-muted'}>:{pkt.dstPort}</span> : null}
                        </div>
                        <div
                          className="w-24 shrink-0 px-1.5 font-semibold"
                          style={{ color: isSelected ? '#ffffff' : (PROTO_COLOR[pkt.protocol] ?? '#47545e') }}
                        >
                          {pkt.protocol}
                        </div>
                        <div className={`w-20 shrink-0 px-1.5 text-right ${isSelected ? 'text-white' : 'text-text-secondary'}`}>{pkt.length}</div>
                        <div className={`flex-1 truncate px-1.5 ${isSelected ? 'text-white' : 'text-text-secondary'}`}>{pkt.info}</div>
                      </>
                    ) : (
                      <div className="px-1">…</div>
                    )}
                  </div>
                )
              })}
            </div>
          </div>

          {data.filtered === 0 && !data.loading && (
            <div className="py-8 text-center text-sm text-text-muted">
              No packets match this filter.
            </div>
          )}
        </div>

        {/* Wireshark-style lower dissection and byte panes */}
        <div className="h-[44%] min-h-[220px] shrink-0 border-t-2 border-[#aeb4b9]">
          {selected != null ? (
            <PacketDetailPane packetNumber={selected} onClose={() => setSelected(null)} />
          ) : (
            <div className="flex h-full items-center justify-center bg-white text-text-muted">
              <div className="flex items-center gap-3 rounded-[3px] border border-border-subtle bg-bg-base px-4 py-3">
                <MousePointerClick className="h-5 w-5 text-accent" />
                <div><div className="text-xs font-medium text-text-primary">Select a packet to inspect it</div><div className="mt-0.5 text-[10px]">Protocol layers and raw bytes will appear in this pane.</div></div>
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="flex h-7 shrink-0 items-center justify-between border-t border-border bg-[#e8eaec] px-2 text-[10px] text-text-secondary">
        <span>Packets: {data.total.toLocaleString()} · Displayed: {data.filtered.toLocaleString()} ({data.total ? ((data.filtered / data.total) * 100).toFixed(1) : '0.0'}%) · Visible: {firstVisible.toLocaleString()}–{lastVisible.toLocaleString()}</span>
        <div className="flex items-center gap-2">
          <span>{selected != null ? `Selected: ${selected}` : 'No packet selected'}</span>
          <div className="flex overflow-hidden rounded-[2px] border border-border bg-white">
            <button
              onClick={() => rowVirtualizer.scrollToIndex(0, { align: 'start' })}
              disabled={data.filtered === 0}
              className="flex h-5 items-center gap-1 border-r border-border px-1.5 hover:bg-bg-hover disabled:opacity-40"
              title="Jump to first packet (Home)"
            >
              <ArrowUpToLine className="h-3 w-3" /> First
            </button>
            <button
              onClick={() => rowVirtualizer.scrollToIndex(Math.max(0, data.filtered - 1), { align: 'end' })}
              disabled={data.filtered === 0}
              className="flex h-5 items-center gap-1 px-1.5 hover:bg-bg-hover disabled:opacity-40"
              title="Jump to last packet (End)"
            >
              <ArrowDownToLine className="h-3 w-3" /> Last
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
