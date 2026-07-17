import {
  Activity,
  FileBarChart,
  FolderOpen,
  Home,
  Layers3,
  List,
  MessageSquareText,
  Network,
  Settings,
  ShieldAlert
} from 'lucide-react'
import { navigate, openDialog, useStore, type View } from '../store'
import { getScanHealth } from '../lib/format'

interface NavItem {
  view: View
  label: string
  icon: typeof Home
}

const NAV_ITEMS: NavItem[] = [
  { view: 'dashboard', label: 'Overview', icon: Activity },
  { view: 'packets', label: 'Packets', icon: List },
  { view: 'conversations', label: 'Conversations', icon: Network },
  { view: 'protocols', label: 'Protocols', icon: Layers3 },
  { view: 'findings', label: 'Findings', icon: ShieldAlert },
  { view: 'report', label: 'Report', icon: FileBarChart },
  { view: 'chat', label: 'Assistant', icon: MessageSquareText }
]

export function Sidebar(): JSX.Element {
  const view = useStore((s) => s.view)
  const status = useStore((s) => s.status)
  const analysis = useStore((s) => s.analysis)
  const fileName = useStore((s) => s.fileName)
  const hasCapture = status === 'ready'
  const health = analysis ? getScanHealth(analysis.findings) : null
  const packetCount = analysis?.stats.packetCount ?? 0

  return (
    <header className="relative z-20 shrink-0 border-b border-border bg-bg-panel">
      <div className="titlebar-drag relative flex h-8 items-center justify-center border-b border-border-subtle bg-[#e8eaec] px-20">
        <div className="truncate text-[11px] font-medium text-text-secondary">
          {fileName ? `${fileName} — PacketEye` : 'PacketEye Network Analyzer'}
        </div>
      </div>

      <div className="flex h-11 items-center gap-1 px-2">
        <button
          className="titlebar-nodrag flex h-8 items-center gap-2 rounded-[3px] border border-border bg-white px-2.5 text-xs font-medium text-text-primary hover:bg-bg-hover"
          onClick={() => void openDialog()}
          title="Open capture file (⌘O)"
        >
          <FolderOpen className="h-4 w-4 text-accent" />
          Open
        </button>

        <button
          className="titlebar-nodrag ml-1 flex h-8 w-8 items-center justify-center rounded-[3px] text-text-secondary hover:bg-bg-hover hover:text-text-primary"
          onClick={() => navigate('home')}
          title="Welcome screen"
          aria-label="Welcome screen"
        >
          <Home className="h-4 w-4" />
        </button>

        <div className="mx-1 h-6 w-px bg-border" />

        <nav className="titlebar-nodrag flex min-w-0 flex-1 items-center gap-0.5 overflow-x-auto" aria-label="Analysis views">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon
            const active = view === item.view
            return (
              <button
                key={item.view}
                disabled={!hasCapture}
                onClick={() => navigate(item.view)}
                title={hasCapture ? item.label : `Open a capture to access ${item.label.toLowerCase()}`}
                className={[
                  'flex h-8 shrink-0 items-center gap-1.5 rounded-[3px] px-2 text-[11px] transition-colors',
                  active
                    ? 'bg-[#cfe3f4] font-semibold text-[#124f80] shadow-[inset_0_0_0_1px_#8eb6d6]'
                    : 'text-text-secondary hover:bg-bg-hover hover:text-text-primary',
                  !hasCapture ? 'opacity-35' : ''
                ].join(' ')}
              >
                <Icon className="h-3.5 w-3.5" />
                {item.label}
              </button>
            )
          })}
        </nav>

        <div className="mx-1 h-6 w-px bg-border" />
        {hasCapture && health ? (
          <button
            onClick={() => navigate(health.findingCount ? 'findings' : 'dashboard')}
            className="titlebar-nodrag flex h-8 items-center gap-2 rounded-[3px] border px-2 text-[10px] font-medium hover:brightness-[0.97]"
            style={{ color: health.color, backgroundColor: health.surface, borderColor: health.border }}
            title={`${health.description} ${packetCount.toLocaleString()} packets analyzed.`}
          >
            <span className="h-2.5 w-2.5 rounded-full shadow-[inset_0_0_0_1px_rgba(0,0,0,0.12)]" style={{ backgroundColor: health.color }} />
            <span>{health.label}</span>
            <span className="hidden text-text-muted xl:inline">· {packetCount.toLocaleString()} packets</span>
          </button>
        ) : (
          <div className="flex items-center gap-1.5 px-1 text-[10px] text-text-muted">
            <span className={`h-2 w-2 rounded-full ${status === 'parsing' ? 'bg-[#d99416]' : 'bg-[#929aa1]'}`} />
            <span className="hidden lg:inline">{status === 'parsing' ? 'Analyzing…' : 'No capture'}</span>
          </div>
        )}
        <button
          onClick={() => navigate('settings')}
          className={`titlebar-nodrag flex h-8 w-8 items-center justify-center rounded-[3px] ${view === 'settings' ? 'bg-[#cfe3f4] text-accent' : 'text-text-secondary hover:bg-bg-hover'}`}
          title="Preferences"
          aria-label="Preferences"
        >
          <Settings className="h-4 w-4" />
        </button>
      </div>
    </header>
  )
}
