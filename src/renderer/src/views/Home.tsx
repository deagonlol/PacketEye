import { useEffect, useState } from 'react'
import { FileSearch, FolderOpen, LockKeyhole, Network, ShieldCheck } from 'lucide-react'
import { openDialog, openPath, useStore } from '../store'

export function Home(): JSX.Element {
  const status = useStore((s) => s.status)
  const errorMessage = useStore((s) => s.errorMessage)
  const [dragging, setDragging] = useState(false)
  const [recent, setRecent] = useState<string[]>([])

  useEffect(() => {
    void window.packeteye.getRecentFiles().then(setRecent)
  }, [status])

  return (
    <div
      className="flex h-full flex-col overflow-auto bg-bg-base"
      onDragEnter={() => setDragging(true)}
      onDragLeave={(e) => {
        if (e.currentTarget === e.target) setDragging(false)
      }}
      onDrop={() => setDragging(false)}
    >
      <div className="border-b border-border bg-white px-6 py-4">
        <h1 className="text-xl font-semibold text-text-primary">Welcome to PacketEye</h1>
        <p className="mt-1 text-xs text-text-secondary">Open a capture file to inspect packets, conversations, protocols, and security findings.</p>
      </div>

      <div className="mx-auto grid w-full max-w-5xl flex-1 grid-cols-1 gap-8 px-8 py-8 md:grid-cols-[1fr_1.25fr]">
        <section>
          <h2 className="mb-2 border-b border-border pb-1 text-sm font-semibold text-text-primary">Capture</h2>
          <button
            onClick={() => void openDialog()}
            className={[
              'flex w-full items-center gap-3 rounded-[3px] border bg-white px-4 py-4 text-left transition-colors',
              dragging ? 'border-accent bg-[#e8f4df]' : 'border-border hover:bg-bg-hover'
            ].join(' ')}
          >
            <FolderOpen className="h-7 w-7 text-accent" />
            <span>
              <span className="block text-sm font-semibold text-accent">Open a capture file</span>
              <span className="mt-0.5 block text-[11px] text-text-muted">PCAP, PCAPNG, or CAP · You can also drop a file here</span>
            </span>
          </button>

          {errorMessage && status === 'error' && (
            <div className="mt-3 rounded-[3px] border border-sev-critical/40 bg-red-50 px-3 py-2 text-xs text-sev-critical">
              {errorMessage}
            </div>
          )}

          <div className="mt-7">
            <h2 className="mb-2 border-b border-border pb-1 text-sm font-semibold text-text-primary">Analysis workspace</h2>
            <div className="space-y-3 px-1 py-2 text-xs text-text-secondary">
              <Feature icon={<Network />} title="Inspect traffic" text="Browse packet details, protocol layers, raw bytes, and endpoint conversations." />
              <Feature icon={<ShieldCheck />} title="Review findings" text="Trace detected risks back to the exact packets that triggered them." />
              <Feature icon={<LockKeyhole />} title="Local-first" text="Capture parsing and deterministic detection stay on this device." />
            </div>
          </div>
        </section>

        <section>
          <h2 className="mb-2 border-b border-border pb-1 text-sm font-semibold text-text-primary">Recent capture files</h2>
          <div className="overflow-hidden rounded-[3px] border border-border bg-white">
            {recent.length > 0 ? (
              recent.slice(0, 8).map((path, index) => {
                const name = path.split(/[\\/]/).pop() ?? path
                return (
                  <button
                    key={path}
                    onClick={() => openPath(path)}
                    className={`flex w-full items-center gap-3 px-3 py-2.5 text-left hover:bg-bg-hover ${index ? 'border-t border-border-subtle' : ''}`}
                  >
                    <FileSearch className="h-4 w-4 shrink-0 text-accent" />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-xs font-medium text-text-primary">{name}</span>
                      <span className="mt-0.5 block truncate text-[10px] text-text-muted">{path}</span>
                    </span>
                  </button>
                )
              })
            ) : (
              <div className="flex min-h-44 flex-col items-center justify-center px-6 text-center">
                <FileSearch className="h-8 w-8 text-text-muted" />
                <p className="mt-3 text-xs font-medium text-text-secondary">No recent capture files</p>
                <p className="mt-1 text-[11px] text-text-muted">Files you open will appear here.</p>
              </div>
            )}
          </div>
        </section>
      </div>

      <div className="border-t border-border bg-[#e8eaec] px-3 py-1 text-[10px] text-text-muted">
        Ready · Default profile
      </div>
    </div>
  )
}

function Feature({ icon, title, text }: { icon: JSX.Element; title: string; text: string }): JSX.Element {
  return (
    <div className="flex gap-3">
      <div className="mt-0.5 text-accent [&>svg]:h-4 [&>svg]:w-4">{icon}</div>
      <div><div className="font-medium text-text-primary">{title}</div><p className="mt-0.5 leading-4">{text}</p></div>
    </div>
  )
}
