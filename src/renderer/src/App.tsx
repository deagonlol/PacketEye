import { useEffect } from 'react'
import { Sidebar } from './components/Sidebar'
import { useStore, openPath } from './store'
import { Home } from './views/Home'
import { Dashboard } from './views/Dashboard'
import { Findings } from './views/Findings'
import { Conversations } from './views/Conversations'
import { Protocols } from './views/Protocols'
import { Packets } from './views/Packets'
import { Report } from './views/Report'
import { Chat } from './views/Chat'
import { SettingsView } from './views/Settings'
import { ParsingOverlay } from './views/ParsingOverlay'

function CurrentView(): JSX.Element {
  const view = useStore((s) => s.view)
  const status = useStore((s) => s.status)
  const analysis = useStore((s) => s.analysis)

  // Settings is always reachable. Otherwise, before a capture is successfully
  // loaded (idle, or a parse error with nothing to show) fall back to Home,
  // which surfaces the error message and the open/drop affordances.
  if (view === 'settings') return <SettingsView />
  // Before a capture is successfully loaded (idle, or a parse error with nothing
  // to show) fall back to Home, which surfaces the error and open/drop controls.
  if (status === 'idle' || (status === 'error' && !analysis)) {
    return <Home />
  }

  switch (view) {
    case 'home':
      return <Home />
    case 'dashboard':
      return <Dashboard />
    case 'findings':
      return <Findings />
    case 'conversations':
      return <Conversations />
    case 'protocols':
      return <Protocols />
    case 'packets':
      return <Packets />
    case 'report':
      return <Report />
    case 'chat':
      return <Chat />
    default:
      return <Dashboard />
  }
}

export default function App(): JSX.Element {
  const status = useStore((s) => s.status)

  // Handle files dropped onto the window.
  useEffect(() => {
    function onDrop(e: DragEvent): void {
      e.preventDefault()
      const file = e.dataTransfer?.files?.[0]
      // Electron exposes the absolute path on the File object.
      const path = (file as unknown as { path?: string })?.path
      if (path) openPath(path)
    }
    function onDragOver(e: DragEvent): void {
      e.preventDefault()
    }
    window.addEventListener('drop', onDrop)
    window.addEventListener('dragover', onDragOver)
    return () => {
      window.removeEventListener('drop', onDrop)
      window.removeEventListener('dragover', onDragOver)
    }
  }, [])

  return (
    <div className="relative flex h-screen w-screen flex-col overflow-hidden bg-bg-base">
      <Sidebar />
      <main className="relative z-10 flex min-w-0 flex-1 flex-col overflow-hidden">
        <CurrentView />
        {status === 'parsing' && <ParsingOverlay />}
      </main>
    </div>
  )
}
