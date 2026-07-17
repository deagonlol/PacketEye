import { useSyncExternalStore } from 'react'
import type {
  AppSettings,
  CaptureAnalysis,
  ChatMessage,
  ParseProgress
} from '@shared/types'

export type View =
  | 'home'
  | 'dashboard'
  | 'findings'
  | 'conversations'
  | 'protocols'
  | 'packets'
  | 'report'
  | 'chat'
  | 'settings'

export type CaptureStatus = 'idle' | 'parsing' | 'ready' | 'error'

export interface AppState {
  view: View
  status: CaptureStatus
  progress: ParseProgress | null
  analysis: CaptureAnalysis | null
  fileName: string | null
  errorMessage: string | null

  // Cross-navigation: when set, the Packets view scrolls to/selects this packet.
  focusPacket: number | null

  settings: AppSettings | null

  // AI report
  reportText: string
  reportStreaming: boolean
  reportRequestId: string | null
  reportError: string | null

  // Chat
  chatMessages: ChatMessage[]
  chatStreaming: boolean
  chatRequestId: string | null
}

const initial: AppState = {
  view: 'home',
  status: 'idle',
  progress: null,
  analysis: null,
  fileName: null,
  errorMessage: null,
  focusPacket: null,
  settings: null,
  reportText: '',
  reportStreaming: false,
  reportRequestId: null,
  reportError: null,
  chatMessages: [],
  chatStreaming: false,
  chatRequestId: null
}

let state: AppState = initial
const listeners = new Set<() => void>()

function emit(): void {
  for (const l of listeners) l()
}

export function setState(patch: Partial<AppState>): void {
  state = { ...state, ...patch }
  emit()
}

export function getState(): AppState {
  return state
}

function subscribe(cb: () => void): () => void {
  listeners.add(cb)
  return () => listeners.delete(cb)
}

export function useStore<T>(selector: (s: AppState) => T): T {
  return useSyncExternalStore(
    subscribe,
    () => selector(state),
    () => selector(initial)
  )
}

// ---- Actions ----

export function navigate(view: View, focusPacket?: number): void {
  setState({ view, focusPacket: focusPacket ?? null })
}

export async function openDialog(): Promise<void> {
  const path = await window.packeteye.openCaptureDialog()
  if (path) startParsing(path)
}

export function openPath(path: string): void {
  void window.packeteye.openCapturePath(path)
  startParsing(path)
}

function startParsing(path: string): void {
  const name = path.split(/[\\/]/).pop() ?? path
  setState({
    status: 'parsing',
    progress: null,
    analysis: null,
    fileName: name,
    errorMessage: null,
    view: 'dashboard',
    reportText: '',
    reportError: null,
    reportStreaming: false,
    reportRequestId: null,
    chatMessages: [],
    focusPacket: null
  })
}

export async function loadSettings(): Promise<void> {
  const settings = await window.packeteye.getSettings()
  setState({ settings })
}

export async function updateSettings(patch: Partial<AppSettings>): Promise<void> {
  const settings = await window.packeteye.setSettings(patch)
  setState({ settings })
}

// ---- AI report ----
export async function runReport(): Promise<void> {
  setState({ reportText: '', reportError: null, reportStreaming: true })
  const requestId = await window.packeteye.runReport()
  setState({ reportRequestId: requestId })
}

// ---- Chat ----
export async function sendChat(text: string): Promise<void> {
  const messages: ChatMessage[] = [
    ...state.chatMessages,
    { role: 'user', content: text },
    { role: 'assistant', content: '' }
  ]
  setState({ chatMessages: messages, chatStreaming: true })
  const requestId = await window.packeteye.runChat(
    messages.filter((m) => m.content !== '' || m.role === 'user')
  )
  setState({ chatRequestId: requestId })
}

function appendAssistant(text: string): void {
  const msgs = [...state.chatMessages]
  const last = msgs[msgs.length - 1]
  if (last && last.role === 'assistant') {
    msgs[msgs.length - 1] = { ...last, content: last.content + text }
    setState({ chatMessages: msgs })
  }
}

// ---- Wire up IPC event listeners (called once at startup) ----
export function initIpcListeners(): void {
  window.packeteye.onParseProgress((p) => setState({ progress: p }))

  window.packeteye.onCaptureReady((analysis) => {
    setState({ status: 'ready', analysis, errorMessage: null })
  })

  window.packeteye.onCaptureError((message) => {
    setState({ status: 'error', errorMessage: message })
  })

  window.packeteye.onAiChunk((chunk) => {
    const s = getState()
    if (chunk.requestId === s.reportRequestId) {
      if (chunk.type === 'delta') setState({ reportText: s.reportText + (chunk.text ?? '') })
      else if (chunk.type === 'done') setState({ reportStreaming: false })
      else if (chunk.type === 'error')
        setState({ reportStreaming: false, reportError: chunk.error ?? 'AI error' })
    } else if (chunk.requestId === s.chatRequestId) {
      if (chunk.type === 'delta') appendAssistant(chunk.text ?? '')
      else if (chunk.type === 'done') setState({ chatStreaming: false })
      else if (chunk.type === 'error') {
        appendAssistant(`\n\n_Error: ${chunk.error ?? 'AI error'}_`)
        setState({ chatStreaming: false })
      }
    }
  })

  window.packeteye.onMenuOpenCapture(() => void openDialog())
}
