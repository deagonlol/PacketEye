import { contextBridge, ipcRenderer } from 'electron'
import { IPC } from '../shared/ipc'
import type {
  AppSettings,
  CaptureAnalysis,
  CaptureDigest,
  ChatMessage,
  PacketDetail,
  PacketPage,
  PacketQuery,
  ParseProgress,
  AiChunk
} from '../shared/types'

const api = {
  // ---- Capture ----
  openCaptureDialog: (): Promise<string | null> => ipcRenderer.invoke(IPC.openCaptureDialog),
  openCapturePath: (path: string): Promise<void> => ipcRenderer.invoke(IPC.openCapturePath, path),
  getPacketPage: (query: PacketQuery): Promise<PacketPage> =>
    ipcRenderer.invoke(IPC.getPacketPage, query),
  getPacketDetail: (packetNumber: number): Promise<PacketDetail | null> =>
    ipcRenderer.invoke(IPC.getPacketDetail, packetNumber),
  getRecentFiles: (): Promise<string[]> => ipcRenderer.invoke(IPC.getRecentFiles),

  // ---- Settings ----
  getSettings: (): Promise<AppSettings> => ipcRenderer.invoke(IPC.getSettings),
  setSettings: (settings: Partial<AppSettings>): Promise<AppSettings> =>
    ipcRenderer.invoke(IPC.setSettings, settings),

  // ---- AI ----
  getDigest: (): Promise<CaptureDigest | null> => ipcRenderer.invoke(IPC.getDigest),
  runReport: (): Promise<string> => ipcRenderer.invoke(IPC.runReport),
  runChat: (messages: ChatMessage[]): Promise<string> =>
    ipcRenderer.invoke(IPC.runChat, messages),
  cancelAi: (requestId: string): Promise<void> => ipcRenderer.invoke(IPC.cancelAi, requestId),

  // ---- Report export ----
  exportReport: (markdown: string): Promise<string | null> =>
    ipcRenderer.invoke(IPC.exportReport, markdown),

  // ---- Events (main -> renderer) ----
  onParseProgress: (cb: (p: ParseProgress) => void): (() => void) => {
    const listener = (_e: unknown, p: ParseProgress): void => cb(p)
    ipcRenderer.on(IPC.parseProgress, listener)
    return () => ipcRenderer.removeListener(IPC.parseProgress, listener)
  },
  onCaptureReady: (cb: (a: CaptureAnalysis) => void): (() => void) => {
    const listener = (_e: unknown, a: CaptureAnalysis): void => cb(a)
    ipcRenderer.on(IPC.captureReady, listener)
    return () => ipcRenderer.removeListener(IPC.captureReady, listener)
  },
  onCaptureError: (cb: (msg: string) => void): (() => void) => {
    const listener = (_e: unknown, msg: string): void => cb(msg)
    ipcRenderer.on(IPC.captureError, listener)
    return () => ipcRenderer.removeListener(IPC.captureError, listener)
  },
  onAiChunk: (cb: (chunk: AiChunk) => void): (() => void) => {
    const listener = (_e: unknown, chunk: AiChunk): void => cb(chunk)
    ipcRenderer.on(IPC.aiChunk, listener)
    return () => ipcRenderer.removeListener(IPC.aiChunk, listener)
  },
  onMenuOpenCapture: (cb: () => void): (() => void) => {
    const listener = (): void => cb()
    ipcRenderer.on(IPC.menuOpenCapture, listener)
    return () => ipcRenderer.removeListener(IPC.menuOpenCapture, listener)
  }
}

export type PacketEyeApi = typeof api

if (process.contextIsolated) {
  try {
    contextBridge.exposeInMainWorld('packeteye', api)
  } catch (error) {
    console.error(error)
  }
} else {
  // @ts-ignore fallback when context isolation is disabled
  window.packeteye = api
}
