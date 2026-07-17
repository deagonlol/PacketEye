import { Worker } from 'worker_threads'
import { join } from 'path'
import { basename } from 'path'
import type { BrowserWindow } from 'electron'
import { IPC } from '../shared/ipc'
import type {
  CaptureAnalysis,
  PacketDetail,
  PacketPage,
  PacketQuery
} from '../shared/types'
import type { MainToWorker, WorkerToMain } from './worker/protocol'
import { addRecentFile } from './settings'

/**
 * Owns the parser worker lifecycle and brokers packet queries. A fresh worker
 * is spawned per capture so memory is fully released when a new file opens.
 */
class CaptureService {
  private worker: Worker | null = null
  private win: BrowserWindow | null = null
  private analysis: CaptureAnalysis | null = null
  private currentPath: string | null = null
  private reqId = 0
  private pending = new Map<
    number,
    { resolve: (v: unknown) => void; reject: (e: unknown) => void }
  >()

  attachWindow(win: BrowserWindow): void {
    this.win = win
  }

  getAnalysis(): CaptureAnalysis | null {
    return this.analysis
  }

  getCurrentPath(): string | null {
    return this.currentPath
  }

  private workerPath(): string {
    // parser-worker.js is emitted next to the main index.js by electron-vite.
    return join(__dirname, 'parser-worker.js')
  }

  open(path: string): void {
    this.dispose()
    this.analysis = null
    this.currentPath = path
    addRecentFile(path)

    const worker = new Worker(this.workerPath())
    this.worker = worker

    worker.on('message', (msg: WorkerToMain) => this.onWorkerMessage(msg))
    worker.on('error', (err) => {
      this.win?.webContents.send(IPC.captureError, String(err?.message ?? err))
    })
    worker.on('exit', (code) => {
      if (code !== 0 && !this.analysis) {
        this.win?.webContents.send(
          IPC.captureError,
          `Parser worker stopped unexpectedly (code ${code}).`
        )
      }
    })

    this.post({ type: 'parse', path })
  }

  private post(msg: MainToWorker): void {
    this.worker?.postMessage(msg)
  }

  private onWorkerMessage(msg: WorkerToMain): void {
    switch (msg.type) {
      case 'progress':
        this.win?.webContents.send(IPC.parseProgress, msg.progress)
        break
      case 'ready':
        this.analysis = msg.analysis
        this.win?.webContents.send(IPC.captureReady, msg.analysis)
        break
      case 'error':
        this.win?.webContents.send(IPC.captureError, msg.message)
        break
      case 'page':
      case 'detail': {
        const p = this.pending.get(msg.requestId)
        if (p) {
          this.pending.delete(msg.requestId)
          p.resolve(msg.type === 'page' ? msg.page : msg.detail)
        }
        break
      }
    }
  }

  getPacketPage(query: PacketQuery): Promise<PacketPage> {
    if (!this.worker) {
      return Promise.resolve({ total: 0, filtered: 0, packets: [] })
    }
    const requestId = ++this.reqId
    return new Promise((resolve, reject) => {
      this.pending.set(requestId, { resolve: resolve as (v: unknown) => void, reject })
      this.post({ type: 'getPage', requestId, query })
    })
  }

  getPacketDetail(packetNumber: number): Promise<PacketDetail | null> {
    if (!this.worker) return Promise.resolve(null)
    const requestId = ++this.reqId
    return new Promise((resolve, reject) => {
      this.pending.set(requestId, { resolve: resolve as (v: unknown) => void, reject })
      this.post({ type: 'getDetail', requestId, packetNumber })
    })
  }

  fileName(): string {
    return this.currentPath ? basename(this.currentPath) : 'capture'
  }

  dispose(): void {
    if (this.worker) {
      this.worker.terminate()
      this.worker = null
    }
    for (const [, p] of this.pending) p.reject(new Error('cancelled'))
    this.pending.clear()
  }
}

export const captureService = new CaptureService()
