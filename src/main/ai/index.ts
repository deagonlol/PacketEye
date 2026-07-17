// AI service: builds the capture digest and streams Groq responses over IPC.
// Fully implemented in the AI integration step; report/chat below are wired
// to real streaming once the digest + provider are in place.
import type { BrowserWindow } from 'electron'
import { IPC } from '../../shared/ipc'
import type { AiChunk, CaptureDigest, ChatMessage } from '../../shared/types'
import { captureService } from '../capture-service'
import { getSettings } from '../settings'
import { buildDigest } from './digest'
import { streamReport, streamChat } from './groq'

let nextRequestId = 1
const controllers = new Map<string, AbortController>()

export function getDigest(): CaptureDigest | null {
  const analysis = captureService.getAnalysis()
  if (!analysis) return null
  return buildDigest(analysis, getSettings().redactPayloads)
}

function send(win: BrowserWindow, chunk: AiChunk): void {
  win.webContents.send(IPC.aiChunk, chunk)
}

export async function runReport(win: BrowserWindow): Promise<string> {
  const requestId = String(nextRequestId++)
  const digest = getDigest()
  const settings = getSettings()
  if (!digest) {
    queueMicrotask(() =>
      send(win, { requestId, type: 'error', error: 'No capture loaded.' })
    )
    return requestId
  }
  if (!settings.groqApiKey) {
    queueMicrotask(() =>
      send(win, {
        requestId,
        type: 'error',
        error: 'No Groq API key set. Add one in Settings to run AI analysis.'
      })
    )
    return requestId
  }
  const controller = new AbortController()
  controllers.set(requestId, controller)
  void streamReport(digest, settings, controller.signal)
    .then(async (stream) => {
      for await (const delta of stream) {
        send(win, { requestId, type: 'delta', text: delta })
      }
      send(win, { requestId, type: 'done' })
    })
    .catch((err) => {
      send(win, { requestId, type: 'error', error: humanizeError(err) })
    })
    .finally(() => controllers.delete(requestId))
  return requestId
}

export async function runChat(win: BrowserWindow, messages: ChatMessage[]): Promise<string> {
  const requestId = String(nextRequestId++)
  const digest = getDigest()
  const settings = getSettings()
  if (!digest) {
    queueMicrotask(() =>
      send(win, { requestId, type: 'error', error: 'No capture loaded.' })
    )
    return requestId
  }
  if (!settings.groqApiKey) {
    queueMicrotask(() =>
      send(win, {
        requestId,
        type: 'error',
        error: 'No Groq API key set. Add one in Settings to use chat.'
      })
    )
    return requestId
  }
  const controller = new AbortController()
  controllers.set(requestId, controller)
  void streamChat(digest, messages, settings, controller.signal)
    .then(async (stream) => {
      for await (const delta of stream) {
        send(win, { requestId, type: 'delta', text: delta })
      }
      send(win, { requestId, type: 'done' })
    })
    .catch((err) => {
      send(win, { requestId, type: 'error', error: humanizeError(err) })
    })
    .finally(() => controllers.delete(requestId))
  return requestId
}

export function cancelAi(requestId: string): void {
  controllers.get(requestId)?.abort()
  controllers.delete(requestId)
}

function humanizeError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err)
  if (/401|unauthor|invalid api key/i.test(msg)) {
    return 'Groq rejected the API key. Check it in Settings.'
  }
  if (/429|rate limit/i.test(msg)) {
    return 'Groq rate limit reached. Wait a moment and try again.'
  }
  if (/aborted|cancel/i.test(msg)) {
    return 'Request cancelled.'
  }
  return `AI request failed: ${msg}`
}
