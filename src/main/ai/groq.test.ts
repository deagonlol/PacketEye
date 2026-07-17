import { describe, it, expect, vi, beforeEach } from 'vitest'
import type { AppSettings, CaptureDigest } from '../../shared/types'

// Capture the arguments streamText is called with.
const streamTextCalls: unknown[] = []

vi.mock('ai', () => ({
  streamText: (opts: unknown) => {
    streamTextCalls.push(opts)
    return {
      textStream: (async function* () {
        yield 'hello'
      })()
    }
  }
}))

vi.mock('@ai-sdk/groq', () => ({
  createGroq: (cfg: { apiKey: string }) => {
    return (modelId: string) => ({ modelId, apiKey: cfg.apiKey })
  }
}))

import { streamReport, streamChat } from './groq'

const settings: AppSettings = {
  groqApiKey: 'gsk_test',
  model: 'llama-3.1-8b-instant',
  redactPayloads: false
}

const digest: CaptureDigest = {
  meta: {
    fileName: 'x.pcap',
    packetCount: 10,
    durationSec: 1,
    startTime: '2026-01-01T00:00:00.000Z',
    hostCount: 2,
    totalBytes: 500
  },
  protocolHierarchy: [{ protocol: 'DNS', packets: 5, bytes: 200 }],
  topTalkers: [{ addr: '10.0.0.1', packets: 5, bytes: 200 }],
  topConversations: [],
  dns: [],
  http: [],
  tls: [],
  findings: [
    {
      severity: 'critical',
      category: 'credentials',
      title: 'Cleartext creds',
      description: 'x',
      affectedHosts: ['10.0.0.1']
    }
  ]
}

describe('groq streaming module', () => {
  beforeEach(() => {
    streamTextCalls.length = 0
  })

  it('streamReport passes the digest, model, and a security-analyst system prompt', async () => {
    const stream = await streamReport(digest, settings, new AbortController().signal)
    const opts = streamTextCalls[0] as {
      model: { modelId: string; apiKey: string }
      system: string
      prompt: string
      abortSignal: AbortSignal
    }
    expect(opts.model.modelId).toBe('llama-3.1-8b-instant')
    expect(opts.model.apiKey).toBe('gsk_test')
    expect(opts.system).toMatch(/security analyst/i)
    expect(opts.prompt).toContain('Cleartext creds') // digest JSON embedded
    expect(opts.abortSignal).toBeInstanceOf(AbortSignal)

    // Returned value is an async iterable of text deltas.
    let out = ''
    for await (const d of stream) out += d
    expect(out).toBe('hello')
  })

  it('streamChat forwards prior messages and digest context', async () => {
    await streamChat(
      digest,
      [{ role: 'user', content: 'why flagged?' }],
      settings,
      new AbortController().signal
    )
    const opts = streamTextCalls[0] as {
      system: string
      messages: { role: string; content: string }[]
    }
    expect(opts.system).toContain('x.pcap') // digest embedded in system context
    expect(opts.messages).toEqual([{ role: 'user', content: 'why flagged?' }])
  })
})
