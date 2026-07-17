// Browser-preview mock of the preload API. Installed only when the app runs
// outside Electron (i.e. `window.packeteye` is absent), so the renderer UI can
// be developed and previewed in a plain browser via `vite`. Serves a fixture
// captured from the synthetic sample. Never used inside the packaged app.
import type { PacketEyeApi } from '../../../preload'
import type {
  AppSettings,
  CaptureAnalysis,
  CaptureDigest,
  PacketDetail,
  PacketSummary
} from '@shared/types'
import { matchesFilter } from '@shared/pcap/filter'
import fixture from './sample-analysis.json'

interface Fixture {
  analysis: CaptureAnalysis
  packets: PacketSummary[]
  details: Record<number, PacketDetail>
  digest: CaptureDigest
}

let settings: AppSettings = {
  groqApiKey: '',
  model: 'llama-3.1-8b-instant',
  redactPayloads: false
}

export function installDevMock(): void {
  if (typeof window === 'undefined' || (window as unknown as { packeteye?: unknown }).packeteye) {
    return
  }
  const f = fixture as unknown as Fixture
  const noopUnsub = (): void => {}
  let readyCb: ((a: CaptureAnalysis) => void) | null = null
  let aiCb: ((c: { requestId: string; type: 'delta' | 'done' | 'error'; text?: string; error?: string }) => void) | null =
    null
  let aiReq = 0

  // Stream a canned response word-by-word so the renderer AI pipeline (store
  // handlers, markdown render, streaming cursor) can be exercised without Groq.
  function streamCanned(text: string): string {
    const requestId = String(++aiReq)
    const words = text.split(/(\s+)/)
    let i = 0
    const timer = setInterval(() => {
      if (!aiCb) return
      if (i >= words.length) {
        aiCb({ requestId, type: 'done' })
        clearInterval(timer)
        return
      }
      aiCb({ requestId, type: 'delta', text: words[i++] })
    }, 15)
    return requestId
  }

  const CANNED_REPORT = `## Executive Summary
This capture is **highly concerning**. It contains cleartext credentials, an active reconnaissance scan, and signs of an on-path (man-in-the-middle) attack. Treat the affected hosts as potentially compromised.

## Threat Assessment
### ARP spoofing (Critical)
\`192.168.1.1\` is claimed by two MAC addresses, the signature of ARP cache poisoning used to intercept traffic (MITRE T1557.002).

### Cleartext credentials (Critical)
Telnet and HTTP Basic Auth exposed logins in plaintext, readable by anyone on the path.

### DNS tunneling to evil-c2.com (High)
Dozens of long, high-entropy subdomains indicate data exfiltration or C2 over DNS.

## Remediation Plan
1. Isolate \`192.168.1.66\` and the ARP-spoofing host immediately.
2. Rotate all credentials seen in cleartext.
3. Block \`evil-c2.com\` and inspect \`192.168.1.100\`.

## Hardening Recommendations
Replace Telnet with SSH, enforce HTTPS, enable Dynamic ARP Inspection and DHCP snooping, and restrict outbound DNS to approved resolvers.`

  const searchOf = (p: PacketSummary): string =>
    [p.number, p.srcAddr, p.dstAddr, p.srcPort ?? '', p.dstPort ?? '', p.protocol, p.info]
      .join(' ')
      .toLowerCase()

  const api: PacketEyeApi = {
    openCaptureDialog: async () => {
      // Simulate loading the fixture capture.
      setTimeout(() => readyCb?.(f.analysis), 300)
      return 'mixed-threats.pcap'
    },
    openCapturePath: async () => {
      setTimeout(() => readyCb?.(f.analysis), 300)
    },
    getPacketPage: async (query) => {
      const filter = (query.filter ?? '').trim()
      const list = filter
        ? f.packets.filter((p) => matchesFilter(p, searchOf(p), filter))
        : f.packets
      return {
        total: f.packets.length,
        filtered: list.length,
        packets: list.slice(query.offset, query.offset + query.limit)
      }
    },
    getPacketDetail: async (n) => f.details[n] ?? null,
    getRecentFiles: async () => ['mixed-threats.pcap'],
    getSettings: async () => settings,
    setSettings: async (patch) => {
      settings = { ...settings, ...patch }
      return settings
    },
    getDigest: async () => f.digest,
    runReport: async () => streamCanned(CANNED_REPORT),
    runChat: async () =>
      streamCanned(
        'Based on the capture, the most urgent issue is the **ARP spoofing** on `192.168.1.1` — it enables interception of all traffic. Fix that first, then rotate the credentials exposed over Telnet and HTTP Basic Auth.'
      ),
    cancelAi: async () => {},
    exportReport: async () => '/Users/preview/mixed-threats-report.md',
    onParseProgress: () => noopUnsub,
    onCaptureReady: (cb) => {
      readyCb = cb
      return () => {
        readyCb = null
      }
    },
    onCaptureError: () => noopUnsub,
    onAiChunk: (cb) => {
      aiCb = cb
      return () => {
        aiCb = null
      }
    },
    onMenuOpenCapture: () => noopUnsub
  }
  ;(window as unknown as { packeteye: PacketEyeApi }).packeteye = api
  console.info('[PacketEye] dev browser mock installed (fixture loaded)')
}
