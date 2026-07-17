// Pure capture-analysis core: given the raw file bytes, produce the full
// CaptureAnalysis plus per-packet summaries. Shared by the parser worker and by
// tests so both exercise identical logic.
import type { CaptureAnalysis, Flow, PacketSummary } from '../types'
import { iterateCapture } from './parse'
import { detectFormat, linkTypeName } from './reader'
import { dissect } from './dissect'
import { FlowTracker } from './flows'
import { Analyzer } from './analyze'
import { runDetection } from '../detect'
import { toDetectPacket, type DetectPacket } from '../detect/context'

export interface AnalyzeResult {
  analysis: CaptureAnalysis
  packetSummaries: PacketSummary[]
  linkType: number
}

export interface AnalyzeOptions {
  fileName: string
  onProgress?: (packets: number, bytesRead: number, totalBytes: number) => void
  progressEvery?: number
}

export function analyzeCapture(buf: Buffer, opts: AnalyzeOptions): AnalyzeResult {
  const info = detectFormat(buf)
  if (!info) {
    throw new Error('This file is not a recognized packet capture (.pcap or .pcapng).')
  }

  const flowTracker = new FlowTracker()
  const analyzer = new Analyzer()
  const detectPackets: DetectPacket[] = []
  const packetSummaries: PacketSummary[] = []

  const progressEvery = opts.progressEvery ?? 5000
  let number = 0
  let firstTs = 0
  let linkType = 1

  const iter = iterateCapture(buf)
  let result = iter.next()
  while (!result.done) {
    const raw = result.value
    number++
    linkType = raw.linkType
    const frame = buf.subarray(raw.frameOffset, raw.frameOffset + raw.capLen)
    const d = dissect(frame, raw.linkType, false)

    if (number === 1) firstTs = raw.tsSec
    const timeOffset = raw.tsSec > 0 && firstTs > 0 ? raw.tsSec - firstTs : 0
    const length = raw.origLen || raw.capLen

    const summary: PacketSummary = {
      number,
      tsSec: raw.tsSec,
      timeOffset,
      srcAddr: d.srcAddr,
      dstAddr: d.dstAddr,
      srcPort: d.srcPort,
      dstPort: d.dstPort,
      protocol: d.protocol,
      length,
      info: d.info,
      fileOffset: raw.frameOffset,
      rawLength: raw.capLen
    }
    packetSummaries.push(summary)
    flowTracker.add(d, number, raw.tsSec, length)
    analyzer.add(d, raw.tsSec, length, number)
    detectPackets.push(toDetectPacket(d, number, raw.tsSec, length))

    if (opts.onProgress && number % progressEvery === 0) {
      opts.onProgress(number, raw.frameOffset + raw.capLen, buf.length)
    }
    result = iter.next()
  }

  const flows = flowTracker.getFlows()
  const findings = runDetection({ packets: detectPackets, flows, analyzer })

  const stats = analyzer.finalize({
    fileName: opts.fileName,
    fileSizeBytes: buf.length,
    format: info.format,
    linkType: linkTypeName(linkType)
  })

  const publicFlows: Flow[] = flows.map(({ timestamps, ...f }) => {
    void timestamps
    return f
  })

  const analysis: CaptureAnalysis = {
    stats,
    flows: publicFlows,
    findings,
    summaries: analyzer.getSummaries()
  }

  return { analysis, packetSummaries, linkType }
}
