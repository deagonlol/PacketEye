// Generates a browser-preview fixture (analysis + packets + details + digest)
// from the synthetic capture, so the renderer UI can be developed against real
// data without launching Electron. Output: src/renderer/src/lib/sample-analysis.json
import { writeFileSync, mkdirSync } from 'fs'
import { join } from 'path'
import { buildMixedCapture } from './scenarios'
import { analyzeCapture } from '../src/shared/pcap/analyze-capture'
import { dissect, buildHex } from '../src/shared/pcap/dissect'
import { buildDigest } from '../src/main/ai/digest'
import type { PacketDetail } from '../src/shared/types'

const buf = buildMixedCapture().toBuffer()
const { analysis, packetSummaries, linkType } = analyzeCapture(buf, {
  fileName: 'mixed-threats.pcap'
})

const details: Record<number, PacketDetail> = {}
for (const s of packetSummaries) {
  const frame = buf.subarray(s.fileOffset, s.fileOffset + s.rawLength)
  const d = dissect(frame, linkType, true)
  const { hex, ascii } = buildHex(frame)
  details[s.number] = {
    summary: s,
    layers: d.layers.length ? d.layers : [{ name: 'Frame', summary: '', fields: [] }],
    hex,
    ascii
  }
}

const digest = buildDigest(analysis, false)
const out = { analysis, packets: packetSummaries, details, digest }
const dir = join(process.cwd(), 'src/renderer/src/lib')
mkdirSync(dir, { recursive: true })
writeFileSync(join(dir, 'sample-analysis.json'), JSON.stringify(out))
console.log(
  `fixture: ${packetSummaries.length} packets, ${analysis.findings.length} findings, ${analysis.flows.length} flows`
)
