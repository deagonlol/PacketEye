import { readFile } from 'fs/promises'
import { basename } from 'path'
import type { WorkerToMain } from './protocol'
import type { PacketStore } from './packet-store'
import { detectFormat } from '../../shared/pcap/reader'
import { analyzeCapture } from '../../shared/pcap/analyze-capture'

export async function runParse(
  path: string,
  store: PacketStore,
  post: (msg: WorkerToMain) => void
): Promise<void> {
  store.reset(path)

  let buf: Buffer
  try {
    buf = await readFile(path)
  } catch (err) {
    post({ type: 'error', message: `Could not read file: ${(err as Error).message}` })
    return
  }

  if (!detectFormat(buf)) {
    post({
      type: 'error',
      message: 'This file is not a recognized packet capture (.pcap or .pcapng).'
    })
    return
  }

  post({
    type: 'progress',
    progress: { phase: 'reading', bytesRead: 0, totalBytes: buf.length, packets: 0 }
  })

  let result
  try {
    result = analyzeCapture(buf, {
      fileName: basename(path),
      onProgress: (packets, bytesRead, totalBytes) =>
        post({ type: 'progress', progress: { phase: 'reading', bytesRead, totalBytes, packets } })
    })
  } catch (err) {
    post({ type: 'error', message: err instanceof Error ? err.message : String(err) })
    return
  }

  post({
    type: 'progress',
    progress: {
      phase: 'analyzing',
      bytesRead: buf.length,
      totalBytes: buf.length,
      packets: result.packetSummaries.length
    }
  })

  for (const summary of result.packetSummaries) store.addPacket(summary)
  store.setBuffer(buf, result.linkType)

  post({
    type: 'progress',
    progress: {
      phase: 'done',
      bytesRead: buf.length,
      totalBytes: buf.length,
      packets: result.packetSummaries.length
    }
  })
  post({ type: 'ready', analysis: result.analysis })
}
