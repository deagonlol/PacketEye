import type { PacketDetail, PacketPage, PacketQuery, PacketSummary } from '../../shared/types'
import { dissect, buildHex } from '../../shared/pcap/dissect'
import { matchesFilter } from '../../shared/pcap/filter'

interface StoredPacket {
  summary: PacketSummary
  search: string // lowercased haystack for text filtering
}

/**
 * Holds the parsed packet index plus the raw capture buffer so packet detail /
 * hex can be produced lazily by re-dissecting a single frame on demand. Kept in
 * the worker thread; only paged summaries cross the IPC boundary.
 */
export class PacketStore {
  filePath = ''
  private buf: Buffer = Buffer.alloc(0)
  private linkType = 1
  private records: StoredPacket[] = []

  reset(filePath: string): void {
    this.filePath = filePath
    this.buf = Buffer.alloc(0)
    this.records = []
  }

  setBuffer(buf: Buffer, linkType: number): void {
    this.buf = buf
    this.linkType = linkType
  }

  addPacket(summary: PacketSummary): void {
    const search = [
      summary.number,
      summary.srcAddr,
      summary.dstAddr,
      summary.srcPort ?? '',
      summary.dstPort ?? '',
      summary.protocol,
      summary.info
    ]
      .join(' ')
      .toLowerCase()
    this.records.push({ summary, search })
  }

  get count(): number {
    return this.records.length
  }

  getPage(query: PacketQuery): PacketPage {
    const filter = (query.filter ?? '').trim()
    let list: StoredPacket[]
    if (!filter) {
      list = this.records
    } else {
      list = this.records.filter((r) => matchesFilter(r.summary, r.search, filter))
    }
    const total = this.records.length
    const filtered = list.length
    const start = Math.max(0, query.offset)
    const packets = list.slice(start, start + query.limit).map((r) => r.summary)
    return { total, filtered, packets }
  }

  async getDetail(packetNumber: number): Promise<PacketDetail | null> {
    const rec = this.records[packetNumber - 1]
    if (!rec) return null
    const { fileOffset, rawLength } = rec.summary
    const frame = this.buf.subarray(fileOffset, fileOffset + rawLength)
    const d = dissect(frame, this.linkType, true)
    const { hex, ascii } = buildHex(frame)
    return {
      summary: rec.summary,
      layers: d.layers.length ? d.layers : [{ name: 'Frame', summary: '', fields: [] }],
      hex,
      ascii
    }
  }
}
