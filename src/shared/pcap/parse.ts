// Iterate a capture buffer and yield one record per packet. Supports classic
// pcap (LE/BE, us/ns timestamps) and pcapng (SHB/IDB/EPB/SPB blocks).
import { detectFormat, type CaptureFormat } from './reader'

export interface RawPacket {
  /** Byte offset of the frame data within the source buffer. */
  frameOffset: number
  /** Captured length of the frame. */
  capLen: number
  /** Original (wire) length. */
  origLen: number
  tsSec: number // epoch seconds, fractional
  linkType: number
}

export interface CaptureMeta {
  format: CaptureFormat
  linkType: number
}

/**
 * Yields packets without copying frame bytes (offsets into `buf`). The caller
 * slices frame data from `buf` using frameOffset/capLen.
 */
export function* iterateCapture(buf: Buffer): Generator<RawPacket, CaptureMeta, void> {
  const info = detectFormat(buf)
  if (!info) throw new Error('Unrecognized capture format (not pcap or pcapng).')

  if (info.format === 'pcap') {
    yield* iteratePcap(buf, info.swapped, info.nanos)
    return { format: 'pcap', linkType: readGlobalLinkType(buf, info.swapped) }
  } else {
    return yield* iteratePcapng(buf)
  }
}

function readGlobalLinkType(buf: Buffer, swapped: boolean): number {
  return swapped ? buf.readUInt32BE(20) : buf.readUInt32LE(20)
}

function* iteratePcap(buf: Buffer, swapped: boolean, nanos: boolean): Generator<RawPacket> {
  const u16 = (o: number): number => (swapped ? buf.readUInt16BE(o) : buf.readUInt16LE(o))
  const u32 = (o: number): number => (swapped ? buf.readUInt32BE(o) : buf.readUInt32LE(o))

  const linkType = u32(20)
  let pos = 24 // global header size
  while (pos + 16 <= buf.length) {
    const tsHigh = u32(pos) // seconds
    const tsFrac = u32(pos + 4) // us or ns
    const capLen = u32(pos + 8)
    const origLen = u32(pos + 12)
    pos += 16
    if (capLen < 0 || pos + capLen > buf.length) break // truncated final record
    const tsSec = tsHigh + tsFrac / (nanos ? 1e9 : 1e6)
    yield { frameOffset: pos, capLen, origLen, tsSec, linkType }
    pos += capLen
  }
  void u16
}

const BT_SHB = 0x0a0d0d0a
const BT_IDB = 0x00000001
const BT_EPB = 0x00000006
const BT_SPB = 0x00000003
const BT_PB_OBSOLETE = 0x00000002

function* iteratePcapng(buf: Buffer): Generator<RawPacket, CaptureMeta, void> {
  let pos = 0
  let le = true
  // Per-interface link type and timestamp resolution.
  const interfaces: { linkType: number; tsResol: number }[] = []
  let firstLinkType = 1

  const u32 = (o: number): number => (le ? buf.readUInt32LE(o) : buf.readUInt32BE(o))
  const u16 = (o: number): number => (le ? buf.readUInt16LE(o) : buf.readUInt16BE(o))

  while (pos + 12 <= buf.length) {
    const blockType = buf.readUInt32BE(pos) === BT_SHB ? BT_SHB : le ? buf.readUInt32LE(pos) : buf.readUInt32BE(pos)
    // Block total length uses the section's endianness; for SHB we detect it.
    if (blockType === BT_SHB) {
      // Byte-order magic at pos+8
      const bom = buf.readUInt32LE(pos + 8)
      le = bom === 0x1a2b3c4d
    }
    const blockLen = u32(pos + 4)
    if (blockLen < 12 || pos + blockLen > buf.length) break

    if (blockType === BT_IDB) {
      const linkType = u16(pos + 8)
      // Parse options for if_tsresol (option code 9).
      const tsResol = readTsResol(buf, pos + 16, pos + blockLen - 4, le)
      interfaces.push({ linkType, tsResol })
      if (interfaces.length === 1) firstLinkType = linkType
    } else if (blockType === BT_EPB) {
      const ifId = u32(pos + 8)
      const tsHi = u32(pos + 12)
      const tsLo = u32(pos + 16)
      const capLen = u32(pos + 20)
      const origLen = u32(pos + 24)
      const iface = interfaces[ifId] ?? interfaces[0] ?? { linkType: firstLinkType, tsResol: 1e6 }
      const tsSec = timestampFrom(tsHi, tsLo, iface.tsResol)
      const frameOffset = pos + 28
      if (frameOffset + capLen <= pos + blockLen) {
        yield { frameOffset, capLen, origLen, tsSec, linkType: iface.linkType }
      }
    } else if (blockType === BT_SPB) {
      const origLen = u32(pos + 8)
      const iface = interfaces[0] ?? { linkType: firstLinkType, tsResol: 1e6 }
      // capLen = block length - 16, padded to 32 bits.
      const capLen = Math.min(origLen, blockLen - 16)
      const frameOffset = pos + 12
      if (frameOffset + capLen <= pos + blockLen) {
        yield { frameOffset, capLen, origLen, tsSec: 0, linkType: iface.linkType }
      }
    } else if (blockType === BT_PB_OBSOLETE) {
      const capLen = u32(pos + 20)
      const origLen = u32(pos + 24)
      const iface = interfaces[0] ?? { linkType: firstLinkType, tsResol: 1e6 }
      const frameOffset = pos + 28
      if (frameOffset + capLen <= pos + blockLen) {
        yield { frameOffset, capLen, origLen, tsSec: 0, linkType: iface.linkType }
      }
    }

    pos += blockLen
    if (blockLen % 4 !== 0) pos += 4 - (blockLen % 4)
  }
  void u16
  return { format: 'pcapng', linkType: firstLinkType }
}

function readTsResol(buf: Buffer, start: number, end: number, le: boolean): number {
  let p = start
  while (p + 4 <= end) {
    const code = le ? buf.readUInt16LE(p) : buf.readUInt16BE(p)
    const len = le ? buf.readUInt16LE(p + 2) : buf.readUInt16BE(p + 2)
    p += 4
    if (code === 0) break // end of options
    if (code === 9 && len >= 1) {
      const val = buf[p]
      if (val & 0x80) return Math.pow(2, val & 0x7f) // power of two
      return Math.pow(10, val)
    }
    p += len
    if (len % 4 !== 0) p += 4 - (len % 4)
  }
  return 1e6 // default: microseconds
}

function timestampFrom(hi: number, lo: number, resolPerSec: number): number {
  // 64-bit timestamp in units of 1/resolPerSec.
  const units = hi * 0x100000000 + lo
  return units / resolPerSec
}
