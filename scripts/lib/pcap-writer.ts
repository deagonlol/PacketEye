// Minimal classic-pcap (LE, microsecond) file writer for synthetic captures.
import { writeFileSync } from 'fs'

export interface CapturedFrame {
  frame: Buffer
  tsSec: number // seconds since epoch (fractional ok)
}

export class PcapWriter {
  private frames: CapturedFrame[] = []
  private baseTs: number

  constructor(baseTs = Date.UTC(2026, 5, 1, 12, 0, 0) / 1000) {
    this.baseTs = baseTs
  }

  /** Add a frame at `offsetSec` seconds after the capture base time. */
  add(frame: Buffer, offsetSec: number): void {
    this.frames.push({ frame, tsSec: this.baseTs + offsetSec })
  }

  toBuffer(linkType = 1): Buffer {
    const global = Buffer.alloc(24)
    global.writeUInt32LE(0xa1b2c3d4, 0) // magic (us)
    global.writeUInt16LE(2, 4) // version major
    global.writeUInt16LE(4, 6) // version minor
    global.writeInt32LE(0, 8) // thiszone
    global.writeUInt32LE(0, 12) // sigfigs
    global.writeUInt32LE(262144, 16) // snaplen
    global.writeUInt32LE(linkType, 20)

    const parts: Buffer[] = [global]
    for (const { frame, tsSec } of this.frames) {
      const rec = Buffer.alloc(16)
      const sec = Math.floor(tsSec)
      const usec = Math.round((tsSec - sec) * 1e6)
      rec.writeUInt32LE(sec, 0)
      rec.writeUInt32LE(usec, 4)
      rec.writeUInt32LE(frame.length, 8)
      rec.writeUInt32LE(frame.length, 12)
      parts.push(rec, frame)
    }
    return Buffer.concat(parts)
  }

  write(path: string, linkType = 1): void {
    writeFileSync(path, this.toBuffer(linkType))
  }

  get count(): number {
    return this.frames.length
  }
}
