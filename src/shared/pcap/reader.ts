// Low-level helpers: capture-format detection, link-layer type names, and a
// small cursor for reading integers out of a Buffer.

export type CaptureFormat = 'pcap' | 'pcapng'

export interface FormatInfo {
  format: CaptureFormat
  /** For classic pcap: whether byte order is swapped relative to host. */
  swapped: boolean
  /** For classic pcap: nanosecond-resolution timestamps. */
  nanos: boolean
}

const PCAP_MAGIC = 0xa1b2c3d4
const PCAP_MAGIC_SWAPPED = 0xd4c3b2a1
const PCAP_MAGIC_NS = 0xa1b23c4d
const PCAP_MAGIC_NS_SWAPPED = 0x4d3cb2a1
const PCAPNG_BLOCK_TYPE_SHB = 0x0a0d0d0a

export function detectFormat(buf: Buffer): FormatInfo | null {
  if (buf.length < 4) return null
  const magicBE = buf.readUInt32BE(0)
  const magicLE = buf.readUInt32LE(0)

  if (magicBE === PCAPNG_BLOCK_TYPE_SHB) {
    return { format: 'pcapng', swapped: false, nanos: false }
  }
  if (magicLE === PCAP_MAGIC) return { format: 'pcap', swapped: false, nanos: false }
  if (magicLE === PCAP_MAGIC_SWAPPED) return { format: 'pcap', swapped: true, nanos: false }
  if (magicLE === PCAP_MAGIC_NS) return { format: 'pcap', swapped: false, nanos: true }
  if (magicLE === PCAP_MAGIC_NS_SWAPPED) return { format: 'pcap', swapped: true, nanos: true }
  return null
}

// Common DLT / LINKTYPE values.
export const LINKTYPE = {
  NULL: 0,
  ETHERNET: 1,
  RAW: 101,
  RAW_ALT1: 12,
  RAW_ALT2: 14,
  LINUX_SLL: 113,
  LINUX_SLL2: 276,
  IEEE802_11: 105,
  LOOP: 108
} as const

export function linkTypeName(lt: number): string {
  switch (lt) {
    case LINKTYPE.NULL:
      return 'Null/Loopback'
    case LINKTYPE.ETHERNET:
      return 'Ethernet'
    case LINKTYPE.RAW:
    case LINKTYPE.RAW_ALT1:
    case LINKTYPE.RAW_ALT2:
      return 'Raw IP'
    case LINKTYPE.LINUX_SLL:
      return 'Linux cooked v1'
    case LINKTYPE.LINUX_SLL2:
      return 'Linux cooked v2'
    case LINKTYPE.IEEE802_11:
      return '802.11'
    case LINKTYPE.LOOP:
      return 'OpenBSD loopback'
    default:
      return `LinkType ${lt}`
  }
}
