// Application-layer dissection dispatch. Chooses a dissector by port and by
// sniffing the payload, then falls back to a port-based service label.
import type { Dissection } from '../model'
import { dissectDns } from './dns'
import { dissectHttp } from './http'
import { dissectTls } from './tls'
import { dissectDhcp } from './dhcp'
import { dissectCleartext, dissectSnmp } from './cleartext'

const DNS_PORTS = new Set([53, 5353, 5355, 137])
const HTTP_PORTS = new Set([80, 8080, 8000, 8888, 591])
const TLS_PORTS = new Set([443, 8443, 993, 995, 465, 990, 636, 5061])

export function dissectAppLayer(
  d: Dissection,
  payload: Buffer,
  srcPort: number,
  dstPort: number,
  transport: 'tcp' | 'udp',
  full: boolean
): void {
  if (payload.length === 0) return

  const onPort = (set: Set<number>): boolean => set.has(srcPort) || set.has(dstPort)

  if (onPort(DNS_PORTS)) {
    if (dissectDns(d, payload, srcPort, dstPort, full)) return
  }

  if (transport === 'udp' && (srcPort === 67 || dstPort === 67 || srcPort === 68 || dstPort === 68)) {
    if (dissectDhcp(d, payload, full)) return
  }

  if (transport === 'udp' && (srcPort === 161 || dstPort === 161 || srcPort === 162 || dstPort === 162)) {
    if (dissectSnmp(d, payload, full)) return
  }

  if (transport === 'tcp') {
    if (onPort(TLS_PORTS) || payload[0] === 0x16) {
      if (dissectTls(d, payload, full)) return
    }
    if (onPort(HTTP_PORTS) || looksHttp(payload)) {
      if (dissectHttp(d, payload, full)) return
    }
    if (dissectCleartext(d, payload, srcPort, dstPort, full)) return
  }

  // Fall through: try DNS on any UDP payload that looks like DNS (best effort).
  if (transport === 'udp' && !d.dns && payload.length >= 12) {
    // Only attempt when ports weren't already app-labeled to avoid noise.
  }
}

function looksHttp(payload: Buffer): boolean {
  if (payload.length < 5) return false
  const head = payload.toString('ascii', 0, 5)
  return (
    head.startsWith('GET ') ||
    head.startsWith('POST ') ||
    head.startsWith('PUT ') ||
    head.startsWith('HEAD ') ||
    head.startsWith('HTTP/')
  )
}
