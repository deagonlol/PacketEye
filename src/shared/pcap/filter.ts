// A deliberately small display-filter matcher. Supports plain substring search
// plus a few convenience tokens so the packet list feels responsive without a
// full expression engine:
//   - bare protocol name:  tcp, udp, dns, http, tls, arp, icmp
//   - ip.addr == 1.2.3.4  /  ip == 1.2.3.4  /  host 1.2.3.4
//   - port == 443  /  port 443
//   - any other text: case-insensitive substring over the packet's summary
import type { PacketSummary } from '../types'

export function matchesFilter(pkt: PacketSummary, haystack: string, filter: string): boolean {
  const f = filter.trim().toLowerCase()
  if (!f) return true

  // Split on whitespace so multiple tokens must all match (AND).
  const tokens = f.split(/\s+/)
  return tokens.every((tok) => matchToken(pkt, haystack, tok, tokens))
}

function matchToken(
  pkt: PacketSummary,
  haystack: string,
  tok: string,
  all: string[]
): boolean {
  // Handle "field == value" or "field value" that got split into tokens.
  const joined = all.join(' ')

  const portMatch = /(?:^|\s)port\s*(?:==|=|:)?\s*(\d+)/.exec(joined)
  if (/^port$|^port[=:]/.test(tok) || tok === '==') {
    if (portMatch) {
      const p = Number(portMatch[1])
      return pkt.srcPort === p || pkt.dstPort === p
    }
  }

  const ipMatch = /(?:ip(?:\.addr)?|host)\s*(?:==|=|:)?\s*([0-9a-f:.]+)/.exec(joined)
  if (/^(ip|ip\.addr|host)$|^(ip|host)[=:]/.test(tok)) {
    if (ipMatch) {
      const ip = ipMatch[1]
      return pkt.srcAddr.includes(ip) || pkt.dstAddr.includes(ip)
    }
  }

  // Bare protocol token.
  if (/^[a-z][a-z0-9]+$/.test(tok)) {
    if (pkt.protocol.toLowerCase() === tok) return true
  }

  // A pure number token: match port or packet number.
  if (/^\d+$/.test(tok)) {
    const n = Number(tok)
    if (pkt.srcPort === n || pkt.dstPort === n) return true
  }

  // Fallback: substring.
  return haystack.includes(tok)
}
