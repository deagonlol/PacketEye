import type { Dissection, DhcpInfo } from '../model'
import { ipv4ToStr, macToStr } from './util'

const MSG_TYPES: Record<number, string> = {
  1: 'DISCOVER',
  2: 'OFFER',
  3: 'REQUEST',
  4: 'DECLINE',
  5: 'ACK',
  6: 'NAK',
  7: 'RELEASE',
  8: 'INFORM'
}

export function dissectDhcp(d: Dissection, payload: Buffer, full: boolean): boolean {
  if (payload.length < 240) return false
  const op = payload[0]
  if (op !== 1 && op !== 2) return false
  // Magic cookie at offset 236.
  if (payload.readUInt32BE(236) !== 0x63825363) return false

  const clientMac = macToStr(payload, 28)
  let messageType = op === 1 ? 'REQUEST' : 'REPLY'
  let requestedIp: string | undefined
  let serverId: string | undefined

  let p = 240
  while (p < payload.length) {
    const code = payload[p]
    if (code === 255) break // end
    if (code === 0) {
      p++
      continue
    }
    const len = payload[p + 1]
    const val = payload.subarray(p + 2, p + 2 + len)
    if (code === 53 && len >= 1) messageType = MSG_TYPES[val[0]] ?? `type ${val[0]}`
    else if (code === 50 && len === 4) requestedIp = ipv4ToStr(val, 0)
    else if (code === 54 && len === 4) serverId = ipv4ToStr(val, 0)
    p += 2 + len
  }

  const isServer = op === 2 // BOOTREPLY comes from a DHCP server
  const dhcp: DhcpInfo = { messageType, isServer, clientMac, requestedIp, serverId }
  d.dhcp = dhcp
  d.protocol = 'DHCP'
  d.info = `DHCP ${messageType}${serverId ? ` (server ${serverId})` : ''}`

  if (full) {
    d.layers.push({
      name: 'DHCP',
      summary: d.info,
      fields: [
        { label: 'Message Type', value: messageType },
        { label: 'Client MAC', value: clientMac },
        ...(requestedIp ? [{ label: 'Requested IP', value: requestedIp }] : []),
        ...(serverId ? [{ label: 'Server ID', value: serverId }] : [])
      ]
    })
  }
  return true
}
