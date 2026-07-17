// Composable traffic scenarios for synthetic captures. Each scenario appends
// frames to a shared PcapWriter using an advancing time cursor. Detection-
// specific scenarios are extended alongside the detection rules.
import { PcapWriter } from './lib/pcap-writer'
import {
  ETH,
  IPPROTO,
  arp,
  ethernet,
  ipv4,
  tcp,
  udp
} from './lib/packet-builder'
import {
  ascii,
  dhcpMessage,
  dnsQuery,
  dnsResponse,
  httpRequest,
  httpResponse,
  tlsClientHello
} from './lib/payloads'

const MAC = {
  gateway: '00:11:22:33:44:01',
  client: '00:aa:bb:cc:dd:01',
  client2: '00:aa:bb:cc:dd:02',
  attacker: 'de:ad:be:ef:00:99',
  server: '00:11:22:33:44:aa'
}

const IP = {
  gateway: '192.168.1.1',
  client: '192.168.1.100',
  client2: '192.168.1.101',
  attacker: '192.168.1.66',
  dns: '192.168.1.1',
  web: '93.184.216.34',
  extC2: '203.0.113.77'
}

class Cursor {
  t = 0
  constructor(private w: PcapWriter) {}
  step(dt = 0.001): number {
    this.t += dt
    return this.t
  }
  eth(dst: string, src: string, etherType: number, payload: Buffer, dt = 0.001): void {
    this.w.add(ethernet(dst, src, etherType, payload), this.step(dt))
  }
}

// ---- Benign background traffic ----
export function benignTraffic(w: PcapWriter, c = new Cursor(w)): void {
  // ARP resolve gateway
  c.eth('ff:ff:ff:ff:ff:ff', MAC.client, ETH.ARP, arp(1, MAC.client, IP.client, '00:00:00:00:00:00', IP.gateway))
  c.eth(MAC.client, MAC.gateway, ETH.ARP, arp(2, MAC.gateway, IP.gateway, MAC.client, IP.client))

  // DNS query + response for example.com
  c.eth(MAC.gateway, MAC.client, ETH.IPV4, ipv4(IP.client, IP.dns, IPPROTO.UDP, udp({ srcPort: 51000, dstPort: 53, payload: dnsQuery(0x1a2b, 'example.com', 'A') })))
  c.eth(MAC.client, MAC.gateway, ETH.IPV4, ipv4(IP.dns, IP.client, IPPROTO.UDP, udp({ srcPort: 53, dstPort: 51000, payload: dnsResponse(0x1a2b, 'example.com', IP.web) })))

  // ICMP echo request + reply
  const echo = Buffer.concat([Buffer.from([8, 0, 0, 0, 0, 1, 0, 1]), ascii('abcdefghijklmnop')])
  const echoR = Buffer.concat([Buffer.from([0, 0, 0, 0, 0, 1, 0, 1]), ascii('abcdefghijklmnop')])
  c.eth(MAC.gateway, MAC.client, ETH.IPV4, ipv4(IP.client, IP.web, IPPROTO.ICMP, echo))
  c.eth(MAC.client, MAC.gateway, ETH.IPV4, ipv4(IP.web, IP.client, IPPROTO.ICMP, echoR))

  // TCP handshake + HTTPS-ish data to a normal server (no cleartext creds)
  handshake(c, IP.client, IP.web, 49200, 443)
  c.eth(MAC.gateway, MAC.client, ETH.IPV4, ipv4(IP.client, IP.web, IPPROTO.TCP, tcp({ srcPort: 49200, dstPort: 443, seq: 1, ack: 1, flags: { psh: true, ack: true }, payload: ascii('encrypted-ish payload') })))
}

// ---- Cleartext HTTP with Basic auth (credential exposure) ----
export function httpBasicAuth(w: PcapWriter, c = new Cursor(w)): void {
  handshake(c, IP.client, IP.web, 49250, 80)
  const creds = Buffer.from('admin:SuperSecret123').toString('base64')
  const req = httpRequest('GET', '/admin', 'intranet.example.com', {
    Authorization: `Basic ${creds}`,
    'User-Agent': 'Mozilla/5.0',
    Cookie: 'session=abc123'
  })
  c.eth(MAC.gateway, MAC.client, ETH.IPV4, ipv4(IP.client, IP.web, IPPROTO.TCP, tcp({ srcPort: 49250, dstPort: 80, seq: 1, ack: 1, flags: { psh: true, ack: true }, payload: req })))
  c.eth(MAC.client, MAC.gateway, ETH.IPV4, ipv4(IP.web, IP.client, IPPROTO.TCP, tcp({ srcPort: 80, dstPort: 49250, seq: 1, ack: 1 + req.length, flags: { psh: true, ack: true }, payload: httpResponse(200, 'OK', 'ok') })))
}

// ---- Telnet cleartext login ----
export function telnetLogin(w: PcapWriter, c = new Cursor(w)): void {
  handshake(c, IP.client, IP.gateway, 49300, 23)
  const send = (text: string, seq: number): void => {
    c.eth(MAC.gateway, MAC.client, ETH.IPV4, ipv4(IP.client, IP.gateway, IPPROTO.TCP, tcp({ srcPort: 49300, dstPort: 23, seq, ack: 1, flags: { psh: true, ack: true }, payload: ascii(text) })))
  }
  const recv = (text: string, seq: number): void => {
    c.eth(MAC.client, MAC.gateway, ETH.IPV4, ipv4(IP.gateway, IP.client, IPPROTO.TCP, tcp({ srcPort: 23, dstPort: 49300, seq, ack: 1, flags: { psh: true, ack: true }, payload: ascii(text) })))
  }
  recv('login: ', 1)
  send('admin\r\n', 1)
  recv('Password: ', 8)
  send('r00tpassword\r\n', 7)
  recv('Last login: ...\r\n$ ', 18)
}

// ---- Port scan: one source SYNs many ports, no completion ----
export function portScan(w: PcapWriter, c = new Cursor(w)): void {
  const ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080]
  let seq = 1000
  for (const p of ports) {
    c.eth(MAC.gateway, MAC.attacker, ETH.IPV4, ipv4(IP.attacker, IP.gateway, IPPROTO.TCP, tcp({ srcPort: 40000, dstPort: p, seq: seq++, flags: { syn: true } })), 0.0005)
  }
}

// ---- ARP spoofing: attacker claims to be the gateway ----
export function arpSpoof(w: PcapWriter, c = new Cursor(w)): void {
  for (let i = 0; i < 5; i++) {
    // Gratuitous ARP: gateway IP -> attacker MAC
    c.eth('ff:ff:ff:ff:ff:ff', MAC.attacker, ETH.ARP, arp(2, MAC.attacker, IP.gateway, 'ff:ff:ff:ff:ff:ff', IP.gateway), 0.05)
  }
  // The legitimate gateway also announces itself (conflicting MAC for same IP)
  c.eth('ff:ff:ff:ff:ff:ff', MAC.gateway, ETH.ARP, arp(2, MAC.gateway, IP.gateway, 'ff:ff:ff:ff:ff:ff', IP.gateway), 0.05)
}

// ---- DNS tunneling: many long high-entropy subdomains ----
export function dnsTunnel(w: PcapWriter, c = new Cursor(w)): void {
  let id = 0x3000
  for (let i = 0; i < 30; i++) {
    const label = randomLabel(40, i + 1)
    const name = `${label}.tunnel.evil-c2.com`
    c.eth(MAC.gateway, MAC.client, ETH.IPV4, ipv4(IP.client, IP.dns, IPPROTO.UDP, udp({ srcPort: 52000 + i, dstPort: 53, payload: dnsQuery(id++, name, 'TXT') })), 0.02)
  }
}

// ---- Weak TLS: ClientHello offering TLS 1.0 + RC4 ----
export function weakTls(w: PcapWriter, c = new Cursor(w)): void {
  handshake(c, IP.client, IP.web, 49400, 443)
  const hello = tlsClientHello(0x0301, 'legacy.example.com', [0x0005, 0x000a, 0x002f])
  c.eth(MAC.gateway, MAC.client, ETH.IPV4, ipv4(IP.client, IP.web, IPPROTO.TCP, tcp({ srcPort: 49400, dstPort: 443, seq: 1, ack: 1, flags: { psh: true, ack: true }, payload: hello })))
}

// ---- Rogue DHCP: two different servers answering ----
export function rogueDhcp(w: PcapWriter, c = new Cursor(w)): void {
  // Client DISCOVER (broadcast)
  c.eth('ff:ff:ff:ff:ff:ff', MAC.client, ETH.IPV4, ipv4('0.0.0.0', '255.255.255.255', IPPROTO.UDP, udp({ srcPort: 68, dstPort: 67, payload: dhcpMessage(1, 1, MAC.client) })), 0.02)
  // Legit server OFFER
  c.eth(MAC.client, MAC.gateway, ETH.IPV4, ipv4(IP.gateway, IP.client, IPPROTO.UDP, udp({ srcPort: 67, dstPort: 68, payload: dhcpMessage(2, 2, MAC.client, IP.gateway) })), 0.02)
  // Rogue server OFFER (different server IP/MAC)
  c.eth(MAC.client, MAC.attacker, ETH.IPV4, ipv4(IP.attacker, IP.client, IPPROTO.UDP, udp({ srcPort: 67, dstPort: 68, payload: dhcpMessage(2, 2, MAC.client, IP.attacker) })), 0.02)
}

// ---- Helpers ----
function handshake(c: Cursor, cli: string, srv: string, sport: number, dport: number): void {
  c.eth(MAC.gateway, MAC.client, ETH.IPV4, ipv4(cli, srv, IPPROTO.TCP, tcp({ srcPort: sport, dstPort: dport, seq: 0, flags: { syn: true } })))
  c.eth(MAC.client, MAC.gateway, ETH.IPV4, ipv4(srv, cli, IPPROTO.TCP, tcp({ srcPort: dport, dstPort: sport, seq: 0, ack: 1, flags: { syn: true, ack: true } })))
  c.eth(MAC.gateway, MAC.client, ETH.IPV4, ipv4(cli, srv, IPPROTO.TCP, tcp({ srcPort: sport, dstPort: dport, seq: 1, ack: 1, flags: { ack: true } })))
}

function randomLabel(n: number, seedBase: number): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
  let s = ''
  // Deterministic pseudo-random (varies per call) so fixtures are reproducible
  // yet each generated subdomain is distinct and high-entropy.
  let seed = (seedBase * 2654435761) >>> 0
  for (let i = 0; i < n; i++) {
    seed = (Math.imul(seed, 1103515245) + 12345) >>> 0
    s += chars[(seed >>> 16) % chars.length]
  }
  return s
}

export function buildMixedCapture(): PcapWriter {
  const w = new PcapWriter()
  const c = new Cursor(w)
  benignTraffic(w, c)
  httpBasicAuth(w, c)
  telnetLogin(w, c)
  portScan(w, c)
  arpSpoof(w, c)
  dnsTunnel(w, c)
  weakTls(w, c)
  rogueDhcp(w, c)
  return w
}

/** Encrypted, well-behaved traffic only — used to guard against false positives. */
export function buildBenignCapture(): PcapWriter {
  const w = new PcapWriter()
  const c = new Cursor(w)
  benignTraffic(w, c)
  benignTraffic(w, c)
  return w
}
