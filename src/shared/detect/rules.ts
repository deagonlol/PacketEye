import type { Finding } from '../types'
import { isPrivateIPv4 } from '../pcap/dissect/util'
import type { DetectionInput } from './index'
import type { DetectPacket } from './context'

type Rule = (input: DetectionInput) => Finding[]

function uniq<T>(arr: T[]): T[] {
  return [...new Set(arr)]
}

function shannonEntropy(s: string): number {
  const freq: Record<string, number> = {}
  for (const ch of s) freq[ch] = (freq[ch] ?? 0) + 1
  let e = 0
  const n = s.length
  for (const k in freq) {
    const p = freq[k] / n
    e -= p * Math.log2(p)
  }
  return e
}

/** Best-effort registrable parent domain (last two labels). */
function parentDomain(name: string): string {
  const parts = name.split('.').filter(Boolean)
  if (parts.length <= 2) return name
  return parts.slice(-2).join('.')
}

// ---- 1. Cleartext credentials ----
const cleartextCredentials: Rule = ({ packets }) => {
  const findings: Finding[] = []
  const byProto = new Map<string, { evidence: number[]; hosts: Set<string>; samples: string[] }>()

  for (const p of packets) {
    let proto: string | null = null
    let sample: string | undefined
    if (p.cleartext?.isCredential) {
      proto = p.cleartext.protocol
      sample = p.cleartext.credentialText
    } else if (p.http?.hasBasicAuth) {
      proto = 'HTTP Basic Auth'
      sample = p.http.basicAuthDecoded ? `credentials: ${p.http.basicAuthDecoded}` : undefined
    }
    if (!proto) continue
    const g = byProto.get(proto) ?? { evidence: [], hosts: new Set(), samples: [] }
    g.evidence.push(p.number)
    if (p.srcAddr) g.hosts.add(p.srcAddr)
    if (p.dstAddr) g.hosts.add(p.dstAddr)
    if (sample && g.samples.length < 3) g.samples.push(sample)
    byProto.set(proto, g)
  }

  for (const [proto, g] of byProto) {
    const isSnmp = proto === 'SNMP'
    findings.push({
      id: '',
      severity: 'critical',
      category: 'credentials',
      title: `Credentials sent in cleartext over ${proto}`,
      description:
        `Login credentials or secrets were transmitted without encryption over ${proto}. ` +
        `Anyone able to observe this traffic (on the same network, a compromised switch, or a ` +
        `man-in-the-middle position) can capture and reuse them.` +
        (g.samples.length ? ` Observed: ${g.samples.map((s) => `"${s.replace(/\s+/g, ' ').trim()}"`).join(', ')}.` : ''),
      evidence: g.evidence.slice(0, 30),
      affectedHosts: [...g.hosts],
      remediation: isSnmp
        ? 'Migrate to SNMPv3 with authentication and privacy (authPriv). Replace default/guessable community strings and restrict SNMP to management VLANs.'
        : `Disable ${proto} or wrap it in TLS (e.g. FTPS/FTP-over-TLS, IMAPS/POP3S/SMTPS, SSH instead of Telnet). Rotate any exposed credentials immediately.`,
      mitre: 'T1040 Network Sniffing / T1552 Unsecured Credentials',
      detail: proto
    })
  }
  return findings
}

// ---- 2. Insecure / unencrypted protocols in use ----
const insecureProtocols: Rule = ({ packets }) => {
  const seen = new Map<string, { evidence: number[]; hosts: Set<string> }>()
  const INSECURE: Record<string, string> = {
    HTTP: 'Unencrypted HTTP',
    FTP: 'Unencrypted FTP',
    Telnet: 'Telnet (unencrypted remote shell)',
    SMB: 'SMB file sharing',
    'NetBIOS-SSN': 'NetBIOS session service'
  }
  for (const p of packets) {
    const label = INSECURE[p.protocol]
    if (!label) continue
    // Require actual application data so bare SYN scan probes (which get labeled
    // by destination port, e.g. FTP/SMB) don't masquerade as protocol usage.
    if (p.protocol === 'HTTP' && !p.http) continue
    if (p.transport === 'tcp' && p.payloadLen === 0) continue
    const g = seen.get(p.protocol) ?? { evidence: [], hosts: new Set() }
    g.evidence.push(p.number)
    if (p.dstAddr) g.hosts.add(p.dstAddr)
    seen.set(p.protocol, g)
  }
  const findings: Finding[] = []
  for (const [proto, g] of seen) {
    findings.push({
      id: '',
      severity: proto === 'Telnet' || proto === 'FTP' ? 'high' : 'medium',
      category: 'insecure-protocol',
      title: `${INSECURE[proto]} observed`,
      description:
        `${INSECURE[proto]} does not encrypt data in transit, exposing content and any ` +
        `credentials to eavesdropping and tampering. ${g.evidence.length} packet(s) used this protocol.`,
      evidence: g.evidence.slice(0, 30),
      affectedHosts: [...g.hosts].slice(0, 20),
      remediation:
        proto === 'HTTP'
          ? 'Serve the application over HTTPS (TLS 1.2+) and redirect HTTP to HTTPS with HSTS.'
          : proto === 'Telnet'
            ? 'Replace Telnet with SSH.'
            : proto === 'FTP'
              ? 'Replace FTP with SFTP or FTPS.'
              : 'Restrict and encrypt this service; disable legacy versions (e.g. SMBv1).',
      mitre: 'T1040 Network Sniffing',
      detail: proto
    })
  }
  return findings
}

// ---- 3. Weak / obsolete TLS ----
const weakTls: Rule = ({ packets }) => {
  const evidence: number[] = []
  const hosts = new Set<string>()
  const versions = new Set<string>()
  const ciphers = new Set<string>()
  for (const p of packets) {
    if (p.tls?.weak) {
      evidence.push(p.number)
      if (p.tls.sni) hosts.add(p.tls.sni)
      else if (p.dstAddr) hosts.add(p.dstAddr)
      versions.add(p.tls.version)
      p.tls.cipherSuites.filter((c) => /RC4|3DES|NULL|EXPORT|MD5/.test(c)).forEach((c) => ciphers.add(c))
    }
  }
  if (evidence.length === 0) return []
  return [
    {
      id: '',
      severity: 'high',
      category: 'weak-crypto',
      title: 'Obsolete TLS version or weak cipher suites negotiated',
      description:
        `TLS handshakes used deprecated protocol versions (${[...versions].join(', ') || 'pre-TLS 1.2'}) ` +
        `or weak cipher suites${ciphers.size ? ` (${[...ciphers].slice(0, 4).join(', ')})` : ''}. ` +
        `These are vulnerable to known attacks (BEAST, POODLE, RC4 biases) and can be downgraded or decrypted.`,
      evidence: evidence.slice(0, 30),
      affectedHosts: [...hosts].slice(0, 20),
      remediation:
        'Require TLS 1.2 or 1.3 and disable SSLv3/TLS 1.0/1.1. Remove RC4, 3DES, EXPORT, and NULL cipher suites; prefer AEAD suites (AES-GCM, ChaCha20-Poly1305).',
      mitre: 'T1557 Adversary-in-the-Middle',
      detail: [...versions].join(',')
    }
  ]
}

// ---- 4. Port scan (one src → many ports on a dst, mostly unanswered SYNs) ----
const portScan: Rule = ({ packets }) => {
  const map = new Map<string, { ports: Set<number>; syn: number; synAck: number; evidence: number[] }>()
  for (const p of packets) {
    if (p.transport !== 'tcp' || !p.tcpFlags) continue
    if (p.tcpFlags.syn && !p.tcpFlags.ack) {
      const key = `${p.srcAddr}→${p.dstAddr}`
      const g = map.get(key) ?? { ports: new Set(), syn: 0, synAck: 0, evidence: [] }
      g.ports.add(p.dstPort ?? 0)
      g.syn++
      if (g.evidence.length < 30) g.evidence.push(p.number)
      map.set(key, g)
    }
  }
  const findings: Finding[] = []
  for (const [key, g] of map) {
    if (g.ports.size >= 15) {
      const [src, dst] = key.split('→')
      findings.push({
        id: '',
        severity: 'high',
        category: 'recon',
        title: `TCP port scan from ${src}`,
        description:
          `${src} sent SYN packets to ${g.ports.size} distinct ports on ${dst} in this capture — ` +
          `a hallmark of port scanning / service enumeration, typically an early reconnaissance step ` +
          `before an attack.`,
        evidence: g.evidence,
        affectedHosts: [src, dst],
        remediation:
          'Investigate the source host — if it is not an authorized scanner, treat it as potentially compromised. Restrict exposed services with a host/network firewall and enable rate-limiting or an IDS/IPS to detect scans.',
        mitre: 'T1046 Network Service Discovery',
        detail: `${g.ports.size} ports`
      })
    }
  }
  return findings
}

// ---- 5. Host sweep (one src → same port on many hosts, or ICMP sweep) ----
const hostSweep: Rule = ({ packets }) => {
  const synMap = new Map<string, Set<string>>() // src|port -> dst set
  const icmpMap = new Map<string, Set<string>>() // src -> dst set (echo requests)
  const evidence = new Map<string, number[]>()
  for (const p of packets) {
    if (p.transport === 'tcp' && p.tcpFlags?.syn && !p.tcpFlags.ack) {
      const key = `${p.srcAddr}|${p.dstPort}`
      const set = synMap.get(key) ?? new Set()
      set.add(p.dstAddr)
      synMap.set(key, set)
      const ev = evidence.get(key) ?? []
      if (ev.length < 30) ev.push(p.number)
      evidence.set(key, ev)
    }
    if (p.icmp && /Echo request/i.test(p.icmp.summary)) {
      const set = icmpMap.get(p.srcAddr) ?? new Set()
      set.add(p.dstAddr)
      icmpMap.set(p.srcAddr, set)
      const ev = evidence.get(`icmp|${p.srcAddr}`) ?? []
      if (ev.length < 30) ev.push(p.number)
      evidence.set(`icmp|${p.srcAddr}`, ev)
    }
  }
  const findings: Finding[] = []
  for (const [key, dsts] of synMap) {
    if (dsts.size >= 15) {
      const [src, port] = key.split('|')
      findings.push({
        id: '',
        severity: 'medium',
        category: 'recon',
        title: `Host sweep on port ${port} from ${src}`,
        description: `${src} probed port ${port} across ${dsts.size} distinct hosts — a network sweep to find hosts running a specific service.`,
        evidence: evidence.get(key) ?? [],
        affectedHosts: [src],
        remediation: 'Verify whether the source is an authorized scanner; otherwise investigate for compromise and segment the network to limit lateral discovery.',
        mitre: 'T1046 Network Service Discovery',
        detail: `${dsts.size} hosts`
      })
    }
  }
  for (const [src, dsts] of icmpMap) {
    if (dsts.size >= 15) {
      findings.push({
        id: '',
        severity: 'low',
        category: 'recon',
        title: `ICMP ping sweep from ${src}`,
        description: `${src} sent ICMP echo requests to ${dsts.size} distinct hosts — a ping sweep used to map live hosts.`,
        evidence: evidence.get(`icmp|${src}`) ?? [],
        affectedHosts: [src],
        remediation: 'Consider rate-limiting or filtering ICMP echo at network boundaries and investigate the source.',
        mitre: 'T1018 Remote System Discovery',
        detail: `${dsts.size} hosts`
      })
    }
  }
  return findings
}

// ---- 6. ARP spoofing (one IP claimed by multiple MACs) ----
const arpSpoofing: Rule = ({ packets }) => {
  const ipToMacs = new Map<string, Map<string, number[]>>() // ip -> mac -> evidence
  for (const p of packets) {
    if (!p.arp || p.arp.opcode !== 2) continue
    const ip = p.arp.senderIp
    const mac = p.arp.senderMac
    if (ip === '0.0.0.0' || mac === '00:00:00:00:00:00') continue
    const macs = ipToMacs.get(ip) ?? new Map()
    const ev = macs.get(mac) ?? []
    ev.push(p.number)
    macs.set(mac, ev)
    ipToMacs.set(ip, macs)
  }
  const findings: Finding[] = []
  for (const [ip, macs] of ipToMacs) {
    if (macs.size >= 2) {
      const evidence = [...macs.values()].flat().slice(0, 30)
      findings.push({
        id: '',
        severity: 'critical',
        category: 'spoofing',
        title: `Possible ARP spoofing: ${ip} claimed by multiple MACs`,
        description:
          `The IP address ${ip} was announced by ${macs.size} different MAC addresses ` +
          `(${[...macs.keys()].join(', ')}). This is the signature of an ARP cache poisoning / ` +
          `man-in-the-middle attack, where an attacker impersonates another host (often the gateway) ` +
          `to intercept traffic.`,
        evidence,
        affectedHosts: [ip, ...macs.keys()],
        remediation:
          'Identify which MAC is legitimate for this IP. Enable Dynamic ARP Inspection (DAI) and DHCP snooping on managed switches, use static ARP entries for critical hosts (e.g. the gateway), and isolate the offending device.',
        mitre: 'T1557.002 ARP Cache Poisoning',
        detail: ip
      })
    }
  }
  return findings
}

// ---- 7. Rogue DHCP (multiple DHCP servers) ----
const rogueDhcp: Rule = ({ packets }) => {
  const servers = new Map<string, number[]>()
  for (const p of packets) {
    if (p.dhcp?.isServer) {
      const id = p.dhcp.serverId ?? p.srcAddr
      const ev = servers.get(id) ?? []
      ev.push(p.number)
      servers.set(id, ev)
    }
  }
  if (servers.size < 2) return []
  return [
    {
      id: '',
      severity: 'high',
      category: 'spoofing',
      title: 'Multiple DHCP servers detected (possible rogue DHCP)',
      description:
        `DHCP offers/acks came from ${servers.size} distinct servers (${[...servers.keys()].join(', ')}). ` +
        `A rogue DHCP server can hand out a malicious gateway or DNS server to redirect and intercept traffic.`,
      evidence: [...servers.values()].flat().slice(0, 30),
      affectedHosts: [...servers.keys()],
      remediation:
        'Confirm which DHCP server is authorized. Enable DHCP snooping on switches to permit DHCP replies only from trusted ports, and locate/remove the rogue server.',
      mitre: 'T1557 Adversary-in-the-Middle',
      detail: `${servers.size} servers`
    }
  ]
}

// ---- 8. DNS tunneling / exfiltration ----
const dnsTunneling: Rule = ({ packets, analyzer }) => {
  const byParent = new Map<
    string,
    { subs: Set<string>; totalLen: number; entropySum: number; count: number; txtNull: number; evidence: number[]; names: string[] }
  >()
  for (const p of packets) {
    if (!p.dns || !p.dns.isQuery) continue
    for (const q of p.dns.questions) {
      const parent = parentDomain(q.name)
      const g = byParent.get(parent) ?? {
        subs: new Set(),
        totalLen: 0,
        entropySum: 0,
        count: 0,
        txtNull: 0,
        evidence: [],
        names: []
      }
      const sub = q.name.slice(0, q.name.length - parent.length - 1)
      g.subs.add(sub)
      g.totalLen += sub.length
      g.entropySum += shannonEntropy(sub)
      g.count++
      if (q.type === 'TXT' || q.type === 'NULL') g.txtNull++
      if (g.evidence.length < 30) g.evidence.push(p.number)
      if (g.names.length < 3) g.names.push(q.name)
      byParent.set(parent, g)
    }
  }
  const findings: Finding[] = []
  for (const [parent, g] of byParent) {
    const avgLen = g.totalLen / Math.max(1, g.count)
    const avgEntropy = g.entropySum / Math.max(1, g.count)
    const manyUnique = g.subs.size >= 15
    const longHighEntropy = avgLen >= 20 && avgEntropy >= 3.0
    const txtHeavy = g.txtNull >= 10
    if (manyUnique && (longHighEntropy || txtHeavy)) {
      analyzer.markDnsSuspicious(g.names[0] ?? parent)
      findings.push({
        id: '',
        severity: 'high',
        category: 'c2-exfil',
        title: `Possible DNS tunneling to ${parent}`,
        description:
          `${g.subs.size} unique, long (avg ${avgLen.toFixed(0)} chars), high-entropy subdomains ` +
          `were queried under ${parent}${txtHeavy ? ` with heavy TXT/NULL record use` : ''}. ` +
          `This pattern is characteristic of DNS tunneling — encoding data (exfiltration or command & ` +
          `control) inside DNS queries to bypass firewalls. e.g. ${g.names[0] ?? ''}`,
        evidence: g.evidence,
        affectedHosts: uniq(packets.filter((p) => g.evidence.includes(p.number)).map((p) => p.srcAddr)),
        remediation:
          `Block or sinkhole ${parent}. Inspect the querying host for malware/beaconing, restrict outbound DNS to approved resolvers, and deploy DNS monitoring that flags high query volume, long labels, and unusual record types.`,
        mitre: 'T1071.004 Application Layer Protocol: DNS / T1048 Exfiltration',
        detail: parent
      })
    }
  }
  return findings
}

// ---- 9. LLMNR / NBT-NS / mDNS exposure ----
const nameServiceExposure: Rule = ({ packets }) => {
  const evidence: number[] = []
  const protos = new Set<string>()
  const hosts = new Set<string>()
  for (const p of packets) {
    if (p.dns && (p.dns.transport === 'llmnr' || p.dns.transport === 'nbns')) {
      if (evidence.length < 30) evidence.push(p.number)
      protos.add(p.dns.transport.toUpperCase())
      hosts.add(p.srcAddr)
    }
  }
  if (evidence.length === 0) return []
  return [
    {
      id: '',
      severity: 'low',
      category: 'spoofing',
      title: `${[...protos].join(' / ')} name resolution in use (poisoning exposure)`,
      description:
        `Hosts used ${[...protos].join('/')} for name resolution. These legacy fallback protocols are ` +
        `trivially spoofed (e.g. with Responder) to poison name lookups and capture NTLM hashes.`,
      evidence,
      affectedHosts: [...hosts].slice(0, 20),
      remediation:
        'Disable LLMNR and NBT-NS via Group Policy where possible, and ensure DNS is correctly configured so hosts do not fall back to them.',
      mitre: 'T1557.001 LLMNR/NBT-NS Poisoning',
      detail: [...protos].join(',')
    }
  ]
}

// ---- 10. NXDOMAIN spike ----
const nxdomainSpike: Rule = ({ packets }) => {
  let nx = 0
  const evidence: number[] = []
  const hosts = new Set<string>()
  for (const p of packets) {
    if (p.dns && !p.dns.isQuery && p.dns.rcode === 3) {
      nx++
      if (evidence.length < 30) evidence.push(p.number)
      hosts.add(p.dstAddr)
    }
  }
  if (nx < 20) return []
  return [
    {
      id: '',
      severity: 'low',
      category: 'hygiene',
      title: `High volume of NXDOMAIN responses (${nx})`,
      description:
        `${nx} DNS lookups failed with NXDOMAIN. A spike of failed lookups can indicate malware using ` +
        `a domain-generation algorithm (DGA) to find its C2, or simply misconfiguration.`,
      evidence,
      affectedHosts: [...hosts].slice(0, 20),
      remediation:
        'Correlate the failing domains with the querying hosts. If the domains look algorithmically generated, treat the host as potentially infected.',
      mitre: 'T1568.002 Domain Generation Algorithms',
      detail: `${nx} NXDOMAIN`
    }
  ]
}

// ---- 11. Beaconing to external hosts (regular-interval connections) ----
const beaconing: Rule = ({ flows }) => {
  const findings: Finding[] = []
  for (const f of flows) {
    const ts = f.timestamps
    if (!ts || ts.length < 8) continue
    // Only consider a public/external endpoint.
    const externalB = !isPrivateIPv4(f.addrB) && f.addrB.includes('.')
    const externalA = !isPrivateIPv4(f.addrA) && f.addrA.includes('.')
    if (!externalA && !externalB) continue

    const sorted = [...ts].sort((a, b) => a - b)
    const gaps: number[] = []
    for (let i = 1; i < sorted.length; i++) gaps.push(sorted[i] - sorted[i - 1])
    const mean = gaps.reduce((s, g) => s + g, 0) / gaps.length
    if (mean <= 0) continue
    const variance = gaps.reduce((s, g) => s + (g - mean) ** 2, 0) / gaps.length
    const cv = Math.sqrt(variance) / mean // coefficient of variation (jitter)
    if (cv < 0.15 && gaps.length >= 7) {
      const ext = externalB ? f.addrB : f.addrA
      findings.push({
        id: '',
        severity: 'medium',
        category: 'c2-exfil',
        title: `Regular beaconing to ${ext}`,
        description:
          `A connection to ${ext} repeated ${sorted.length} times at a near-constant interval ` +
          `(~${mean.toFixed(2)}s, jitter ${(cv * 100).toFixed(0)}%). Highly regular timing is typical of ` +
          `malware command-and-control beaconing rather than human-driven traffic.`,
        evidence: f.samplePackets.slice(0, 20),
        affectedHosts: [f.addrA, f.addrB],
        remediation:
          `Investigate the internal host and the process contacting ${ext}. Block the destination if unrecognized and hunt for persistence/malware on the host.`,
        mitre: 'T1071 Application Layer Protocol (C2 Beaconing)',
        detail: ext
      })
    }
  }
  return findings
}

// ---- 12. Plaintext broadcast/discovery exposure (SSDP/SNMP-trap/NetBIOS) ----
const broadcastExposure: Rule = ({ packets }) => {
  const evidence: number[] = []
  const protos = new Set<string>()
  for (const p of packets) {
    if (['SSDP', 'NetBIOS', 'NBNS'].includes(p.protocol)) {
      if (evidence.length < 20) evidence.push(p.number)
      protos.add(p.protocol)
    }
  }
  if (evidence.length === 0 || protos.size === 0) return []
  return [
    {
      id: '',
      severity: 'info',
      category: 'hygiene',
      title: `Legacy discovery/broadcast chatter (${[...protos].join(', ')})`,
      description:
        `Broadcast discovery protocols (${[...protos].join(', ')}) were observed. They leak host and ` +
        `service information on the local segment and expand the attack surface.`,
      evidence,
      affectedHosts: [],
      remediation:
        'Disable unused discovery services (SSDP/UPnP, NetBIOS) on endpoints, and segment/limit broadcast domains.',
      mitre: 'T1046 Network Service Discovery',
      detail: [...protos].join(',')
    }
  ]
}

export const ALL_RULES: Rule[] = [
  cleartextCredentials,
  insecureProtocols,
  weakTls,
  portScan,
  hostSweep,
  arpSpoofing,
  rogueDhcp,
  dnsTunneling,
  nameServiceExposure,
  nxdomainSpike,
  beaconing,
  broadcastExposure
]
