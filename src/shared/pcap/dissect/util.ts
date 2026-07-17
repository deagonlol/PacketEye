// Formatting + lookup helpers shared by dissectors.

export function macToStr(buf: Buffer, off: number): string {
  const p: string[] = []
  for (let i = 0; i < 6; i++) p.push(buf[off + i].toString(16).padStart(2, '0'))
  return p.join(':')
}

export function ipv4ToStr(buf: Buffer, off: number): string {
  return `${buf[off]}.${buf[off + 1]}.${buf[off + 2]}.${buf[off + 3]}`
}

export function ipv6ToStr(buf: Buffer, off: number): string {
  const groups: string[] = []
  for (let i = 0; i < 16; i += 2) {
    groups.push(((buf[off + i] << 8) | buf[off + i + 1]).toString(16))
  }
  // Compress the longest run of zero groups (::).
  let bestStart = -1
  let bestLen = 0
  let curStart = -1
  let curLen = 0
  for (let i = 0; i < 8; i++) {
    if (groups[i] === '0') {
      if (curStart < 0) curStart = i
      curLen++
      if (curLen > bestLen) {
        bestLen = curLen
        bestStart = curStart
      }
    } else {
      curStart = -1
      curLen = 0
    }
  }
  if (bestLen > 1) {
    const head = groups.slice(0, bestStart).join(':')
    const tail = groups.slice(bestStart + bestLen).join(':')
    return `${head}::${tail}`.replace(/:::+/, '::')
  }
  return groups.join(':')
}

const WELL_KNOWN: Record<number, string> = {
  20: 'FTP-DATA',
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  67: 'DHCP',
  68: 'DHCP',
  69: 'TFTP',
  80: 'HTTP',
  110: 'POP3',
  111: 'RPC',
  123: 'NTP',
  135: 'MSRPC',
  137: 'NBNS',
  138: 'NetBIOS',
  139: 'NetBIOS-SSN',
  143: 'IMAP',
  161: 'SNMP',
  162: 'SNMP-Trap',
  389: 'LDAP',
  443: 'HTTPS',
  445: 'SMB',
  465: 'SMTPS',
  514: 'Syslog',
  515: 'LPD',
  587: 'SMTP-Sub',
  636: 'LDAPS',
  993: 'IMAPS',
  995: 'POP3S',
  1080: 'SOCKS',
  1433: 'MSSQL',
  1521: 'Oracle',
  1883: 'MQTT',
  1900: 'SSDP',
  3306: 'MySQL',
  3389: 'RDP',
  5060: 'SIP',
  5222: 'XMPP',
  5353: 'mDNS',
  5355: 'LLMNR',
  5432: 'PostgreSQL',
  5900: 'VNC',
  6379: 'Redis',
  8080: 'HTTP-Alt',
  8443: 'HTTPS-Alt',
  9200: 'Elasticsearch',
  27017: 'MongoDB'
}

export function serviceName(port: number): string | undefined {
  return WELL_KNOWN[port]
}

export function ipProtoName(proto: number): string {
  switch (proto) {
    case 1:
      return 'ICMP'
    case 2:
      return 'IGMP'
    case 6:
      return 'TCP'
    case 17:
      return 'UDP'
    case 41:
      return 'IPv6'
    case 47:
      return 'GRE'
    case 50:
      return 'ESP'
    case 51:
      return 'AH'
    case 58:
      return 'ICMPv6'
    case 89:
      return 'OSPF'
    case 132:
      return 'SCTP'
    default:
      return `IP proto ${proto}`
  }
}

export function isPrivateIPv4(ip: string): boolean {
  const p = ip.split('.').map(Number)
  if (p.length !== 4 || p.some((n) => Number.isNaN(n))) return false
  if (p[0] === 10) return true
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true
  if (p[0] === 192 && p[1] === 168) return true
  if (p[0] === 169 && p[1] === 254) return true // link-local
  if (p[0] === 127) return true
  return false
}

export function isMulticastOrBroadcast(ip: string): boolean {
  if (ip === '255.255.255.255') return true
  const first = Number(ip.split('.')[0])
  if (first >= 224 && first <= 239) return true // IPv4 multicast
  if (ip.startsWith('ff')) return true // IPv6 multicast
  return false
}

/** Read an ASCII string, replacing non-printables with '.'. */
export function asciiPreview(buf: Buffer, max = 256): string {
  const n = Math.min(buf.length, max)
  let s = ''
  for (let i = 0; i < n; i++) {
    const c = buf[i]
    s += c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : '.'
  }
  return s
}
