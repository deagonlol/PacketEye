import type { Dissection, HttpInfo } from '../model'

const METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT']

function looksLikeHttp(payload: Buffer): 'request' | 'response' | null {
  if (payload.length < 5) return null
  const head = payload.toString('ascii', 0, Math.min(16, payload.length))
  if (head.startsWith('HTTP/')) return 'response'
  for (const m of METHODS) {
    if (head.startsWith(m + ' ')) return 'request'
  }
  return null
}

export function dissectHttp(d: Dissection, payload: Buffer, full: boolean): boolean {
  const kind = looksLikeHttp(payload)
  if (!kind) return false

  const text = payload.toString('latin1')
  const headerEnd = text.indexOf('\r\n\r\n')
  const headerBlock = headerEnd >= 0 ? text.slice(0, headerEnd) : text
  const bodyBlock = headerEnd >= 0 ? text.slice(headerEnd + 4) : ''
  const lines = headerBlock.split('\r\n')
  const startLine = lines[0] ?? ''

  const headers: Record<string, string> = {}
  for (let i = 1; i < lines.length; i++) {
    const idx = lines[i].indexOf(':')
    if (idx > 0) {
      headers[lines[i].slice(0, idx).trim().toLowerCase()] = lines[i].slice(idx + 1).trim()
    }
  }

  const http: HttpInfo = {
    kind,
    headers,
    hasBasicAuth: false
  }

  if (kind === 'request') {
    const [method, path] = startLine.split(' ')
    http.method = method
    http.path = path
    http.host = headers['host']
    http.userAgent = headers['user-agent']
    http.cookie = headers['cookie']

    const auth = headers['authorization']
    if (auth && /^basic\s+/i.test(auth)) {
      http.hasBasicAuth = true
      try {
        http.basicAuthDecoded = Buffer.from(auth.replace(/^basic\s+/i, ''), 'base64').toString('utf-8')
      } catch {
        /* ignore */
      }
    }
    if (method === 'POST' && /pass(word|wd)?=|pwd=|login=|user(name)?=/i.test(bodyBlock)) {
      http.passwordLikeBody = true
      http.bodyPreview = bodyBlock.slice(0, 200)
    }
    d.protocol = 'HTTP'
    d.info = `${method} ${path}${http.host ? ` (${http.host})` : ''}`
  } else {
    const m = /^HTTP\/\d\.\d\s+(\d{3})\s*(.*)$/.exec(startLine)
    if (m) http.status = Number(m[1])
    d.protocol = 'HTTP'
    d.info = `Response ${http.status ?? ''}`.trim()
  }

  d.http = http

  if (full) {
    const fields = [{ label: kind === 'request' ? 'Request' : 'Status', value: startLine }]
    if (http.host) fields.push({ label: 'Host', value: http.host })
    if (http.userAgent) fields.push({ label: 'User-Agent', value: http.userAgent })
    if (http.hasBasicAuth)
      fields.push({ label: 'Authorization', value: `Basic (decoded: ${http.basicAuthDecoded ?? '?'})` })
    if (http.cookie) fields.push({ label: 'Cookie', value: http.cookie })
    if (http.passwordLikeBody && http.bodyPreview)
      fields.push({ label: 'Body', value: http.bodyPreview })
    d.layers.push({ name: 'HTTP', summary: d.info, fields })
  }
  return true
}
