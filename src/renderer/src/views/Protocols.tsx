import { useState } from 'react'
import { AlertTriangle } from 'lucide-react'
import { navigate, useStore } from '../store'
import { PageHeader } from '../components/ui'

type Tab = 'dns' | 'http' | 'tls'

export function Protocols(): JSX.Element {
  const analysis = useStore((s) => s.analysis)
  const [tab, setTab] = useState<Tab>('dns')

  if (!analysis) {
    return (
      <div className="flex h-full flex-col">
        <PageHeader title="Protocols" />
        <div className="flex-1 px-6 py-5 text-sm text-text-secondary">No capture loaded.</div>
      </div>
    )
  }

  const { dns, http, tls } = analysis.summaries
  const tabs: { id: Tab; label: string; count: number }[] = [
    { id: 'dns', label: 'DNS', count: dns.length },
    { id: 'http', label: 'HTTP', count: http.length },
    { id: 'tls', label: 'TLS', count: tls.length }
  ]

  return (
    <div className="flex h-full flex-col">
      <PageHeader title="Protocols" subtitle="Application-layer breakdown" />
      <div className="border-b border-border-subtle px-6">
        <div className="flex gap-1">
          {tabs.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={[
                'border-b-2 px-4 py-2.5 text-sm font-medium transition-colors',
                tab === t.id
                  ? 'border-accent text-text-primary'
                  : 'border-transparent text-text-secondary hover:text-text-primary'
              ].join(' ')}
            >
              {t.label}
              <span className="ml-1.5 text-xs text-text-muted">{t.count}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 overflow-auto px-6 py-4">
        {tab === 'dns' && <DnsTable dns={dns} />}
        {tab === 'http' && <HttpTable http={http} />}
        {tab === 'tls' && <TlsTable tls={tls} />}
      </div>
    </div>
  )
}

function DnsTable({ dns }: { dns: import('@shared/types').DnsSummaryEntry[] }): JSX.Element {
  if (dns.length === 0) return <Empty text="No DNS traffic in this capture." />
  return (
    <table className="w-full border-collapse text-sm">
      <THead cols={['Domain', 'Types', 'Response', 'Count', 'Resolved to']} />
      <tbody>
        {dns.map((d, i) => (
          <tr key={i} className="border-b border-border-subtle hover:bg-bg-hover">
            <td className="max-w-md truncate py-2 pr-3 font-mono text-xs text-text-primary">
              {d.suspicious && (
                <AlertTriangle className="mr-1 inline h-3.5 w-3.5 text-sev-high" />
              )}
              {d.name}
            </td>
            <td className="py-2 pr-3 text-xs text-text-secondary">{d.types.join(', ')}</td>
            <td className="py-2 pr-3 text-xs">
              {d.responseCodes.map((rc) => (
                <span
                  key={rc}
                  className={rc === 'NXDOMAIN' ? 'text-sev-medium' : 'text-text-secondary'}
                >
                  {rc}{' '}
                </span>
              ))}
            </td>
            <td className="py-2 pr-3 text-xs tabular-nums text-text-secondary">{d.count}</td>
            <td className="py-2 font-mono text-xs text-text-secondary">
              {d.addresses.slice(0, 3).join(', ')}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function HttpTable({ http }: { http: import('@shared/types').HttpSummaryEntry[] }): JSX.Element {
  if (http.length === 0) return <Empty text="No cleartext HTTP requests in this capture." />
  return (
    <table className="w-full border-collapse text-sm">
      <THead cols={['Method', 'Host', 'Path', 'User-Agent', 'Auth', '']} />
      <tbody>
        {http.map((h, i) => (
          <tr key={i} className="border-b border-border-subtle hover:bg-bg-hover">
            <td className="py-2 pr-3 font-mono text-xs font-semibold text-accent">{h.method}</td>
            <td className="py-2 pr-3 font-mono text-xs text-text-primary">{h.host}</td>
            <td className="max-w-xs truncate py-2 pr-3 font-mono text-xs text-text-secondary">
              {h.path}
            </td>
            <td className="max-w-[12rem] truncate py-2 pr-3 text-xs text-text-muted">
              {h.userAgent ?? '—'}
            </td>
            <td className="py-2 pr-3 text-xs">
              {h.hasBasicAuth ? (
                <span className="rounded border border-sev-critical/30 bg-sev-critical/10 px-1.5 py-0.5 text-sev-critical">
                  Basic
                </span>
              ) : (
                <span className="text-text-muted">—</span>
              )}
            </td>
            <td className="py-2 text-right">
              <button
                onClick={() => navigate('packets', h.packetNumber)}
                className="text-xs text-accent hover:underline"
              >
                #{h.packetNumber}
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function TlsTable({ tls }: { tls: import('@shared/types').TlsSummaryEntry[] }): JSX.Element {
  if (tls.length === 0) return <Empty text="No TLS handshakes in this capture." />
  return (
    <table className="w-full border-collapse text-sm">
      <THead cols={['Server Name (SNI)', 'Version', 'Cipher suites', '', '']} />
      <tbody>
        {tls.map((t, i) => (
          <tr key={i} className="border-b border-border-subtle hover:bg-bg-hover">
            <td className="py-2 pr-3 font-mono text-xs text-text-primary">{t.sni ?? '—'}</td>
            <td className="py-2 pr-3 text-xs">
              <span className={t.weak ? 'text-sev-high' : 'text-text-secondary'}>{t.version}</span>
            </td>
            <td className="py-2 pr-3 text-xs tabular-nums text-text-secondary">
              {t.cipherSuites.length} offered
            </td>
            <td className="py-2 pr-3 text-xs">
              {t.weak && (
                <span className="inline-flex items-center gap-1 rounded border border-sev-high/30 bg-sev-high/10 px-1.5 py-0.5 text-sev-high">
                  <AlertTriangle className="h-3 w-3" /> Weak
                </span>
              )}
            </td>
            <td className="py-2 text-right">
              <button
                onClick={() => navigate('packets', t.packetNumber)}
                className="text-xs text-accent hover:underline"
              >
                #{t.packetNumber}
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

function THead({ cols }: { cols: string[] }): JSX.Element {
  return (
    <thead className="sticky top-0 bg-bg-base">
      <tr className="border-b border-border text-left text-xs uppercase tracking-wide text-text-muted">
        {cols.map((c, i) => (
          <th key={i} className="py-2 pr-3 font-medium">
            {c}
          </th>
        ))}
      </tr>
    </thead>
  )
}

function Empty({ text }: { text: string }): JSX.Element {
  return <div className="py-10 text-center text-sm text-text-muted">{text}</div>
}
