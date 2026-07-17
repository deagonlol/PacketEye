import { FileText, ArrowUpRight, ShieldAlert, ShieldCheck, Activity, Clock3, HardDrive, Network } from 'lucide-react'
import { navigate, useStore } from '../store'
import { PageHeader } from '../components/ui'
import { BarList, type BarItem } from '../components/BarList'
import { TrafficChart } from '../components/TrafficChart'
import { SeveritySummary } from '../components/SeveritySummary'
import { formatBytes, formatDuration, formatNumber, getScanHealth, SEVERITY_COLOR, SEVERITY_LABEL, SEVERITY_ORDER } from '../lib/format'

export function Dashboard(): JSX.Element {
  const analysis = useStore((s) => s.analysis)
  const fileName = useStore((s) => s.fileName)

  if (!analysis) {
    return (
      <div className="flex h-full flex-col">
        <PageHeader title="Dashboard" />
        <div className="flex-1 px-6 py-5 text-sm text-text-secondary">No capture loaded.</div>
      </div>
    )
  }

  const { stats, findings } = analysis
  const health = getScanHealth(findings)
  const HealthIcon = health.level === 'healthy' || health.level === 'info' ? ShieldCheck : ShieldAlert

  // Protocol breakdown: top 8 + Other, single-hue bars, click → filtered packets.
  const proto = stats.protocolHierarchy
  const topProto = proto.slice(0, 8)
  const otherPackets = proto.slice(8).reduce((s, p) => s + p.packets, 0)
  const protoItems: BarItem[] = topProto.map((p) => ({
    label: p.protocol,
    value: p.packets,
    display: `${formatNumber(p.packets)} (${((p.packets / stats.packetCount) * 100).toFixed(1)}%)`,
    onClick: () => navigate('packets', undefined)
  }))
  if (otherPackets > 0) {
    protoItems.push({
      label: 'Other',
      value: otherPackets,
      display: formatNumber(otherPackets)
    })
  }

  const talkerItems: BarItem[] = stats.topTalkers.slice(0, 8).map((t) => ({
    label: t.addr,
    value: t.bytes,
    display: formatBytes(t.bytes),
    sublabel: `${formatNumber(t.packets)} packets`
  }))

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="Dashboard"
        subtitle={fileName ?? undefined}
        actions={
          <button className="btn-ghost" onClick={() => navigate('report')}>
            <FileText className="h-4 w-4" />
            AI Report
          </button>
        }
      />
      <div className="flex-1 overflow-y-auto px-7 py-6">
        <div className="mx-auto max-w-[1240px] space-y-5">
          <section className="grid gap-4 xl:grid-cols-[1.25fr_0.75fr]">
            <div className="card relative overflow-hidden border-l-4 p-6" style={{ borderLeftColor: health.color }}>
              <div className="relative flex h-full flex-col justify-between gap-8">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="eyebrow">Investigation status</div>
                    <div className="mt-3 flex items-center gap-3">
                      <span className="h-3.5 w-3.5 rounded-full shadow-[inset_0_0_0_1px_rgba(0,0,0,0.14)]" style={{ backgroundColor: health.color }} />
                      <h2 className="text-[30px] font-bold tracking-[-0.04em]" style={{ color: health.color }}>{health.label}</h2>
                    </div>
                    <p className="mt-2 max-w-xl text-sm leading-6 text-text-secondary">
                      {health.description} {findings.length > 0 ? `${findings.length} total finding${findings.length === 1 ? '' : 's'} in this capture.` : 'You can continue with packet or conversation inspection.'}
                    </p>
                  </div>
                  <div className="rounded-[3px] border p-3" style={{ color: health.color, backgroundColor: health.surface, borderColor: health.border }}><HealthIcon className="h-6 w-6" /></div>
                </div>
                <div className="flex flex-wrap items-center gap-3">
                  <button className="btn-primary" onClick={() => navigate(findings.length ? 'findings' : 'packets')}>{findings.length ? `Review ${findings.length} finding${findings.length === 1 ? '' : 's'}` : 'Inspect packets'} <ArrowUpRight className="h-4 w-4" /></button>
                  <button className="btn-ghost" onClick={() => navigate('report')}><FileText className="h-4 w-4" /> Generate report</button>
                </div>
              </div>
            </div>

            <div className="card p-5">
              <div className="flex items-center justify-between">
                <div><div className="eyebrow">Threat distribution</div><h2 className="mt-1.5 text-base font-bold text-text-primary">Signals by severity</h2></div>
                <span className="rounded-full border border-border-subtle bg-bg-base px-2.5 py-1 text-[10px] font-semibold text-text-muted">{findings.length} total</span>
              </div>
              <div className="mt-5"><SeveritySummary findings={findings} onSelect={() => navigate('findings')} compact /></div>
              <div className="mt-4 border-t border-border-subtle pt-3">
                <div className="mb-1.5 flex items-center justify-between text-[9px] font-medium uppercase tracking-wide text-text-muted"><span>Healthy</span><span>Critical</span></div>
                <div className="flex h-2 overflow-hidden rounded-full border border-border-subtle">
                  <span className="flex-1" style={{ backgroundColor: '#218739' }} />
                  {[...SEVERITY_ORDER].reverse().map((severity) => <span key={severity} className="flex-1" style={{ backgroundColor: SEVERITY_COLOR[severity] }} title={SEVERITY_LABEL[severity]} />)}
                </div>
              </div>
            </div>
          </section>

          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <Metric icon={<Activity />} label="Packets" value={formatNumber(stats.packetCount)} hint="frames inspected" />
            <Metric icon={<HardDrive />} label="Data volume" value={formatBytes(stats.totalBytes)} hint="on the wire" />
            <Metric icon={<Clock3 />} label="Duration" value={formatDuration(stats.durationSec)} hint="capture window" />
            <Metric icon={<Network />} label="Unique hosts" value={formatNumber(stats.hostCount)} hint="endpoints seen" />
          </div>

          <section className="card p-5">
            <div className="mb-2 flex items-center justify-between">
              <div><div className="eyebrow">Traffic pulse</div><h2 className="mt-1.5 text-base font-bold text-text-primary">Volume over time</h2></div>
              <div className="flex items-center gap-2 text-[10px] font-semibold text-text-muted"><span className="h-2 w-2 rounded-full bg-accent" />Bytes transferred</div>
            </div>
            <TrafficChart data={stats.timeline} />
          </section>

          <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
            <section className="card p-5">
              <div className="mb-4 flex items-center justify-between"><div><div className="eyebrow">Composition</div><h2 className="mt-1.5 text-base font-bold text-text-primary">Protocol mix</h2></div><button className="text-xs font-semibold text-accent" onClick={() => navigate('protocols')}>Explore <ArrowUpRight className="ml-1 inline h-3 w-3" /></button></div>
              <BarList items={protoItems} />
            </section>
            <section className="card p-5">
              <div className="mb-4 flex items-center justify-between">
                <div><div className="eyebrow">Endpoints</div><h2 className="mt-1.5 text-base font-bold text-text-primary">Most active hosts</h2></div>
                <button
                  className="text-xs font-semibold text-accent"
                  onClick={() => navigate('conversations')}
                >
                  Explore <ArrowUpRight className="ml-1 inline h-3 w-3" />
                </button>
              </div>
              <BarList items={talkerItems} />
            </section>
          </div>
        </div>
      </div>
    </div>
  )
}

function Metric({ icon, label, value, hint }: { icon: JSX.Element; label: string; value: string; hint: string }): JSX.Element {
  return (
    <div className="card flex items-center gap-4 p-4">
      <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-accent/10 bg-accent/[0.07] text-accent [&>svg]:h-4 [&>svg]:w-4">{icon}</div>
      <div className="min-w-0"><div className="eyebrow">{label}</div><div className="mt-1 text-xl font-bold tracking-tight text-text-primary">{value}</div><div className="mt-0.5 text-[10px] text-text-muted">{hint}</div></div>
    </div>
  )
}
