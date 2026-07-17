import {
  Area,
  AreaChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  CartesianGrid
} from 'recharts'
import type { TimeBucket } from '@shared/types'
import { formatBytes } from '../lib/format'

const ACCENT = '#1f6fae'

/** Traffic volume over the capture duration — one measure, single hue area. */
export function TrafficChart({ data }: { data: TimeBucket[] }): JSX.Element {
  const chartData = data.map((b) => ({
    t: b.timeOffset,
    bytes: b.bytes,
    packets: b.packets
  }))

  return (
    <ResponsiveContainer width="100%" height={200}>
      <AreaChart data={chartData} margin={{ top: 8, right: 12, bottom: 4, left: 4 }}>
        <defs>
          <linearGradient id="trafficFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={ACCENT} stopOpacity={0.35} />
            <stop offset="100%" stopColor={ACCENT} stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="#d6d9dc" vertical={false} />
        <XAxis
          dataKey="t"
          tickFormatter={(v) => `${Number(v).toFixed(0)}s`}
          stroke="#77818a"
          tick={{ fontSize: 11, fill: '#77818a' }}
          tickLine={false}
          axisLine={{ stroke: '#d6d9dc' }}
          minTickGap={40}
        />
        <YAxis
          stroke="#77818a"
          tick={{ fontSize: 11, fill: '#77818a' }}
          tickLine={false}
          axisLine={false}
          width={54}
          tickFormatter={(v) => formatBytes(Number(v))}
        />
        <Tooltip
          contentStyle={{
            background: '#ffffff',
            border: '1px solid #b8bdc2',
            borderRadius: 3,
            fontSize: 12
          }}
          labelStyle={{ color: '#4f5a63' }}
          labelFormatter={(v) => `t = ${Number(v).toFixed(3)}s`}
          formatter={(value: number, name: string) =>
            name === 'bytes'
              ? [formatBytes(value), 'Bytes']
              : [value.toLocaleString(), 'Packets']
          }
        />
        <Area
          type="monotone"
          dataKey="bytes"
          stroke={ACCENT}
          strokeWidth={2}
          fill="url(#trafficFill)"
          dot={false}
          activeDot={{ r: 3, fill: ACCENT }}
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}
