import { describe, it, expect } from 'vitest'
import { analyzeCapture } from './analyze-capture'
import { detectFormat } from './reader'
import { buildMixedCapture } from '../../../scripts/scenarios'

describe('parser robustness', () => {
  it('rejects an empty buffer', () => {
    expect(detectFormat(Buffer.alloc(0))).toBeNull()
    expect(() => analyzeCapture(Buffer.alloc(0), { fileName: 'empty' })).toThrow(/not a recognized/i)
  })

  it('rejects random garbage as not a capture', () => {
    const garbage = Buffer.from('this is definitely not a pcap file, just text.', 'utf-8')
    expect(() => analyzeCapture(garbage, { fileName: 'garbage' })).toThrow()
  })

  it('parses a valid header with no packets without crashing', () => {
    const full = buildMixedCapture().toBuffer()
    const headerOnly = full.subarray(0, 24) // global header, zero records
    const { analysis } = analyzeCapture(headerOnly, { fileName: 'headeronly' })
    expect(analysis.stats.packetCount).toBe(0)
    expect(analysis.findings).toEqual([])
  })

  it('tolerates a truncated final record (stops cleanly)', () => {
    const full = buildMixedCapture().toBuffer()
    // Cut mid-way through the capture so the last record is incomplete.
    const truncated = full.subarray(0, Math.floor(full.length * 0.6))
    const { analysis, packetSummaries } = analyzeCapture(truncated, { fileName: 'trunc' })
    expect(packetSummaries.length).toBeGreaterThan(0)
    expect(packetSummaries.length).toBeLessThan(buildMixedCapture().count)
    // Whatever parsed should still be internally consistent.
    expect(analysis.stats.packetCount).toBe(packetSummaries.length)
  })

  it('does not throw on a corrupt record length', () => {
    const full = Buffer.from(buildMixedCapture().toBuffer())
    // Corrupt the first record's captured-length field (offset 24 + 8).
    full.writeUInt32LE(0xffffffff, 32)
    expect(() => analyzeCapture(full, { fileName: 'corrupt' })).not.toThrow()
  })
})
