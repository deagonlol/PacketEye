import { useCallback, useEffect, useReducer, useRef, useState } from 'react'
import type { PacketSummary } from '@shared/types'

const PAGE = 300

export interface PacketData {
  total: number
  filtered: number
  loading: boolean
  get: (index: number) => PacketSummary | undefined
  ensureRange: (start: number, end: number) => void
}

/**
 * Windowed packet fetching over IPC. The full filtered list is never loaded at
 * once — pages are fetched on demand as rows scroll into view and cached by
 * their index within the filtered result set.
 */
export function usePacketData(filter: string): PacketData {
  const [counts, setCounts] = useState({ total: 0, filtered: 0 })
  const [loading, setLoading] = useState(true)
  const cache = useRef<Map<number, PacketSummary>>(new Map())
  const pending = useRef<Set<number>>(new Set())
  const [, force] = useReducer((x: number) => x + 1, 0)
  const filterRef = useRef(filter)
  filterRef.current = filter

  useEffect(() => {
    let cancelled = false
    cache.current.clear()
    pending.current.clear()
    setLoading(true)
    window.packeteye
      .getPacketPage({ offset: 0, limit: PAGE, filter })
      .then((page) => {
        if (cancelled) return
        setCounts({ total: page.total, filtered: page.filtered })
        page.packets.forEach((p, i) => cache.current.set(i, p))
        setLoading(false)
        force()
      })
      .catch(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [filter])

  const ensureRange = useCallback((start: number, end: number) => {
    const firstPage = Math.max(0, Math.floor(start / PAGE))
    const lastPage = Math.floor(end / PAGE)
    const f = filterRef.current
    for (let pg = firstPage; pg <= lastPage; pg++) {
      const base = pg * PAGE
      if (cache.current.has(base) || pending.current.has(pg)) continue
      pending.current.add(pg)
      window.packeteye
        .getPacketPage({ offset: base, limit: PAGE, filter: f })
        .then((page) => {
          if (filterRef.current !== f) return
          page.packets.forEach((p, i) => cache.current.set(base + i, p))
          pending.current.delete(pg)
          force()
        })
        .catch(() => pending.current.delete(pg))
    }
  }, [])

  const get = useCallback((index: number) => cache.current.get(index), [])

  return { total: counts.total, filtered: counts.filtered, loading, get, ensureRange }
}
