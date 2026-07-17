import { app } from 'electron'
import { readFileSync, writeFileSync, existsSync } from 'fs'
import { join } from 'path'
import type { AppSettings } from '../shared/types'

const DEFAULTS: AppSettings = {
  groqApiKey: '',
  model: 'llama-3.1-8b-instant',
  redactPayloads: false
}

function settingsPath(): string {
  return join(app.getPath('userData'), 'settings.json')
}

let cache: AppSettings | null = null

export function getSettings(): AppSettings {
  if (cache) return cache
  try {
    const p = settingsPath()
    if (existsSync(p)) {
      const parsed = JSON.parse(readFileSync(p, 'utf-8'))
      cache = { ...DEFAULTS, ...parsed }
    } else {
      cache = { ...DEFAULTS }
    }
  } catch {
    cache = { ...DEFAULTS }
  }
  return cache!
}

export function setSettings(partial: Partial<AppSettings>): AppSettings {
  const next = { ...getSettings(), ...partial }
  cache = next
  try {
    writeFileSync(settingsPath(), JSON.stringify(next, null, 2), 'utf-8')
  } catch (err) {
    console.error('Failed to persist settings', err)
  }
  return next
}

// ---- Recent files (stored alongside settings) ----
const RECENT_LIMIT = 8

function recentPath(): string {
  return join(app.getPath('userData'), 'recent.json')
}

export function getRecentFiles(): string[] {
  try {
    const p = recentPath()
    if (existsSync(p)) return JSON.parse(readFileSync(p, 'utf-8'))
  } catch {
    /* ignore */
  }
  return []
}

export function addRecentFile(path: string): void {
  try {
    let list = getRecentFiles().filter((x) => x !== path)
    list.unshift(path)
    list = list.slice(0, RECENT_LIMIT)
    writeFileSync(recentPath(), JSON.stringify(list, null, 2), 'utf-8')
  } catch {
    /* ignore */
  }
}
