import { useState } from 'react'
import { Eye, EyeOff, Check, ExternalLink } from 'lucide-react'
import { useStore, updateSettings } from '../store'
import { PageHeader } from '../components/ui'
import type { GroqModel } from '@shared/types'

const MODELS: { id: GroqModel; label: string; hint: string }[] = [
  {
    id: 'llama-3.1-8b-instant',
    label: 'Llama 3.1 8B Instant',
    hint: 'Cheapest & fastest. Great default for most captures.'
  },
  {
    id: 'llama-3.3-70b-versatile',
    label: 'Llama 3.3 70B Versatile',
    hint: 'Stronger reasoning for complex captures. Costs more.'
  }
]

export function SettingsView(): JSX.Element {
  const settings = useStore((s) => s.settings)
  const [showKey, setShowKey] = useState(false)
  const [keyDraft, setKeyDraft] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  if (!settings) return <div className="p-6 text-sm text-text-secondary">Loading…</div>

  const keyValue = keyDraft ?? settings.groqApiKey

  async function saveKey(): Promise<void> {
    await updateSettings({ groqApiKey: keyValue })
    setKeyDraft(null)
    setSaved(true)
    setTimeout(() => setSaved(false), 1500)
  }

  return (
    <div className="flex h-full flex-col">
      <PageHeader title="Settings" subtitle="Configure the AI provider and privacy options." />
      <div className="flex-1 overflow-y-auto px-6 py-5">
        <div className="mx-auto max-w-2xl space-y-6">
          {/* API key */}
          <section className="card p-5">
            <h2 className="text-sm font-semibold text-text-primary">Groq API Key</h2>
            <p className="mt-1 text-xs text-text-secondary">
              PacketEye uses Groq for fast, low-cost AI analysis. Your key is stored locally on
              this machine and only sent to Groq's API.
            </p>
            <div className="mt-3 flex gap-2">
              <div className="relative flex-1">
                <input
                  type={showKey ? 'text' : 'password'}
                  className="input pr-10 font-mono"
                  placeholder="gsk_…"
                  value={keyValue}
                  onChange={(e) => setKeyDraft(e.target.value)}
                />
                <button
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-primary"
                  onClick={() => setShowKey((v) => !v)}
                  type="button"
                >
                  {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              <button className="btn-primary" onClick={() => void saveKey()}>
                {saved ? <Check className="h-4 w-4" /> : null}
                {saved ? 'Saved' : 'Save'}
              </button>
            </div>
            <a
              href="https://console.groq.com/keys"
              target="_blank"
              rel="noreferrer"
              className="mt-2 inline-flex items-center gap-1 text-xs text-accent hover:underline"
            >
              Get a free Groq API key <ExternalLink className="h-3 w-3" />
            </a>
          </section>

          {/* Model */}
          <section className="card p-5">
            <h2 className="text-sm font-semibold text-text-primary">Model</h2>
            <div className="mt-3 space-y-2">
              {MODELS.map((m) => {
                const active = settings.model === m.id
                return (
                  <button
                    key={m.id}
                    onClick={() => void updateSettings({ model: m.id })}
                    className={[
                      'flex w-full items-start gap-3 rounded-lg border p-3 text-left transition-colors',
                      active
                        ? 'border-accent bg-accent/10'
                        : 'border-border-subtle bg-bg-base hover:bg-bg-hover'
                    ].join(' ')}
                  >
                    <div
                      className={[
                        'mt-0.5 flex h-4 w-4 items-center justify-center rounded-full border',
                        active ? 'border-accent' : 'border-border'
                      ].join(' ')}
                    >
                      {active && <div className="h-2 w-2 rounded-full bg-accent" />}
                    </div>
                    <div>
                      <div className="text-sm font-medium text-text-primary">{m.label}</div>
                      <div className="text-xs text-text-secondary">{m.hint}</div>
                    </div>
                  </button>
                )
              })}
            </div>
          </section>

          {/* Privacy */}
          <section className="card p-5">
            <h2 className="text-sm font-semibold text-text-primary">Privacy</h2>
            <label className="mt-3 flex cursor-pointer items-start gap-3">
              <input
                type="checkbox"
                className="mt-0.5 h-4 w-4 accent-accent"
                checked={settings.redactPayloads}
                onChange={(e) => void updateSettings({ redactPayloads: e.target.checked })}
              />
              <div>
                <div className="text-sm font-medium text-text-primary">Redact payload details</div>
                <div className="text-xs text-text-secondary">
                  Strip full URLs, DNS subdomains, and payload snippets from the summary sent to
                  the AI. Metadata and findings are still included.
                </div>
              </div>
            </label>
          </section>
        </div>
      </div>
    </div>
  )
}
