import { useState } from 'react'
import { Sparkles, Download, RefreshCw, AlertTriangle, Settings2 } from 'lucide-react'
import { navigate, runReport, useStore } from '../store'
import { PageHeader, EmptyState, Spinner } from '../components/ui'
import { Markdown } from '../components/Markdown'

export function Report(): JSX.Element {
  const analysis = useStore((s) => s.analysis)
  const settings = useStore((s) => s.settings)
  const text = useStore((s) => s.reportText)
  const streaming = useStore((s) => s.reportStreaming)
  const error = useStore((s) => s.reportError)
  const [exportMsg, setExportMsg] = useState<string | null>(null)

  const hasKey = !!settings?.groqApiKey
  const hasReport = text.trim().length > 0

  async function onExport(): Promise<void> {
    const path = await window.packeteye.exportReport(text)
    if (path) {
      setExportMsg(`Saved to ${path}`)
      setTimeout(() => setExportMsg(null), 4000)
    }
  }

  if (!analysis) {
    return (
      <div className="flex h-full flex-col">
        <PageHeader title="AI Report" />
        <div className="flex-1 px-6 py-5 text-sm text-text-secondary">No capture loaded.</div>
      </div>
    )
  }

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="AI Threat Report"
        subtitle="Generated from a compact summary of the capture"
        actions={
          <>
            {hasReport && !streaming && (
              <button className="btn-ghost" onClick={() => void onExport()}>
                <Download className="h-4 w-4" />
                Export
              </button>
            )}
            <button
              className="btn-primary"
              disabled={streaming || !hasKey}
              onClick={() => void runReport()}
            >
              {streaming ? (
                <Spinner className="h-4 w-4" />
              ) : hasReport ? (
                <RefreshCw className="h-4 w-4" />
              ) : (
                <Sparkles className="h-4 w-4" />
              )}
              {streaming ? 'Analyzing…' : hasReport ? 'Regenerate' : 'Run AI Analysis'}
            </button>
          </>
        }
      />

      <div className="flex-1 overflow-y-auto px-6 py-5">
        <div className="mx-auto max-w-3xl">
          {exportMsg && (
            <div className="mb-4 rounded-md border border-sev-low/30 bg-sev-low/10 px-3 py-2 text-xs text-sev-low">
              {exportMsg}
            </div>
          )}

          {!hasKey && (
            <div className="mb-4 flex items-start gap-3 rounded-lg border border-sev-medium/30 bg-sev-medium/10 px-4 py-3">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-sev-medium" />
              <div className="flex-1 text-sm text-text-secondary">
                Add a Groq API key in Settings to generate the AI report.
              </div>
              <button className="btn-ghost !py-1" onClick={() => navigate('settings')}>
                <Settings2 className="h-3.5 w-3.5" />
                Settings
              </button>
            </div>
          )}

          {error && (
            <div className="mb-4 rounded-md border border-sev-critical/30 bg-sev-critical/10 px-3 py-2 text-sm text-sev-critical">
              {error}
            </div>
          )}

          {hasReport ? (
            <div className="card p-6">
              <Markdown>{text}</Markdown>
              {streaming && (
                <span className="ml-0.5 inline-block h-4 w-2 animate-pulse bg-accent align-middle" />
              )}
            </div>
          ) : (
            !streaming && (
              <EmptyState
                icon={<Sparkles className="h-12 w-12 text-accent" />}
                title="Generate an AI threat assessment"
                message="The AI reviews the capture's findings, protocols, and conversations, then writes a prioritized threat report with remediation guidance. Only a compact summary — never raw packets — is sent to Groq."
                action={
                  hasKey ? (
                    <button className="btn-primary" onClick={() => void runReport()}>
                      <Sparkles className="h-4 w-4" />
                      Run AI Analysis
                    </button>
                  ) : undefined
                }
              />
            )
          )}
        </div>
      </div>
    </div>
  )
}
