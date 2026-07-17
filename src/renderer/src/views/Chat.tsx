import { useEffect, useRef, useState } from 'react'
import { Send, MessageSquare, AlertTriangle, Settings2 } from 'lucide-react'
import { navigate, sendChat, useStore } from '../store'
import { PageHeader } from '../components/ui'
import { Markdown } from '../components/Markdown'

const SUGGESTIONS = [
  'What are the most urgent issues in this capture?',
  'Explain the DNS tunneling finding in simple terms.',
  'Which hosts look compromised and why?',
  'What should I fix first to secure this network?'
]

export function Chat(): JSX.Element {
  const analysis = useStore((s) => s.analysis)
  const settings = useStore((s) => s.settings)
  const messages = useStore((s) => s.chatMessages)
  const streaming = useStore((s) => s.chatStreaming)
  const [input, setInput] = useState('')
  const scrollRef = useRef<HTMLDivElement>(null)

  const hasKey = !!settings?.groqApiKey

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight })
  }, [messages])

  function submit(text: string): void {
    const t = text.trim()
    if (!t || streaming || !hasKey) return
    void sendChat(t)
    setInput('')
  }

  if (!analysis) {
    return (
      <div className="flex h-full flex-col">
        <PageHeader title="Chat" />
        <div className="flex-1 px-6 py-5 text-sm text-text-secondary">No capture loaded.</div>
      </div>
    )
  }

  return (
    <div className="flex h-full flex-col">
      <PageHeader title="Chat" subtitle="Ask questions about this capture" />

      <div ref={scrollRef} className="flex-1 overflow-y-auto px-6 py-5">
        <div className="mx-auto max-w-3xl space-y-4">
          {!hasKey && (
            <div className="flex items-start gap-3 rounded-lg border border-sev-medium/30 bg-sev-medium/10 px-4 py-3">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-sev-medium" />
              <div className="flex-1 text-sm text-text-secondary">
                Add a Groq API key in Settings to chat about the capture.
              </div>
              <button className="btn-ghost !py-1" onClick={() => navigate('settings')}>
                <Settings2 className="h-3.5 w-3.5" />
                Settings
              </button>
            </div>
          )}

          {messages.length === 0 && (
            <div className="pt-6 text-center">
              <MessageSquare className="mx-auto mb-3 h-10 w-10 text-text-muted" />
              <p className="text-sm text-text-secondary">
                Ask anything about the loaded capture. The AI has access to a summary of the
                findings, protocols, and conversations.
              </p>
              {hasKey && (
                <div className="mx-auto mt-5 grid max-w-lg grid-cols-1 gap-2 sm:grid-cols-2">
                  {SUGGESTIONS.map((s) => (
                    <button
                      key={s}
                      onClick={() => submit(s)}
                      className="rounded-lg border border-border-subtle bg-bg-panel px-3 py-2 text-left text-xs text-text-secondary transition-colors hover:bg-bg-hover hover:text-text-primary"
                    >
                      {s}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}

          {messages.map((m, i) => (
            <div key={i} className={m.role === 'user' ? 'flex justify-end' : 'flex justify-start'}>
              <div
                className={
                  m.role === 'user'
                    ? 'max-w-[80%] rounded-2xl rounded-br-sm bg-accent px-4 py-2.5 text-sm text-white'
                    : 'max-w-[85%] rounded-2xl rounded-bl-sm border border-border-subtle bg-bg-panel px-4 py-3'
                }
              >
                {m.role === 'user' ? (
                  m.content
                ) : m.content ? (
                  <Markdown>{m.content}</Markdown>
                ) : (
                  <span className="inline-flex gap-1">
                    <Dot /> <Dot /> <Dot />
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="border-t border-border-subtle px-6 py-4">
        <div className="mx-auto flex max-w-3xl items-end gap-2">
          <textarea
            className="input max-h-32 flex-1 resize-none"
            rows={1}
            placeholder={hasKey ? 'Ask about this capture…' : 'Add a Groq API key in Settings first'}
            value={input}
            disabled={!hasKey || streaming}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault()
                submit(input)
              }
            }}
          />
          <button
            className="btn-primary h-[42px]"
            disabled={!hasKey || streaming || !input.trim()}
            onClick={() => submit(input)}
          >
            <Send className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  )
}

function Dot(): JSX.Element {
  return <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-text-muted" />
}
