import { createGroq } from '@ai-sdk/groq'
import { streamText } from 'ai'
import type { AppSettings, CaptureDigest, ChatMessage } from '../../shared/types'

const REPORT_SYSTEM = `You are a senior network security analyst writing a threat assessment of a packet capture.
You are given a JSON digest of the capture: metadata, protocol breakdown, top talkers, conversations, DNS/HTTP/TLS summaries, and a list of findings already produced by a deterministic detection engine. The findings and their severities are authoritative — do not downgrade or invent severities, but you may add expert context.

Write clear, well-structured GitHub-flavored Markdown with these sections:

## Executive Summary
2-4 sentences a non-expert can understand: is this capture concerning, and why.

## Threat Assessment
For each finding (most severe first), a subsection with: what it means in plain language, why it matters, the concrete evidence from the digest, and the relevant MITRE ATT&CK tactic/technique where applicable.

## Remediation Plan
Prioritized, actionable steps to fix the issues found.

## Hardening Recommendations
General improvements to secure this network's communications going forward.

Be specific to the data. Reference real hosts, domains, and ports from the digest. Do not fabricate findings that aren't supported by the data. Keep it focused and skimmable.`

const CHAT_SYSTEM = `You are a network security assistant embedded in a packet-capture analyzer.
Answer the user's questions about the loaded capture using the provided JSON digest and, if present, the prior AI report. Be concrete and cite hosts, domains, ports, and findings from the digest. If the digest doesn't contain the answer, say so plainly rather than guessing. Keep answers concise and use Markdown.`

function makeModel(settings: AppSettings): ReturnType<ReturnType<typeof createGroq>> {
  const groq = createGroq({ apiKey: settings.groqApiKey })
  return groq(settings.model)
}

export async function streamReport(
  digest: CaptureDigest,
  settings: AppSettings,
  signal: AbortSignal
): Promise<AsyncIterable<string>> {
  const result = streamText({
    model: makeModel(settings),
    system: REPORT_SYSTEM,
    prompt: `Here is the capture digest as JSON:\n\n\`\`\`json\n${JSON.stringify(
      digest,
      null,
      2
    )}\n\`\`\`\n\nWrite the full threat assessment report now.`,
    abortSignal: signal,
    temperature: 0.3,
    maxTokens: 2600
  })
  return result.textStream
}

export async function streamChat(
  digest: CaptureDigest,
  messages: ChatMessage[],
  settings: AppSettings,
  signal: AbortSignal
): Promise<AsyncIterable<string>> {
  const context = `Capture digest (JSON):\n\`\`\`json\n${JSON.stringify(digest)}\n\`\`\``
  const result = streamText({
    model: makeModel(settings),
    system: `${CHAT_SYSTEM}\n\n${context}`,
    messages: messages.map((m) => ({ role: m.role, content: m.content })),
    abortSignal: signal,
    temperature: 0.4,
    maxTokens: 1400
  })
  return result.textStream
}
