# PacketEye

AI-powered network traffic analyzer — a Wireshark-style **desktop app** that opens a
`.pcap`/`.pcapng` capture, dissects it locally, runs a deterministic threat-detection
engine, and layers an AI threat report and chat on top.

Everything is parsed **on your machine**. Only a compact, few-KB summary — never raw
packets — is ever sent to the AI.

## Features

- **Threat detection** — cleartext credentials (Telnet/FTP/HTTP Basic/SNMP), insecure
  protocols, weak/obsolete TLS, port scans, host/ICMP sweeps, ARP spoofing, rogue DHCP,
  DNS tunneling, LLMNR/NBT-NS exposure, NXDOMAIN spikes, C2 beaconing, and more — each
  with severity, affected hosts, clickable packet evidence, remediation, and a MITRE
  ATT&CK reference.
- **Dashboard** — packet/byte/host/duration stats, findings-by-severity, protocol
  breakdown, traffic-over-time, and top talkers.
- **Conversations** — sortable/filterable 5-tuple flow table with TCP state.
- **Protocols** — DNS / HTTP / TLS breakdowns (queried domains + NXDOMAINs, requests with
  methods/hosts/UAs, SNIs with versions/ciphers).
- **Packets** — virtualized Wireshark-style table with a display filter, a decoded layer
  tree, and a hex/ASCII dump.
- **AI Report** — a streamed, sectioned Markdown threat assessment (Groq). Exportable to
  Markdown (findings + AI assessment).
- **Chat** — ask follow-up questions about the capture.

## Stack

Electron + electron-vite + React 19 + TypeScript + Tailwind. A pure-TypeScript
pcap/pcapng parser and dissectors (no `tshark`/`libpcap` dependency) run in a Node worker
thread. AI via the Vercel AI SDK + `@ai-sdk/groq`, called from the main process so the
API key never reaches the renderer.

## Getting started

```bash
npm install
npm run make-samples   # writes synthetic test captures into ./samples
npm run dev            # launch the app (electron-vite)
```

Open `samples/mixed-threats.pcap` to see the full range of detections on a synthetic
capture with planted threats.

### AI (optional)

The report and chat use [Groq](https://console.groq.com/keys) (cheapest/fastest, bring
your own key). Open **Settings**, paste your `gsk_…` key, pick a model
(`llama-3.1-8b-instant` by default), and optionally enable payload redaction. Detection
and all inspection features work fully without a key.

## Scripts

| Script | What it does |
|--------|--------------|
| `npm run dev` | Launch the app in development |
| `npm run build` | Build main/preload/renderer bundles |
| `npm test` | Run the Vitest suite (parser, detection, robustness, report, AI wiring) |
| `npm run make-samples` | Generate synthetic `.pcap` fixtures in `./samples` |
| `npm run make-fixture` | Regenerate the browser-preview data fixture |
| `npm run dist` | Package installers via electron-builder |

## Architecture

```
Main process   window/menu, file dialogs, settings (userData/settings.json),
               Groq streaming over IPC, Markdown report export
Parser worker  streaming pcap/pcapng parse; owns the packet index, flow table,
               stats, app-layer summaries, and findings; answers paged/filtered
               packet queries and lazy hex/detail by file offset
Renderer       sandboxed React UI (contextIsolation on) via a typed preload bridge
```

Source layout:

- `src/shared/pcap/` — readers (`parse.ts`, `reader.ts`), dissectors (`dissect/`), flow
  tracker (`flows.ts`), stats (`analyze.ts`), and the pure analysis core
  (`analyze-capture.ts`).
- `src/shared/detect/` — the deterministic detection rules (`rules.ts`).
- `src/main/` — window/IPC (`index.ts`), worker host (`capture-service.ts`), settings,
  report export, and AI (`ai/`).
- `src/renderer/src/` — the React app (`views/`, `components/`, `store.ts`).
- `scripts/` — synthetic capture generator (`scenarios.ts`, `make-sample-pcaps.ts`).

### Browser preview

`npm run make-fixture` writes `src/renderer/src/lib/sample-analysis.json`, letting the
renderer UI run in a plain browser (`vite --config vite.preview.config.ts`) against real
analysis data via a mock of the preload API — handy for fast UI iteration without
launching Electron.

### Next Steps

Add a real time network traffic analyser to mitigate threats in real time as they happen.
