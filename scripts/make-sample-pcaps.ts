// Generates synthetic .pcap fixtures with known-good and known-bad traffic.
// Run: npm run make-samples  → writes into ./samples
import { mkdirSync } from 'fs'
import { join } from 'path'
import { buildMixedCapture } from './scenarios'

const OUT = join(process.cwd(), 'samples')

function main(): void {
  mkdirSync(OUT, { recursive: true })

  const mixed = buildMixedCapture()
  mixed.write(join(OUT, 'mixed-threats.pcap'))
  console.log(`mixed-threats.pcap: ${mixed.count} packets`)

  console.log('Samples written to', OUT)
}

main()
