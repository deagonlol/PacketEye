// Parser worker entry. Runs in a Node worker_thread. Streaming parse + analysis
// is implemented in the capture pipeline modules; this file wires the message
// protocol to that pipeline.
import { parentPort } from 'worker_threads'
import type { MainToWorker, WorkerToMain } from './protocol'
import { runParse } from './pipeline'
import { PacketStore } from './packet-store'

const store = new PacketStore()

function post(msg: WorkerToMain): void {
  parentPort?.postMessage(msg)
}

parentPort?.on('message', async (msg: MainToWorker) => {
  try {
    switch (msg.type) {
      case 'parse': {
        await runParse(msg.path, store, post)
        break
      }
      case 'getPage': {
        post({ type: 'page', requestId: msg.requestId, page: store.getPage(msg.query) })
        break
      }
      case 'getDetail': {
        const detail = await store.getDetail(msg.packetNumber)
        post({ type: 'detail', requestId: msg.requestId, detail })
        break
      }
    }
  } catch (err) {
    post({ type: 'error', message: err instanceof Error ? err.message : String(err) })
  }
})
