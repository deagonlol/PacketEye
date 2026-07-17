// Message protocol between the main process (capture-service) and the parser worker.
import type {
  CaptureAnalysis,
  PacketDetail,
  PacketPage,
  PacketQuery,
  ParseProgress
} from '../../shared/types'

export type MainToWorker =
  | { type: 'parse'; path: string }
  | { type: 'getPage'; requestId: number; query: PacketQuery }
  | { type: 'getDetail'; requestId: number; packetNumber: number }

export type WorkerToMain =
  | { type: 'progress'; progress: ParseProgress }
  | { type: 'ready'; analysis: CaptureAnalysis }
  | { type: 'error'; message: string }
  | { type: 'page'; requestId: number; page: PacketPage }
  | { type: 'detail'; requestId: number; detail: PacketDetail | null }
