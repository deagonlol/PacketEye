// Canonical IPC channel names, shared by main and preload.

export const IPC = {
  // invoke (renderer -> main, returns promise)
  openCaptureDialog: 'capture:openDialog',
  openCapturePath: 'capture:openPath',
  getPacketPage: 'capture:getPacketPage',
  getPacketDetail: 'capture:getPacketDetail',
  getSettings: 'settings:get',
  setSettings: 'settings:set',
  getDigest: 'ai:getDigest',
  runReport: 'ai:runReport', // starts a stream; returns requestId
  runChat: 'ai:runChat', // starts a stream; returns requestId
  cancelAi: 'ai:cancel',
  exportReport: 'report:export',
  getRecentFiles: 'capture:recent',

  // send (main -> renderer)
  parseProgress: 'capture:progress',
  captureReady: 'capture:ready',
  captureError: 'capture:error',
  aiChunk: 'ai:chunk',
  menuOpenCapture: 'menu:openCapture'
} as const

export type IpcChannel = (typeof IPC)[keyof typeof IPC]
