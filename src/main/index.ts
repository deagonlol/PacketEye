import { app, shell, BrowserWindow, ipcMain, dialog, Menu } from 'electron'
import { join } from 'path'
import { IPC } from '../shared/ipc'
import type { AppSettings, ChatMessage, PacketQuery } from '../shared/types'
import { captureService } from './capture-service'
import { getSettings, setSettings, getRecentFiles } from './settings'
import { getDigest, runReport, runChat, cancelAi } from './ai'
import { exportReport } from './report'

const CAPTURE_FILTERS = [
  { name: 'Capture Files', extensions: ['pcap', 'pcapng', 'cap'] },
  { name: 'All Files', extensions: ['*'] }
]

let mainWindow: BrowserWindow | null = null

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1000,
    minHeight: 640,
    show: false,
    backgroundColor: '#f1f2f3',
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    webPreferences: {
      preload: join(__dirname, '../preload/index.mjs'),
      sandbox: false,
      contextIsolation: true,
      nodeIntegration: false
    }
  })

  captureService.attachWindow(mainWindow)

  mainWindow.on('ready-to-show', () => mainWindow?.show())

  mainWindow.webContents.setWindowOpenHandler((details) => {
    shell.openExternal(details.url)
    return { action: 'deny' }
  })

  // Accept capture files dragged onto the window.
  mainWindow.webContents.on('will-navigate', (e) => e.preventDefault())

  const devUrl = process.env['ELECTRON_RENDERER_URL']
  if (devUrl) {
    mainWindow.loadURL(devUrl)
  } else {
    mainWindow.loadFile(join(__dirname, '../renderer/index.html'))
  }
}

function buildMenu(): void {
  const isMac = process.platform === 'darwin'
  const template: Electron.MenuItemConstructorOptions[] = [
    ...(isMac
      ? [{ role: 'appMenu' as const }]
      : []),
    {
      label: 'File',
      submenu: [
        {
          label: 'Open Capture…',
          accelerator: 'CmdOrCtrl+O',
          click: () => mainWindow?.webContents.send(IPC.menuOpenCapture)
        },
        { type: 'separator' as const },
        isMac ? { role: 'close' as const } : { role: 'quit' as const }
      ]
    },
    { role: 'editMenu' },
    { role: 'viewMenu' },
    { role: 'windowMenu' }
  ]
  Menu.setApplicationMenu(Menu.buildFromTemplate(template))
}

function registerIpc(): void {
  ipcMain.handle(IPC.openCaptureDialog, async () => {
    if (!mainWindow) return null
    const { canceled, filePaths } = await dialog.showOpenDialog(mainWindow, {
      title: 'Open Capture File',
      properties: ['openFile'],
      filters: CAPTURE_FILTERS
    })
    if (canceled || filePaths.length === 0) return null
    captureService.open(filePaths[0])
    return filePaths[0]
  })

  ipcMain.handle(IPC.openCapturePath, async (_e, path: string) => {
    captureService.open(path)
  })

  ipcMain.handle(IPC.getPacketPage, (_e, query: PacketQuery) =>
    captureService.getPacketPage(query)
  )
  ipcMain.handle(IPC.getPacketDetail, (_e, n: number) => captureService.getPacketDetail(n))
  ipcMain.handle(IPC.getRecentFiles, () => getRecentFiles())

  ipcMain.handle(IPC.getSettings, () => getSettings())
  ipcMain.handle(IPC.setSettings, (_e, partial: Partial<AppSettings>) => setSettings(partial))

  ipcMain.handle(IPC.getDigest, () => getDigest())
  ipcMain.handle(IPC.runReport, () => (mainWindow ? runReport(mainWindow) : ''))
  ipcMain.handle(IPC.runChat, (_e, messages: ChatMessage[]) =>
    mainWindow ? runChat(mainWindow, messages) : ''
  )
  ipcMain.handle(IPC.cancelAi, (_e, id: string) => cancelAi(id))

  ipcMain.handle(IPC.exportReport, (_e, markdown: string) =>
    mainWindow ? exportReport(mainWindow, markdown) : null
  )
}

app.whenReady().then(() => {
  buildMenu()
  registerIpc()
  createWindow()

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  captureService.dispose()
  if (process.platform !== 'darwin') app.quit()
})
