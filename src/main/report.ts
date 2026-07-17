import { dialog } from 'electron'
import { writeFileSync } from 'fs'
import type { BrowserWindow } from 'electron'
import { captureService } from './capture-service'
import { buildReportMarkdown } from '../shared/report-format'

export async function exportReport(
  win: BrowserWindow,
  aiMarkdown: string
): Promise<string | null> {
  const analysis = captureService.getAnalysis()
  if (!analysis) return null

  const content = buildReportMarkdown(analysis, aiMarkdown)
  const base = analysis.stats.fileName.replace(/\.[^.]+$/, '')
  const { canceled, filePath } = await dialog.showSaveDialog(win, {
    title: 'Export PacketEye Report',
    defaultPath: `${base}-report.md`,
    filters: [{ name: 'Markdown', extensions: ['md'] }]
  })
  if (canceled || !filePath) return null
  writeFileSync(filePath, content, 'utf-8')
  return filePath
}
