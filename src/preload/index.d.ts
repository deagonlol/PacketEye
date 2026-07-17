import type { PacketEyeApi } from './index'

declare global {
  interface Window {
    packeteye: PacketEyeApi
  }
}

export {}
