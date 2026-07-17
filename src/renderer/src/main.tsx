import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'
import { initIpcListeners, loadSettings } from './store'
import { installDevMock } from './lib/dev-mock'

installDevMock()
initIpcListeners()
void loadSettings()

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
)
