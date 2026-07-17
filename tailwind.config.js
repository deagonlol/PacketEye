/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/renderer/index.html', './src/renderer/src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: {
          base: '#f1f2f3',
          panel: '#ffffff',
          elevated: '#e8ebee',
          hover: '#dce8f3'
        },
        border: {
          subtle: '#d6d9dc',
          DEFAULT: '#b8bdc2'
        },
        text: {
          primary: '#20262b',
          secondary: '#4f5a63',
          muted: '#77818a'
        },
        accent: {
          DEFAULT: '#1f6fae',
          dim: '#d7e9f7'
        },
        sev: {
          critical: '#c92a2a',
          high: '#e66a00',
          medium: '#d39e00',
          low: '#7f9f16',
          info: '#3d9860'
        }
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
        sans: ['Inter', 'SF Pro Display', 'ui-sans-serif', 'system-ui', 'sans-serif']
      },
      boxShadow: {
        panel: '0 1px 2px rgba(0, 0, 0, 0.08)',
        glow: '0 1px 3px rgba(0, 0, 0, 0.12)'
      }
    }
  },
  plugins: []
}
