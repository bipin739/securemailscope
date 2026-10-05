/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        brand: {
          dark: '#090d16',
          panel: '#0f172a',
          card: '#131d31',
          hover: '#1e293b',
          border: '#1e293b',
          borderLight: '#334155',
          accent: '#38bdf8',
          accentDark: '#0284c7',
        },
        sec: {
          secure: '#10b981',
          'secure-bg': '#064e3b20',
          'secure-border': '#05966940',
          warning: '#f59e0b',
          'warning-bg': '#78350f20',
          'warning-border': '#d9770640',
          critical: '#ef4444',
          'critical-bg': '#7f1d1d20',
          'critical-border': '#dc262640',
          info: '#38bdf8',
          'info-bg': '#0c4a6e20',
          'info-border': '#0284c740',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
}
