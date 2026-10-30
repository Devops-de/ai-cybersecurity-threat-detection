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
        cyber: {
          bg: '#0a0d14',
          card: '#111726',
          border: '#1e293b',
          accent: '#06b6d4',
          danger: '#ef4444',
          warning: '#f59e0b',
          success: '#10b981',
          neon: '#00f0ff'
        }
      },
      fontFamily: {
        mono: ['Fira Code', 'Courier New', 'monospace']
      }
    },
  },
  plugins: [],
}
