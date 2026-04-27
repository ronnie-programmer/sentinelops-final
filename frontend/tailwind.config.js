/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        sentinel: {
          bg: '#0d1117',
          surface: '#161b22',
          border: '#30363d',
          primary: '#58a6ff',
          secondary: '#8b949e',
          danger: '#f85149',
          warning: '#d29922',
          success: '#3fb950',
          purple: '#bc8cff',
        },
      },
    },
  },
  plugins: [],
}
