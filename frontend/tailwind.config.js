// Design tokens. Colors are semantic (verdicts, severities) so meaning stays
// consistent across tables, badges, the graph and the timeline.
/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Inter Variable"', "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "SFMono-Regular", "monospace"],
      },
      colors: {
        ink: { 950: "#06080c", 900: "#0a0e14", 850: "#0d121a", 800: "#111823", 700: "#1a2331", 600: "#243041", 500: "#3a475a" },
        fg: { DEFAULT: "#e6edf5", muted: "#93a1b4", faint: "#5f6d80" },
        accent: { DEFAULT: "#38bdf8", soft: "#0c4a6e" },
      },
      boxShadow: { panel: "0 0 0 1px rgba(255,255,255,0.04), 0 8px 24px -12px rgba(0,0,0,0.6)" },
      keyframes: { pulseDot: { "0%,100%": { opacity: 1 }, "50%": { opacity: 0.35 } } },
      animation: { pulseDot: "pulseDot 1.6s ease-in-out infinite" },
    },
  },
  plugins: [],
};
