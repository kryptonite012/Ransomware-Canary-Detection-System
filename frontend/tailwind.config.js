/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        bg: { DEFAULT: "#0a0e14", soft: "#0f141c", panel: "#121a25", border: "#1e2a3a" },
        ink: { DEFAULT: "#e6edf3", dim: "#8b9bb0", faint: "#5b6b80" },
        accent: { DEFAULT: "#2dd4bf", glow: "#14b8a6" },
        risk: {
          normal: "#22c55e", low: "#84cc16", elevated: "#eab308",
          high: "#f97316", critical: "#ef4444",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      boxShadow: { glow: "0 0 24px -6px rgba(45,212,191,0.35)" },
      keyframes: {
        pulseRing: { "0%": { opacity: "0.7" }, "50%": { opacity: "0.2" }, "100%": { opacity: "0.7" } },
      },
      animation: { pulseRing: "pulseRing 2s ease-in-out infinite" },
    },
  },
  plugins: [],
};
