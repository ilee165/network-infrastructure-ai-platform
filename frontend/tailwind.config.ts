import type { Config } from "tailwindcss";

/**
 * Tailwind design tokens (ADR-0012): dark, dense operations-console palette.
 *
 * - `carbon`  — surface scale (page → panel → raised → border).
 * - `accent`  — interactive highlight.
 * - `status`  — shared status palette for dependency/device/change states.
 */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  // Auth & Account UI: the theme store toggles a `dark` class on <html>, so
  // dark variants must be class-driven (not the default media-query mode).
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        carbon: {
          950: "#0a0d13",
          900: "#0f131b",
          850: "#141a24",
          800: "#1a2230",
          700: "#243044",
          600: "#33415c",
        },
        accent: {
          DEFAULT: "#38bdf8",
          muted: "#0e7490",
        },
        status: {
          ok: "#34d399",
          warn: "#fbbf24",
          error: "#f87171",
          idle: "#64748b",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "Segoe UI", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
    },
  },
  plugins: [],
} satisfies Config;
