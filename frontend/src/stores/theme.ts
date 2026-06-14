/**
 * Theme store (Auth & Account UI, F1): light / dark / system appearance.
 *
 * Tailwind is configured with ``darkMode: "class"`` (see ``tailwind.config.ts``),
 * so the resolved theme is applied by toggling the ``dark`` class on
 * ``document.documentElement``. The user's *choice* (not the resolved value) is
 * persisted to ``localStorage``; ``system`` follows ``prefers-color-scheme`` and
 * reacts to OS changes for as long as the choice stays ``system``.
 */

import { create } from "zustand";

export type Theme = "light" | "dark" | "system";

/** localStorage key the chosen theme is persisted under. */
export const THEME_STORAGE_KEY = "netops.theme";

export interface ThemeState {
  /** The user's chosen theme (``system`` defers to the OS preference). */
  theme: Theme;
  /** Persist + apply a new theme choice (and wire/unwire the OS listener). */
  setTheme: (theme: Theme) => void;
}

const DARK_QUERY = "(prefers-color-scheme: dark)";

/** Whether the OS currently prefers a dark color scheme (false when unsupported). */
function prefersDark(): boolean {
  return typeof globalThis.matchMedia === "function" && globalThis.matchMedia(DARK_QUERY).matches;
}

/** Resolve a chosen theme to a concrete light/dark decision. */
function isDark(theme: Theme): boolean {
  return theme === "dark" || (theme === "system" && prefersDark());
}

/** Toggle the ``dark`` class on the document root to match *theme*. */
function applyTheme(theme: Theme): void {
  const root = globalThis.document?.documentElement;
  if (root === undefined) {
    return;
  }
  root.classList.toggle("dark", isDark(theme));
}

/** Persist the chosen theme; storage failures (private mode) are non-fatal. */
function persistTheme(theme: Theme): void {
  try {
    globalThis.localStorage?.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // Storage can throw in locked-down/private-mode contexts; ignore.
  }
}

/** Read the persisted choice, defaulting to ``system`` when unset/unreadable. */
function loadTheme(): Theme {
  try {
    const stored = globalThis.localStorage?.getItem(THEME_STORAGE_KEY);
    if (stored === "light" || stored === "dark" || stored === "system") {
      return stored;
    }
  } catch {
    // Ignore unreadable storage.
  }
  return "system";
}

//: The single OS-preference listener; (re)wired only while the choice is
//: ``system`` so a later light→dark OS switch live-updates the document.
let mediaListener: ((event: MediaQueryListEvent) => void) | null = null;

function unwireSystemListener(): void {
  if (mediaListener !== null && typeof globalThis.matchMedia === "function") {
    globalThis.matchMedia(DARK_QUERY).removeEventListener("change", mediaListener);
  }
  mediaListener = null;
}

function wireSystemListener(): void {
  unwireSystemListener();
  if (typeof globalThis.matchMedia !== "function") {
    return;
  }
  mediaListener = () => applyTheme("system");
  globalThis.matchMedia(DARK_QUERY).addEventListener("change", mediaListener);
}

const initialTheme = loadTheme();
applyTheme(initialTheme);
if (initialTheme === "system") {
  wireSystemListener();
}

export const useThemeStore = create<ThemeState>()((set) => ({
  theme: initialTheme,
  setTheme: (theme) => {
    persistTheme(theme);
    applyTheme(theme);
    if (theme === "system") {
      wireSystemListener();
    } else {
      unwireSystemListener();
    }
    set({ theme });
  },
}));
