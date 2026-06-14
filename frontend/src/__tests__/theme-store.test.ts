/**
 * Unit tests for the theme store (Auth & Account UI, F1).
 *
 * Theme is persisted to localStorage; the resolved theme toggles the ``dark``
 * class on ``document.documentElement``; ``system`` follows
 * ``prefers-color-scheme`` and reacts to OS changes.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { THEME_STORAGE_KEY, useThemeStore } from "../stores/theme";

/** Install a controllable matchMedia returning the given dark-mode preference. */
function stubMatchMedia(prefersDark: boolean): {
  fire: (matches: boolean) => void;
} {
  const listeners = new Set<(e: MediaQueryListEvent) => void>();
  let matches = prefersDark;
  const mql = {
    get matches() {
      return matches;
    },
    media: "(prefers-color-scheme: dark)",
    addEventListener: (_: string, cb: (e: MediaQueryListEvent) => void) => {
      listeners.add(cb);
    },
    removeEventListener: (_: string, cb: (e: MediaQueryListEvent) => void) => {
      listeners.delete(cb);
    },
  };
  vi.stubGlobal(
    "matchMedia",
    vi.fn(() => mql),
  );
  return {
    fire(next: boolean) {
      matches = next;
      for (const cb of listeners) {
        cb({ matches: next } as MediaQueryListEvent);
      }
    },
  };
}

function reset(): void {
  globalThis.localStorage.clear();
  document.documentElement.classList.remove("dark");
  useThemeStore.setState({ theme: "system" });
}

beforeEach(() => {
  stubMatchMedia(false);
  reset();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("theme store — explicit dark/light", () => {
  it("adds the dark class on document.documentElement for dark", () => {
    useThemeStore.getState().setTheme("dark");
    expect(document.documentElement.classList.contains("dark")).toBe(true);
  });

  it("removes the dark class for light", () => {
    document.documentElement.classList.add("dark");
    useThemeStore.getState().setTheme("light");
    expect(document.documentElement.classList.contains("dark")).toBe(false);
  });

  it("persists the chosen theme to localStorage", () => {
    useThemeStore.getState().setTheme("dark");
    expect(globalThis.localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
  });

  it("updates the store state", () => {
    useThemeStore.getState().setTheme("light");
    expect(useThemeStore.getState().theme).toBe("light");
  });
});

describe("theme store — system mode", () => {
  it("applies dark when the OS prefers dark", () => {
    stubMatchMedia(true);
    useThemeStore.getState().setTheme("system");
    expect(document.documentElement.classList.contains("dark")).toBe(true);
  });

  it("applies light when the OS prefers light", () => {
    stubMatchMedia(false);
    useThemeStore.getState().setTheme("system");
    expect(document.documentElement.classList.contains("dark")).toBe(false);
  });

  it("persists 'system' (not the resolved value) to localStorage", () => {
    useThemeStore.getState().setTheme("system");
    expect(globalThis.localStorage.getItem(THEME_STORAGE_KEY)).toBe("system");
  });

  it("reacts to a later prefers-color-scheme change while in system mode", () => {
    const media = stubMatchMedia(false);
    useThemeStore.getState().setTheme("system");
    expect(document.documentElement.classList.contains("dark")).toBe(false);
    media.fire(true);
    expect(document.documentElement.classList.contains("dark")).toBe(true);
  });
});
