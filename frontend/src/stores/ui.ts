/**
 * Zustand store for UI-local state ONLY (ADR-0012 decision 4).
 *
 * Server data (devices, topology, changes, audit, health) lives exclusively
 * in TanStack Query's cache and must never be copied into this store.
 */

import { create } from "zustand";

export type Theme = "dark" | "light";

export interface UiState {
  /** Whether the primary sidebar is collapsed to icon width. */
  sidebarCollapsed: boolean;
  /** Active color theme; the console is dark-first. */
  theme: Theme;
  toggleSidebar: () => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  setTheme: (theme: Theme) => void;
}

export const useUiStore = create<UiState>()((set) => ({
  sidebarCollapsed: false,
  theme: "dark",
  toggleSidebar: () => set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed })),
  setSidebarCollapsed: (sidebarCollapsed) => set({ sidebarCollapsed }),
  setTheme: (theme) => set({ theme }),
}));
