/**
 * Zustand store for UI-local state ONLY (ADR-0012 decision 4).
 *
 * Server data (devices, topology, changes, audit, health) lives exclusively
 * in TanStack Query's cache and must never be copied into this store.
 */

import { create } from "zustand";

export type Theme = "dark" | "light";

/** A toast's semantic kind; also drives the tone it renders in (audit UI_UX #6). */
export type ToastKind = "success" | "error" | "info";

export interface Toast {
  id: string;
  kind: ToastKind;
  message: string;
}

export interface UiState {
  /** Whether the primary sidebar is collapsed to icon width. */
  sidebarCollapsed: boolean;
  /** Active color theme; the console is dark-first. */
  theme: Theme;
  /** Active toast stack, oldest first; rendered by the `Toaster` portal. */
  toasts: Toast[];
  toggleSidebar: () => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  setTheme: (theme: Theme) => void;
  /** Push a toast onto the stack and return its generated id. */
  pushToast: (kind: ToastKind, message: string) => string;
  dismissToast: (id: string) => void;
}

/**
 * Monotonic counter for toast ids (not `Date.now()` — pushing several toasts
 * within the same millisecond must still yield distinct, stably-ordered ids).
 * Store actions stay pure; auto-dismiss timers live in the `Toaster`
 * component, not here.
 */
let nextToastId = 0;

export const useUiStore = create<UiState>()((set) => ({
  sidebarCollapsed: false,
  theme: "dark",
  toasts: [],
  toggleSidebar: () => set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed })),
  setSidebarCollapsed: (sidebarCollapsed) => set({ sidebarCollapsed }),
  setTheme: (theme) => set({ theme }),
  pushToast: (kind, message) => {
    const id = `toast-${(nextToastId += 1)}`;
    set((state) => ({ toasts: [...state.toasts, { id, kind, message }] }));
    return id;
  },
  dismissToast: (id) => set((state) => ({ toasts: state.toasts.filter((t) => t.id !== id) })),
}));
