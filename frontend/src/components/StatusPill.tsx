/**
 * StatusPill: the single sanctioned status-pill composition (audit UI_UX
 * #3/#7).
 *
 * Every page previously hand-composed its own `border-status-X/40
 * bg-status-X/10 text-status-X` pill (see the `PILL_BASE` idiom this was
 * lifted from in `DevicesPage.tsx`), with subtle drift between pages. This
 * component encodes that composition once.
 *
 * Status must never be color-only (audit UI_UX #5): each variant renders a
 * small `aria-hidden` glyph beside the label so the signal survives for
 * color-blind users and in monochrome print/screenshots.
 */

import type { ReactNode } from "react";

export type StatusPillVariant = "ok" | "warn" | "error" | "neutral" | "info";

interface StatusPillProps {
  variant: StatusPillVariant;
  children: ReactNode;
  "data-testid"?: string;
}

const PILL_BASE =
  "inline-flex items-center gap-1 rounded border px-2 py-0.5 font-mono text-[11px] uppercase tracking-wider";

/** Token composition per variant, matching the idiom already in use across pages. */
const VARIANT_STYLES: Record<StatusPillVariant, string> = {
  ok: "border-status-ok/40 bg-status-ok/10 text-status-ok",
  warn: "border-status-warn/40 bg-status-warn/10 text-status-warn",
  error: "border-status-error/40 bg-status-error/10 text-status-error",
  neutral: "border-carbon-600 bg-carbon-800 text-zinc-400",
  info: "border-accent/40 bg-accent/10 text-accent",
};

/** Non-color glyph per variant so status reads without relying on hue. */
const VARIANT_GLYPH: Record<StatusPillVariant, string> = {
  ok: "●", // ●
  warn: "▲", // ▲
  error: "✕", // ✕
  neutral: "○", // ○
  info: "◆", // ◆
};

export function StatusPill({ variant, children, "data-testid": dataTestId }: StatusPillProps) {
  return (
    <span className={`${PILL_BASE} ${VARIANT_STYLES[variant]}`} data-testid={dataTestId}>
      <span
        aria-hidden="true"
        className="before:content-[attr(data-glyph)]"
        data-glyph={VARIANT_GLYPH[variant]}
      />
      {children}
    </span>
  );
}
