/**
 * Loading/motion primitives (audit UI_UX #4): skeleton blocks, skeleton table
 * rows, and a spinner — replacing the plain "Loading…" text every page used.
 * All motion respects `prefers-reduced-motion` via Tailwind's
 * `motion-reduce:` variant.
 */

import type { HTMLAttributes } from "react";

interface SkeletonProps extends HTMLAttributes<HTMLDivElement> {
  /**
   * Accessible loading announcement. Rendered as a visually-hidden
   * (`sr-only`) element with `role="status"` alongside the (still
   * `aria-hidden`) pulsing block, so screen-reader users get the same loading
   * cue sighted users infer from the skeleton animation.
   */
  label?: string;
}

/** A single pulsing placeholder block. Purely decorative — hidden from a11y tree. */
export function Skeleton({ className = "", label, ...rest }: SkeletonProps) {
  return (
    <>
      {/* role="status" computes its accessible name from `aria-label`, not
          content (same idiom as `Spinner` below) — a text child alone would
          be announced with no name. */}
      {label ? <span role="status" aria-label={label} className="sr-only" /> : null}
      <div
        aria-hidden="true"
        className={`animate-pulse motion-reduce:animate-none rounded bg-carbon-800 ${className}`}
        {...rest}
      />
    </>
  );
}

interface SkeletonRowsProps {
  /** Number of placeholder rows to render. */
  rows: number;
  /** Number of placeholder columns (cells) per row. */
  cols: number;
  /**
   * Accessible loading announcement, e.g. "Loading inventory…". Rendered
   * once as a visually-hidden `role="status"` cell in an extra `sr-only`
   * row — the pulsing rows themselves stay `aria-hidden`.
   */
  label?: string;
}

/**
 * Skeleton table rows matching the existing table idiom (`border-b
 * border-carbon-800 last:border-0` rows, `py-1 pr-4` cells). Drop directly
 * inside an existing `<tbody>` in place of the real rows while loading.
 */
export function SkeletonRows({ rows, cols, label }: SkeletonRowsProps) {
  return (
    <>
      {label ? (
        <tr className="sr-only">
          <td colSpan={cols}>
            <span role="status" aria-label={label} />
          </td>
        </tr>
      ) : null}
      {Array.from({ length: rows }, (_, rowIndex) => (
        <tr key={rowIndex} className="border-b border-carbon-800 last:border-0">
          {Array.from({ length: cols }, (_, colIndex) => (
            <td key={colIndex} className="py-1 pr-4">
              <Skeleton className="h-3 w-full max-w-24" />
            </td>
          ))}
        </tr>
      ))}
    </>
  );
}

interface SpinnerProps {
  /** Accessible label for the loading indicator. */
  "aria-label"?: string;
  className?: string;
}

/**
 * Small in-flight spinner for mutations. When motion is reduced, the spin
 * animation stops and a static glyph stands in so the state is still legible.
 */
export function Spinner({ "aria-label": ariaLabel = "Loading", className = "" }: SpinnerProps) {
  return (
    <span role="status" aria-label={ariaLabel} className={`relative inline-flex h-4 w-4 ${className}`}>
      <span
        aria-hidden="true"
        className="absolute inset-0 animate-spin motion-reduce:hidden rounded-full border-2 border-carbon-600 border-t-accent"
      />
      <span aria-hidden="true" className="absolute inset-0 hidden items-center justify-center motion-reduce:flex">
        ◐
      </span>
    </span>
  );
}
