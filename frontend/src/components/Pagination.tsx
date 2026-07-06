/**
 * Offset/limit pager for the read-only inventory tables.
 *
 * Server-side lists cap each page at ``limit`` rows; without a pager, items
 * beyond the first page are silently hidden while the header still shows the
 * full ``total``. This renders a "showing X–Y of TOTAL" range plus Prev/Next
 * controls so nothing is dropped without an affordance to reach it. When the
 * whole result set fits in one page (``total <= limit``) it renders nothing.
 *
 * Self-healing on shrink: if a refetch returns a smaller ``total`` while the
 * caller still holds a now-out-of-range ``offset`` (a stale page index), the
 * component snaps ``offset`` back to the last valid page via ``onChange`` —
 * the refetch that triggers then repopulates the table, instead of rendering
 * an inverted "Showing 201–150 of 150" range over a misleading empty page.
 */

import { useEffect } from "react";

interface PaginationProps {
  /** Zero-based offset of the first row on the current page. */
  offset: number;
  /** Page size (rows per fetch). */
  limit: number;
  /** Server-reported total across all pages. */
  total: number;
  /** Called with the new offset when the user pages. */
  onChange: (offset: number) => void;
  /** Stable slug for the test id / aria label (e.g. "virtual-servers"). */
  label: string;
}

export function Pagination({ offset, limit, total, onChange, label }: PaginationProps) {
  // Stale page index (total shrank below the current offset): snap back to the
  // last valid page. Must run unconditionally, before any early return.
  useEffect(() => {
    if (offset > 0 && offset >= total) {
      onChange(Math.max(0, Math.floor(Math.max(total - 1, 0) / limit) * limit));
    }
  }, [offset, limit, total, onChange]);

  // Everything fits on one page — no controls needed. A stale offset past the
  // end also renders nothing (never an inverted range) while the effect above
  // snaps the caller's offset back.
  if (total <= limit || offset >= total) return null;

  const start = offset + 1;
  const end = Math.min(offset + limit, total);
  const hasPrev = offset > 0;
  const hasNext = offset + limit < total;

  return (
    <div
      data-testid={`${label}-pagination`}
      className="flex items-center justify-between px-1 text-xs text-zinc-500"
    >
      <span data-testid={`${label}-pagination-range`}>
        Showing {start}–{end} of {total}
      </span>
      <div className="flex items-center gap-2">
        <button
          type="button"
          data-testid={`${label}-pagination-prev`}
          className="rounded border border-carbon-600 px-2 py-1 text-zinc-300 transition-colors hover:bg-carbon-800/50 disabled:cursor-not-allowed disabled:opacity-40"
          disabled={!hasPrev}
          onClick={() => onChange(Math.max(0, offset - limit))}
        >
          Prev
        </button>
        <button
          type="button"
          data-testid={`${label}-pagination-next`}
          className="rounded border border-carbon-600 px-2 py-1 text-zinc-300 transition-colors hover:bg-carbon-800/50 disabled:cursor-not-allowed disabled:opacity-40"
          disabled={!hasNext}
          onClick={() => onChange(offset + limit)}
        >
          Next
        </button>
      </div>
    </div>
  );
}
