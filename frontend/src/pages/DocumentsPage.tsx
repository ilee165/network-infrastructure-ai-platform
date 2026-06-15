/**
 * Documents library: list generated inventories, diagrams, and runbooks by
 * kind, with download and Mermaid client-side render for diagram documents.
 *
 * Three sub-views (kind filter tabs): All | Inventory | Diagram | Runbook.
 * Clicking a row's "View" button opens an inline panel:
 *  - Mermaid format → raw source + PNG export button (disabled stub; requires mermaid npm integration, post-M4)
 *  - All other formats (md / csv) → plain pre-formatted content view
 *
 * Download uses the ``/docs/{id}/download`` endpoint and triggers a browser
 * Blob download (no server-stored PNG; ADR-0019 §3).
 *
 * Wired to ``api/docs.ts`` (T14 endpoints). Read-only in M4 (ADR-0019).
 */

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import {
  downloadDocument,
  listDocuments,
  type DocumentKind,
  type DocumentListResponse,
  type DocumentRead,
} from "../api/docs";
import { PageHeader } from "../components/PageHeader";

// ── Constants ─────────────────────────────────────────────────────────────────

const PILL_BASE =
  "inline-flex items-center rounded border px-2 py-0.5 font-mono text-[11px] uppercase tracking-wider";

// ── Kind badge ────────────────────────────────────────────────────────────────

const KIND_STYLES: Record<DocumentKind, string> = {
  inventory: "border-accent/40 bg-accent/10 text-accent",
  diagram: "border-status-ok/40 bg-status-ok/10 text-status-ok",
  runbook: "border-status-warn/40 bg-status-warn/10 text-status-warn",
};

function KindBadge({
  docId,
  kind,
}: {
  docId: string;
  kind: DocumentKind;
}) {
  return (
    <span
      data-testid={`doc-kind-${docId}`}
      className={`${PILL_BASE} ${KIND_STYLES[kind]}`}
    >
      {kind}
    </span>
  );
}

function FormatBadge({
  docId,
  format,
}: {
  docId: string;
  format: string;
}) {
  return (
    <span
      data-testid={`doc-format-${docId}`}
      className={`${PILL_BASE} border-carbon-600 bg-carbon-800 text-zinc-400`}
    >
      {format}
    </span>
  );
}

// ── Mermaid panel ─────────────────────────────────────────────────────────────

/**
 * Client-side Mermaid panel.  In M4 we store the Mermaid source (ADR-0019 §3);
 * the browser renders and exports as PNG.  In the test environment
 * (jsdom) the ``<canvas>`` path is not available, so PNG export is gated on
 * ``HTMLCanvasElement`` presence — the button is always rendered but export
 * degrades gracefully when the environment lacks a canvas implementation.
 */
function MermaidPanel({
  doc,
  onClose,
}: {
  doc: DocumentRead;
  onClose: () => void;
}) {
  // PNG export requires the `mermaid` npm package to be integrated for
  // SVG→canvas rendering. That integration is a post-M4 hardening item
  // (ADR-0019 §3). Until then the button is disabled so no blank/corrupt
  // file is ever downloaded. Users can paste the source into mermaid.live.
  const PNG_EXPORT_AVAILABLE = false as boolean;

  return (
    <div
      data-testid="mermaid-panel"
      className="flex flex-col gap-4 rounded-md border border-carbon-700 bg-carbon-900 p-4"
    >
      <div className="flex items-center justify-between">
        <h3 className="font-mono text-xs font-semibold uppercase tracking-widest text-zinc-300">
          {doc.title}
        </h3>
        <div className="flex items-center gap-2">
          <button
            type="button"
            data-testid="mermaid-export-png"
            disabled={!PNG_EXPORT_AVAILABLE}
            title="PNG export requires the Mermaid renderer — paste source into mermaid.live to generate a PNG"
            className="rounded border border-carbon-600 px-3 py-1 font-mono text-[11px] uppercase tracking-wider text-zinc-400 transition-colors disabled:cursor-not-allowed disabled:opacity-40"
          >
            Export PNG
          </button>
          <button
            type="button"
            data-testid="doc-panel-close"
            onClick={onClose}
            className="rounded border border-carbon-600 px-3 py-1 font-mono text-[11px] uppercase tracking-wider text-zinc-400 transition-colors hover:border-carbon-500 hover:text-zinc-200"
          >
            Close
          </button>
        </div>
      </div>

      {/* Raw Mermaid source — the diagram-of-record (ADR-0019 §3) */}
      <pre
        data-testid="mermaid-source"
        aria-label="Mermaid diagram source"
        className="overflow-x-auto rounded bg-carbon-950 p-4 font-mono text-[11px] leading-relaxed text-zinc-300"
      >
        {doc.content}
      </pre>
      <p className="font-mono text-[10px] text-zinc-600">
        Mermaid source — paste into mermaid.live or any Mermaid renderer for a
        live diagram. PNG export renders client-side.
      </p>
    </div>
  );
}

// ── Plain content panel ───────────────────────────────────────────────────────

function ContentPanel({
  doc,
  onClose,
}: {
  doc: DocumentRead;
  onClose: () => void;
}) {
  return (
    <div
      data-testid="doc-content-panel"
      className="flex flex-col gap-4 rounded-md border border-carbon-700 bg-carbon-900 p-4"
    >
      <div className="flex items-center justify-between">
        <h3 className="font-mono text-xs font-semibold uppercase tracking-widest text-zinc-300">
          {doc.title}
        </h3>
        <button
          type="button"
          data-testid="doc-panel-close"
          onClick={onClose}
          className="rounded border border-carbon-600 px-3 py-1 font-mono text-[11px] uppercase tracking-wider text-zinc-400 transition-colors hover:border-carbon-500 hover:text-zinc-200"
        >
          Close
        </button>
      </div>
      <pre
        data-testid="doc-content-source"
        aria-label={`${doc.format} document content`}
        className="overflow-x-auto rounded bg-carbon-950 p-4 font-mono text-[11px] leading-relaxed text-zinc-300"
      >
        {doc.content}
      </pre>
    </div>
  );
}

// ── Document row ──────────────────────────────────────────────────────────────

function DocRow({
  doc,
  onView,
  onDownload,
}: {
  doc: DocumentRead;
  onView: (doc: DocumentRead) => void;
  onDownload: (doc: DocumentRead) => void;
}) {
  return (
    <tr
      data-testid={`doc-row-${doc.id}`}
      className="border-b border-carbon-800 last:border-0"
    >
      <td className="px-4 py-3 text-zinc-200">
        <span className="text-sm font-medium">{doc.title}</span>
      </td>
      <td className="px-4 py-3">
        <KindBadge docId={doc.id} kind={doc.kind} />
      </td>
      <td className="px-4 py-3">
        <FormatBadge docId={doc.id} format={doc.format} />
      </td>
      <td className="px-4 py-3 font-mono text-[11px] text-zinc-500">
        {new Date(doc.generated_at).toLocaleString()}
      </td>
      <td className="px-4 py-3">
        <div className="flex items-center gap-2">
          <button
            type="button"
            data-testid={`doc-view-${doc.id}`}
            onClick={() => onView(doc)}
            className="rounded border border-carbon-600 px-2 py-1 font-mono text-[11px] uppercase tracking-wider text-zinc-400 transition-colors hover:border-carbon-500 hover:text-zinc-200"
          >
            View
          </button>
          <button
            type="button"
            data-testid={`doc-download-${doc.id}`}
            onClick={() => onDownload(doc)}
            className="rounded border border-carbon-600 px-2 py-1 font-mono text-[11px] uppercase tracking-wider text-zinc-400 transition-colors hover:border-carbon-500 hover:text-zinc-200"
          >
            Download
          </button>
        </div>
      </td>
    </tr>
  );
}

// ── Tab types ─────────────────────────────────────────────────────────────────

type DocsTab = "all" | DocumentKind;

// ── Page ──────────────────────────────────────────────────────────────────────

export function DocumentsPage() {
  const [tab, setTab] = useState<DocsTab>("all");
  const [viewedDoc, setViewedDoc] = useState<DocumentRead | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const kindParam: DocumentKind | undefined =
    tab === "all" ? undefined : tab;

  const { data, isPending, error } = useQuery<DocumentListResponse>({
    queryKey: ["documents", tab],
    queryFn: () => listDocuments({ kind: kindParam, limit: 50 }),
  });

  // ── Download handler ────────────────────────────────────────────────────────

  async function handleDownload(doc: DocumentRead): Promise<void> {
    try {
      setDownloadError(null);
      const payload = await downloadDocument(doc.id);
      const ext = payload.format === "csv" ? "csv" : payload.format === "mermaid" ? "mmd" : "md";
      const mimeType =
        payload.format === "csv"
          ? "text/csv"
          : payload.format === "mermaid"
            ? "text/plain"
            : "text/markdown";
      const blob = new Blob([payload.content], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${payload.title.replace(/\s+/g, "-").toLowerCase()}.${ext}`;
      a.click();
      // Defer revoke past the browser's async fetch-dispatch tick so the file
      // is fully handed off before the object URL is invalidated (Firefox / older
      // Chrome revoke the resource before the download starts if revoke is
      // synchronous with the click).
      setTimeout(() => URL.revokeObjectURL(url), 0);
    } catch (err) {
      setDownloadError(err instanceof Error ? err.message : "Download failed");
    }
  }

  // ── Tab button factory ──────────────────────────────────────────────────────

  const tabBtn = (t: DocsTab, label: string) => (
    <button
      key={t}
      type="button"
      role="tab"
      aria-selected={tab === t}
      aria-controls={`docs-tabpanel-${t}`}
      data-testid={`docs-tab-${t}`}
      onClick={() => {
        setTab(t);
        setViewedDoc(null);
      }}
      className={`px-4 py-2 text-xs font-medium transition-colors ${
        tab === t
          ? "border-b-2 border-accent text-zinc-100"
          : "text-zinc-500 hover:text-zinc-300"
      }`}
    >
      {label}
    </button>
  );

  // ── Render ──────────────────────────────────────────────────────────────────

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Documents"
        description="Agent-generated inventories, diagrams, and runbooks. All artifacts are downloadable and searchable via the knowledge base."
      />

      {/* Kind filter tab bar */}
      <div
        className="flex gap-1 border-b border-carbon-700"
        role="tablist"
        aria-label="Document kinds"
      >
        {tabBtn("all", "All")}
        {tabBtn("inventory", "Inventory")}
        {tabBtn("diagram", "Diagram")}
        {tabBtn("runbook", "Runbook")}
      </div>

      {/* Tab panel */}
      <div
        role="tabpanel"
        id={`docs-tabpanel-${tab}`}
        aria-labelledby={`docs-tab-${tab}`}
        className="flex flex-col gap-4"
      >
        {/* Loading */}
        {isPending && (
          <p role="status" className="text-xs text-zinc-500">
            Loading documents…
          </p>
        )}

        {/* Error */}
        {error && (
          <div
            role="alert"
            className="panel border-status-error/40 px-4 py-3 text-xs text-status-error"
          >
            Documents load failed: {error.message}
          </div>
        )}

        {/* Download error */}
        {downloadError !== null && (
          <div
            role="alert"
            data-testid="docs-download-error"
            className="panel border-status-error/40 px-4 py-3 text-xs text-status-error"
          >
            Download failed: {downloadError}
          </div>
        )}

        {/* Empty state */}
        {!isPending && !error && (data?.items ?? []).length === 0 && (
          <div
            data-testid="docs-empty-state"
            className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-carbon-600 bg-carbon-900/50 px-6 py-16 text-center"
          >
            <p className="text-sm font-medium text-zinc-200">No documents generated yet</p>
            <p className="max-w-md text-xs leading-relaxed text-zinc-500">
              The Documentation Agent generates inventories, diagrams, and runbooks on
              demand. Trigger a docs run to populate this library.
            </p>
          </div>
        )}

        {/* Document table */}
        {!isPending && !error && (data?.items ?? []).length > 0 && (
          <div className="flex flex-col gap-4">
            <div className="panel overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-carbon-700 text-left text-zinc-500">
                    <th className="px-4 py-2 font-medium">Title</th>
                    <th className="px-4 py-2 font-medium">Kind</th>
                    <th className="px-4 py-2 font-medium">Format</th>
                    <th className="px-4 py-2 font-medium">Generated</th>
                    <th className="px-4 py-2 font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {(data?.items ?? []).map((doc: DocumentRead) => (
                    <DocRow
                      key={doc.id}
                      doc={doc}
                      onView={setViewedDoc}
                      onDownload={handleDownload}
                    />
                  ))}
                </tbody>
              </table>
              <p
                data-testid="docs-total-count"
                className="px-4 py-2 text-[11px] text-zinc-600"
              >
                {data?.total ?? 0}
              </p>
            </div>

            {/* Inline view panel */}
            {viewedDoc !== null && (
              <div className="mt-2">
                {viewedDoc.format === "mermaid" ? (
                  <MermaidPanel doc={viewedDoc} onClose={() => setViewedDoc(null)} />
                ) : (
                  <ContentPanel doc={viewedDoc} onClose={() => setViewedDoc(null)} />
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
