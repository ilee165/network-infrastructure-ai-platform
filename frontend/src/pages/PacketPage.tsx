/**
 * Packet: capture-launch control + analysis view.
 *
 * Two sub-views (tabs):
 *  - Launch — form to start an async capture (POST /agents/captures; engineer+).
 *    Returns the capture id which the user can then poll or paste into Analysis.
 *  - Analysis — enter a capture id to view findings: top talkers, protocol
 *    hierarchy, TCP-anomaly counts (GET /agents/captures/{id}/analysis).
 *    Read-only; never exposes raw packet bytes (ADR-0023 §1).
 *
 * Mirror of the M4 DocumentsPage / ConfigPage tab pattern.
 */

import { useState } from "react";
import {
  getCaptureAnalysis,
  launchCapture,
  type CaptureLaunchResponse,
  type PacketFindings,
} from "../api/packet";
import { PageHeader } from "../components/PageHeader";

// ── Tab types ─────────────────────────────────────────────────────────────────

type PacketTab = "launch" | "analysis";

// ── Capture Launch ────────────────────────────────────────────────────────────

/**
 * Capture-launch form. Collects the mandatory interface and optional BPF filter
 * / duration, then POSTs to the T15 ``/agents/captures`` endpoint. On success
 * shows the queued capture id so the user can paste it into the Analysis tab.
 */
function CaptureLaunchForm() {
  const [iface, setIface] = useState("");
  const [filter, setFilter] = useState("");
  const [duration, setDuration] = useState("");
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<CaptureLaunchResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleLaunch(e: React.FormEvent): Promise<void> {
    e.preventDefault();
    if (!iface.trim()) return;
    setPending(true);
    setError(null);
    setResult(null);
    try {
      const resp = await launchCapture({
        interface: iface.trim(),
        capture_filter: filter.trim() || null,
        duration_seconds: duration ? Number(duration) : null,
      });
      setResult(resp);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Launch failed");
    } finally {
      setPending(false);
    }
  }

  return (
    <section aria-label="Launch capture" className="flex flex-col gap-6">
      <form
        data-testid="capture-launch-form"
        onSubmit={(e) => void handleLaunch(e)}
        className="panel flex flex-col gap-4 p-4"
      >
        <h2 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          Launch packet capture
        </h2>

        {/* Interface */}
        <div className="flex flex-col gap-1">
          <label htmlFor="capture-interface" className="text-[11px] text-zinc-400">
            Interface / segment <span className="text-status-error">*</span>
          </label>
          <input
            id="capture-interface"
            data-testid="capture-interface"
            type="text"
            value={iface}
            onChange={(e) => setIface(e.target.value)}
            placeholder="eth0 or GigabitEthernet0/0"
            required
            className="input w-72"
          />
        </div>

        {/* BPF filter */}
        <div className="flex flex-col gap-1">
          <label htmlFor="capture-filter" className="text-[11px] text-zinc-400">
            BPF filter (optional)
          </label>
          <input
            id="capture-filter"
            data-testid="capture-filter"
            type="text"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="host 10.0.0.1 or port 443"
            className="input w-72"
          />
        </div>

        {/* Duration */}
        <div className="flex flex-col gap-1">
          <label htmlFor="capture-duration" className="text-[11px] text-zinc-400">
            Duration (seconds, optional)
          </label>
          <input
            id="capture-duration"
            data-testid="capture-duration"
            type="number"
            min={1}
            max={3600}
            value={duration}
            onChange={(e) => setDuration(e.target.value)}
            placeholder="30"
            className="input w-32"
          />
        </div>

        <div>
          <button
            type="submit"
            data-testid="capture-launch-btn"
            disabled={pending || !iface.trim()}
            className="btn"
          >
            {pending ? "Launching…" : "Launch capture"}
          </button>
        </div>
      </form>

      {/* Success */}
      {result !== null && (
        <div
          data-testid="capture-launch-result"
          className="panel border-status-ok/40 px-4 py-3"
        >
          <p className="mb-1 font-mono text-xs uppercase tracking-wider text-status-ok">
            Queued
          </p>
          <p className="font-mono text-xs text-zinc-300">
            Capture ID:{" "}
            <span data-testid="capture-id" className="text-zinc-100">
              {result.capture_id}
            </span>
          </p>
          <p className="mt-1 font-mono text-[11px] text-zinc-500">
            Interface: {result.interface} · Status: {result.status}
          </p>
          <p className="mt-2 text-[11px] text-zinc-500">
            Poll the Analysis tab with this capture id once the worker completes.
          </p>
        </div>
      )}

      {/* Error */}
      {error !== null && (
        <div
          data-testid="capture-launch-error"
          role="alert"
          className="panel border-status-error/40 px-4 py-3 text-xs text-status-error"
        >
          Launch failed: {error}
        </div>
      )}
    </section>
  );
}

// ── Capture Analysis ──────────────────────────────────────────────────────────

/**
 * Analysis view: enter a capture id, fetch findings (top talkers / protocols /
 * TCP anomalies). Read-only; no raw packet content (ADR-0023 §1).
 */
function CaptureAnalysisView() {
  const [captureId, setCaptureId] = useState("");
  const [displayFilter, setDisplayFilter] = useState("");
  const [pending, setPending] = useState(false);
  const [findings, setFindings] = useState<PacketFindings | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleAnalyze(e: React.FormEvent): Promise<void> {
    e.preventDefault();
    const id = captureId.trim();
    if (!id) return;
    setPending(true);
    setError(null);
    setFindings(null);
    try {
      const result = await getCaptureAnalysis(id, displayFilter.trim() || undefined);
      setFindings(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Analysis failed");
    } finally {
      setPending(false);
    }
  }

  return (
    <section aria-label="Capture analysis" className="flex flex-col gap-6">
      <form
        data-testid="capture-analysis-form"
        onSubmit={(e) => void handleAnalyze(e)}
        className="panel flex flex-col gap-4 p-4"
      >
        <h2 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          View capture analysis
        </h2>

        <div className="flex flex-col gap-1">
          <label htmlFor="analysis-capture-id" className="text-[11px] text-zinc-400">
            Capture ID <span className="text-status-error">*</span>
          </label>
          <input
            id="analysis-capture-id"
            data-testid="analysis-capture-id"
            type="text"
            value={captureId}
            onChange={(e) => setCaptureId(e.target.value)}
            placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            required
            className="input w-96"
          />
        </div>

        <div className="flex flex-col gap-1">
          <label htmlFor="analysis-display-filter" className="text-[11px] text-zinc-400">
            Display filter (optional)
          </label>
          <input
            id="analysis-display-filter"
            data-testid="analysis-display-filter"
            type="text"
            value={displayFilter}
            onChange={(e) => setDisplayFilter(e.target.value)}
            placeholder="tcp.port == 443"
            className="input w-72"
          />
        </div>

        <div>
          <button
            type="submit"
            data-testid="analysis-fetch-btn"
            disabled={pending || !captureId.trim()}
            className="btn"
          >
            {pending ? "Loading…" : "Fetch analysis"}
          </button>
        </div>
      </form>

      {/* Error */}
      {error !== null && (
        <div
          data-testid="analysis-error"
          role="alert"
          className="panel border-status-error/40 px-4 py-3 text-xs text-status-error"
        >
          Analysis failed: {error}
        </div>
      )}

      {/* Findings */}
      {findings !== null && (
        <div data-testid="analysis-findings" className="flex flex-col gap-4">
          {/* Summary strip */}
          <div className="panel grid grid-cols-3 gap-4 px-4 py-3">
            <div className="flex flex-col gap-0.5">
              <dt className="text-[10px] uppercase tracking-wider text-zinc-600">Packets</dt>
              <dd data-testid="findings-packet-count" className="font-mono text-lg text-zinc-200">
                {findings.packet_count.toLocaleString()}
              </dd>
            </div>
            <div className="flex flex-col gap-0.5">
              <dt className="text-[10px] uppercase tracking-wider text-zinc-600">TCP resets</dt>
              <dd
                data-testid="findings-tcp-resets"
                className={`font-mono text-lg ${findings.tcp_resets > 0 ? "text-status-error" : "text-zinc-200"}`}
              >
                {findings.tcp_resets.toLocaleString()}
              </dd>
            </div>
            <div className="flex flex-col gap-0.5">
              <dt className="text-[10px] uppercase tracking-wider text-zinc-600">
                Retransmissions
              </dt>
              <dd
                data-testid="findings-tcp-retx"
                className={`font-mono text-lg ${findings.tcp_retransmissions > 0 ? "text-status-warn" : "text-zinc-200"}`}
              >
                {findings.tcp_retransmissions.toLocaleString()}
              </dd>
            </div>
          </div>

          {/* Top talkers */}
          {findings.top_talkers.length > 0 && (
            <div className="panel overflow-x-auto">
              <h3 className="border-b border-carbon-700 px-4 py-2 font-mono text-xs uppercase tracking-widest text-zinc-500">
                Top talkers
              </h3>
              <table
                data-testid="top-talkers-table"
                className="w-full text-xs"
              >
                <thead>
                  <tr className="border-b border-carbon-700 text-left text-zinc-500">
                    <th className="px-4 py-2 font-medium">Source</th>
                    <th className="px-4 py-2 font-medium">Destination</th>
                    <th className="px-4 py-2 font-medium text-right">Packets</th>
                    <th className="px-4 py-2 font-medium text-right">Bytes</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.top_talkers.map((conv, i) => (
                    <tr
                      key={`${conv.src}→${conv.dst}-${i}`}
                      data-testid={`talker-row-${i}`}
                      className="border-b border-carbon-800 last:border-0"
                    >
                      <td className="px-4 py-2 font-mono text-zinc-300">{conv.src}</td>
                      <td className="px-4 py-2 font-mono text-zinc-300">{conv.dst}</td>
                      <td className="px-4 py-2 font-mono text-right text-zinc-400">
                        {conv.packets.toLocaleString()}
                      </td>
                      <td className="px-4 py-2 font-mono text-right text-zinc-400">
                        {conv.bytes.toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Protocol hierarchy */}
          {findings.protocol_hierarchy.length > 0 && (
            <div className="panel overflow-x-auto">
              <h3 className="border-b border-carbon-700 px-4 py-2 font-mono text-xs uppercase tracking-widest text-zinc-500">
                Protocol hierarchy
              </h3>
              <table
                data-testid="protocol-table"
                className="w-full text-xs"
              >
                <thead>
                  <tr className="border-b border-carbon-700 text-left text-zinc-500">
                    <th className="px-4 py-2 font-medium">Protocol</th>
                    <th className="px-4 py-2 font-medium text-right">Packets</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.protocol_hierarchy.map((proto, i) => (
                    <tr
                      key={`${proto.protocol}-${i}`}
                      data-testid={`proto-row-${i}`}
                      className="border-b border-carbon-800 last:border-0"
                    >
                      <td className="px-4 py-2 font-mono text-zinc-300">{proto.protocol}</td>
                      <td className="px-4 py-2 font-mono text-right text-zinc-400">
                        {proto.packets.toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Empty findings state */}
          {findings.top_talkers.length === 0 && findings.protocol_hierarchy.length === 0 && (
            <div
              data-testid="findings-empty"
              className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-carbon-600 bg-carbon-900/50 px-6 py-12 text-center"
            >
              <p className="text-sm font-medium text-zinc-200">No conversations found</p>
              <p className="text-xs text-zinc-500">
                The capture may be empty or the display filter matched no packets.
              </p>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export function PacketPage() {
  const [tab, setTab] = useState<PacketTab>("launch");

  const tabBtn = (t: PacketTab, label: string) => (
    <button
      key={t}
      type="button"
      role="tab"
      aria-selected={tab === t}
      data-testid={`packet-tab-${t}`}
      onClick={() => setTab(t)}
      className={`px-4 py-2 text-xs font-medium transition-colors ${
        tab === t
          ? "border-b-2 border-accent text-zinc-100"
          : "text-zinc-500 hover:text-zinc-300"
      }`}
    >
      {label}
    </button>
  );

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Packet Analysis"
        description="Launch on-demand packet captures (engineer+) and view normalized findings: top talkers, protocol hierarchy, and TCP anomaly indicators. Raw packet bytes never leave the capture worker (ADR-0023)."
      />

      {/* Tab bar */}
      <div
        className="flex gap-1 border-b border-carbon-700"
        role="tablist"
        aria-label="Packet views"
      >
        {tabBtn("launch", "Launch")}
        {tabBtn("analysis", "Analysis")}
      </div>

      {/* Tab panel */}
      <div
        role="tabpanel"
        data-testid={`packet-panel-${tab}`}
      >
        {tab === "launch" ? <CaptureLaunchForm /> : <CaptureAnalysisView />}
      </div>
    </div>
  );
}
