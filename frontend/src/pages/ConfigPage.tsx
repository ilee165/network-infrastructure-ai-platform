/**
 * Config Management: snapshots list, drift diff view, and compliance posture.
 *
 * Three sub-views for a selected device (tabs):
 *  - Snapshots  — paginated list (metadata only; no content per ADR-0017)
 *  - Drift      — unified diff rendering against the approved baseline
 *  - Compliance — findings by severity (info / warn / violation)
 *
 * Wired to the T14 endpoints via ``api/config.ts``.  All views are read-only
 * in M4 — no write paths exposed (ADR-0017 §4).
 */

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import {
  getDeviceCompliance,
  getDeviceDrift,
  listConfigSnapshots,
  type ComplianceRunResponse,
  type ConfigSnapshotListResponse,
  type ConfigSnapshotRead,
  type DriftResponse,
  type FindingRead,
  type FindingStatus,
  type Severity,
} from "../api/config";
import { listDevices, type DeviceRead } from "../api/devices";
import { PageHeader } from "../components/PageHeader";

// ── Constants ─────────────────────────────────────────────────────────────────

const PILL_BASE =
  "inline-flex items-center rounded border px-2 py-0.5 font-mono text-[11px] uppercase tracking-wider";

// ── Severity badge ────────────────────────────────────────────────────────────

const SEVERITY_STYLES: Record<Severity, string> = {
  info: "border-accent/40 bg-accent/10 text-accent",
  warn: "border-status-warn/40 bg-status-warn/10 text-status-warn",
  violation: "border-status-error/40 bg-status-error/10 text-status-error",
};

const FINDING_STATUS_STYLES: Record<FindingStatus, string> = {
  pass: "border-status-ok/40 bg-status-ok/10 text-status-ok",
  violation: "border-status-error/40 bg-status-error/10 text-status-error",
  skipped: "border-carbon-600 bg-carbon-800 text-zinc-400",
};

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      data-testid={`severity-${severity}`}
      className={`${PILL_BASE} ${SEVERITY_STYLES[severity]}`}
    >
      {severity}
    </span>
  );
}

function FindingStatusBadge({ status }: { status: FindingStatus }) {
  return (
    <span
      data-testid={`finding-status-${status}`}
      className={`${PILL_BASE} ${FINDING_STATUS_STYLES[status]}`}
    >
      {status}
    </span>
  );
}

// ── Device selector ───────────────────────────────────────────────────────────

function DeviceSelector({
  devices,
  selectedId,
  onSelect,
}: {
  devices: DeviceRead[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  return (
    <div className="flex items-center gap-3">
      <label
        htmlFor="config-device-select"
        className="font-mono text-[11px] uppercase tracking-widest text-zinc-500"
      >
        Device
      </label>
      <select
        id="config-device-select"
        data-testid="config-device-select"
        value={selectedId ?? ""}
        onChange={(e) => onSelect(e.target.value)}
        className="input w-64"
      >
        <option value="">Select a device…</option>
        {devices.map((d) => (
          <option key={d.id} value={d.id}>
            {d.hostname} ({d.mgmt_ip})
          </option>
        ))}
      </select>
    </div>
  );
}

// ── Snapshots tab ─────────────────────────────────────────────────────────────

function BaselineBadge({ baseline }: { baseline: boolean }) {
  if (!baseline) return null;
  return (
    <span className="border-accent/40 bg-accent/10 text-accent inline-flex items-center rounded border px-2 py-0.5 font-mono text-[11px] uppercase tracking-wider">
      baseline
    </span>
  );
}

function SnapshotsPanel({ deviceId }: { deviceId: string }) {
  const { data, isPending, error } = useQuery<ConfigSnapshotListResponse>({
    queryKey: ["config-snapshots", deviceId],
    queryFn: () => listConfigSnapshots(deviceId, { limit: 50 }),
  });

  if (isPending) {
    return (
      <p role="status" className="text-xs text-zinc-500">
        Loading snapshots…
      </p>
    );
  }
  if (error) {
    return (
      <div
        role="alert"
        className="panel border-status-error/40 px-4 py-3 text-xs text-status-error"
      >
        Snapshots load failed: {error.message}
      </div>
    );
  }

  const items = data?.items ?? [];

  if (items.length === 0) {
    return (
      <div
        data-testid="snapshots-empty-state"
        className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-carbon-600 bg-carbon-900/50 px-6 py-16 text-center"
      >
        <p className="text-sm font-medium text-zinc-200">No snapshots captured yet</p>
        <p className="max-w-md text-xs leading-relaxed text-zinc-500">
          The config engine captures snapshots on a nightly schedule or on-demand. Run a
          config backup to populate this view.
        </p>
      </div>
    );
  }

  return (
    <div className="panel overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-carbon-700 text-left text-zinc-500">
            <th className="px-4 py-2 font-medium">Captured At</th>
            <th className="px-4 py-2 font-medium">Source</th>
            <th className="px-4 py-2 font-medium">Content Hash</th>
            <th className="px-4 py-2 font-medium">Baseline</th>
            <th className="px-4 py-2 font-medium">Snapshot ID</th>
          </tr>
        </thead>
        <tbody>
          {items.map((snap: ConfigSnapshotRead) => (
            <tr
              key={snap.id}
              data-testid={`snapshot-row-${snap.id}`}
              className="border-b border-carbon-800 last:border-0"
            >
              <td className="px-4 py-2 font-mono text-zinc-300">
                {new Date(snap.captured_at).toLocaleString()}
              </td>
              <td className="px-4 py-2 font-mono uppercase text-zinc-400">{snap.source}</td>
              <td className="px-4 py-2 font-mono text-[11px] text-zinc-500">
                {snap.content_hash.slice(0, 16)}…
              </td>
              <td className="px-4 py-2">
                <BaselineBadge baseline={snap.baseline} />
                {!snap.baseline && <span className="text-zinc-600">—</span>}
              </td>
              <td className="px-4 py-2 font-mono text-[11px] text-zinc-600">
                {snap.id.slice(0, 8)}…
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="px-4 py-2 text-[11px] text-zinc-600">
        {data?.total ?? 0} snapshot{(data?.total ?? 0) !== 1 ? "s" : ""} total
      </p>
    </div>
  );
}

// ── Drift tab ─────────────────────────────────────────────────────────────────

/**
 * Renders a unified diff with coloured +/- lines.
 * Lines starting with "+" are green, "-" are red, "@@ … @@" are accent,
 * and context lines are zinc-400.
 */
function UnifiedDiff({ diff }: { diff: string }) {
  const lines = diff.split("\n");
  return (
    <pre
      data-testid="unified-diff"
      aria-label="Unified diff"
      className="overflow-x-auto rounded bg-carbon-950 p-4 font-mono text-[11px] leading-relaxed"
    >
      {lines.map((line, i) => {
        let color = "text-zinc-400";
        if (line.startsWith("+")) color = "text-status-ok";
        else if (line.startsWith("-")) color = "text-status-error";
        else if (line.startsWith("@@")) color = "text-accent";
        return (
          <span key={i} className={`block ${color}`}>
            {line || " "}
          </span>
        );
      })}
    </pre>
  );
}

function DriftPanel({ deviceId }: { deviceId: string }) {
  const { data, isPending, error } = useQuery<DriftResponse>({
    queryKey: ["device-drift", deviceId],
    queryFn: () => getDeviceDrift(deviceId),
  });

  if (isPending) {
    return (
      <p role="status" className="text-xs text-zinc-500">
        Loading drift…
      </p>
    );
  }
  if (error) {
    return (
      <div
        role="alert"
        data-testid="drift-error"
        className="panel border-status-error/40 px-4 py-3 text-xs text-status-error"
      >
        Drift check failed: {error.message}
      </div>
    );
  }

  if (!data) return null;

  return (
    <div className="flex flex-col gap-4">
      {/* Summary row */}
      <div className="flex flex-wrap items-center gap-4 text-xs">
        <div className="flex items-center gap-2">
          <span className="text-zinc-500">Drift detected:</span>
          <span
            data-testid="drift-has-drift"
            className={data.has_drift ? "text-status-error font-semibold" : "text-status-ok"}
          >
            {data.has_drift ? "Yes" : "No"}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-zinc-500">Baseline hash:</span>
          <span className="font-mono text-[11px] text-zinc-400">
            {data.baseline_hash.slice(0, 16)}…
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-zinc-500">Current hash:</span>
          <span className="font-mono text-[11px] text-zinc-400">
            {data.current_hash.slice(0, 16)}…
          </span>
        </div>
      </div>

      {/* Diff view */}
      {data.has_drift ? (
        <UnifiedDiff diff={data.diff} />
      ) : (
        <div
          data-testid="drift-no-change"
          className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-carbon-600 bg-carbon-900/50 px-6 py-12 text-center"
        >
          <p className="text-sm font-medium text-status-ok">No drift detected</p>
          <p className="text-xs text-zinc-500">
            The current configuration matches the approved baseline.
          </p>
        </div>
      )}

      {/* Hunks summary */}
      {data.hunks.length > 0 && (
        <section aria-label="Diff hunks">
          <h4 className="mb-2 font-mono text-[11px] uppercase tracking-widest text-zinc-500">
            Hunks ({data.hunks.length})
          </h4>
          <ul className="flex flex-col gap-1">
            {data.hunks.map((hunk, i) => (
              <li
                key={i}
                data-testid={`drift-hunk-${i}`}
                className="font-mono text-[11px] text-accent"
              >
                {hunk}
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

// ── Compliance tab ────────────────────────────────────────────────────────────

function ComplianceSummaryBar({ data }: { data: ComplianceRunResponse }) {
  return (
    <div className="flex flex-wrap gap-4 text-xs">
      <div className="flex items-center gap-2">
        <span className="text-zinc-500">Violations:</span>
        <span
          data-testid="compliance-violation-count"
          className={
            data.violation_count > 0
              ? "font-semibold text-status-error"
              : "text-zinc-400"
          }
        >
          {data.violation_count}
        </span>
      </div>
      <div className="flex items-center gap-2">
        <span className="text-zinc-500">Warns:</span>
        <span
          data-testid="compliance-warn-count"
          className={data.warn_count > 0 ? "font-semibold text-status-warn" : "text-zinc-400"}
        >
          {data.warn_count}
        </span>
      </div>
      <div className="flex items-center gap-2">
        <span className="text-zinc-500">Pass:</span>
        <span data-testid="compliance-pass-count" className="text-status-ok">
          {data.pass_count}
        </span>
      </div>
      <div className="flex items-center gap-2">
        <span className="text-zinc-500">Skipped:</span>
        <span data-testid="compliance-skipped-count" className="text-zinc-400">
          {data.skipped_count}
        </span>
      </div>
      <div className="flex items-center gap-2">
        <span className="text-zinc-500">Policy:</span>
        <span className="font-mono text-zinc-400">
          {data.policy_id} v{data.policy_version}
        </span>
      </div>
    </div>
  );
}

function FindingRow({ finding }: { finding: FindingRead }) {
  return (
    <tr
      data-testid={`finding-row-${finding.rule_id}`}
      className="border-b border-carbon-800 last:border-0"
    >
      <td className="px-4 py-2 font-mono text-zinc-200">{finding.rule_id}</td>
      <td className="px-4 py-2">
        <SeverityBadge severity={finding.severity} />
      </td>
      <td className="px-4 py-2">
        <FindingStatusBadge status={finding.status} />
      </td>
      <td className="px-4 py-2 text-zinc-500 max-w-xs truncate" title={finding.evidence}>
        {finding.evidence || "—"}
      </td>
    </tr>
  );
}

function CompliancePanel({ deviceId }: { deviceId: string }) {
  const { data, isPending, error } = useQuery<ComplianceRunResponse>({
    queryKey: ["device-compliance", deviceId],
    queryFn: () => getDeviceCompliance(deviceId),
  });

  if (isPending) {
    return (
      <p role="status" className="text-xs text-zinc-500">
        Loading compliance…
      </p>
    );
  }
  if (error) {
    return (
      <div
        role="alert"
        data-testid="compliance-error"
        className="panel border-status-error/40 px-4 py-3 text-xs text-status-error"
      >
        Compliance check failed: {error.message}
      </div>
    );
  }

  if (!data) return null;

  const violations = data.findings.filter((f) => f.status === "violation");
  const passes = data.findings.filter((f) => f.status === "pass");
  const skipped = data.findings.filter((f) => f.status === "skipped");

  // Display order: violations first, then passes, then skipped.
  const ordered: FindingRead[] = [...violations, ...passes, ...skipped];

  return (
    <div className="flex flex-col gap-4">
      <ComplianceSummaryBar data={data} />

      {ordered.length === 0 ? (
        <div
          data-testid="compliance-empty-state"
          className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-carbon-600 bg-carbon-900/50 px-6 py-12 text-center"
        >
          <p className="text-sm font-medium text-zinc-200">No findings</p>
          <p className="text-xs text-zinc-500">No rules evaluated for this device.</p>
        </div>
      ) : (
        <div className="panel overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-carbon-700 text-left text-zinc-500">
                <th className="px-4 py-2 font-medium">Rule</th>
                <th className="px-4 py-2 font-medium">Severity</th>
                <th className="px-4 py-2 font-medium">Status</th>
                <th className="px-4 py-2 font-medium">Evidence</th>
              </tr>
            </thead>
            <tbody>
              {ordered.map((f) => (
                <FindingRow key={`${f.rule_id}-${f.status}`} finding={f} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── Tab types ─────────────────────────────────────────────────────────────────

type ConfigTab = "snapshots" | "drift" | "compliance";

// ── Page ──────────────────────────────────────────────────────────────────────

export function ConfigPage() {
  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>(null);
  const [tab, setTab] = useState<ConfigTab>("snapshots");

  const { data: devicesData, isPending: devicesLoading } = useQuery({
    queryKey: ["devices"],
    queryFn: () => listDevices({ limit: 500 }),
  });

  const devices = devicesData?.items ?? [];

  const tabBtn = (t: ConfigTab, label: string) => (
    <button
      type="button"
      role="tab"
      aria-selected={tab === t}
      aria-controls={`config-tabpanel-${t}`}
      data-testid={`config-tab-${t}`}
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
        title="Config Management"
        description="Scheduled backups, drift detection, and compliance posture for managed devices."
      />

      {/* Device selector */}
      <section aria-label="Device selection" className="flex flex-col gap-3">
        {devicesLoading ? (
          <p className="text-xs text-zinc-500">Loading devices…</p>
        ) : (
          <DeviceSelector
            devices={devices}
            selectedId={selectedDeviceId}
            onSelect={setSelectedDeviceId}
          />
        )}
      </section>

      {/* No device selected prompt */}
      {!selectedDeviceId && !devicesLoading && (
        <div
          data-testid="config-no-device"
          className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-carbon-600 bg-carbon-900/50 px-6 py-16 text-center"
        >
          <p className="text-sm font-medium text-zinc-200">Select a device to begin</p>
          <p className="max-w-md text-xs leading-relaxed text-zinc-500">
            Choose a device from the dropdown above to view its config snapshots, drift
            against the approved baseline, and compliance posture.
          </p>
        </div>
      )}

      {/* Tabs + content */}
      {selectedDeviceId && (
        <section aria-label="Config sub-views" className="flex flex-col gap-0">
          {/* Tab bar */}
          <div
            className="flex gap-1 border-b border-carbon-700"
            role="tablist"
            aria-label="Config views"
          >
            {tabBtn("snapshots", "Snapshots")}
            {tabBtn("drift", "Drift")}
            {tabBtn("compliance", "Compliance")}
          </div>

          {/* Tab panel */}
          <div
            role="tabpanel"
            id={`config-tabpanel-${tab}`}
            aria-labelledby={`config-tab-${tab}`}
            className="pt-4"
          >
            {tab === "snapshots" && <SnapshotsPanel deviceId={selectedDeviceId} />}
            {tab === "drift" && <DriftPanel deviceId={selectedDeviceId} />}
            {tab === "compliance" && <CompliancePanel deviceId={selectedDeviceId} />}
          </div>
        </section>
      )}
    </div>
  );
}
