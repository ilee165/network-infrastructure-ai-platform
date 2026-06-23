#!/usr/bin/env node
// npm-audit gate (P1 W6-T4, ADR-0016 D16 pipeline).
//
// npm audit has no native ignore file. This script makes `npm audit` a RED gate
// with a REVIEWED, EXPIRING allowlist (mirrors the .trivyignore convention):
//
//   npm audit --json | node scripts/npm-audit-gate.mjs
//
// It exits 1 (fails the CI job) when any advisory at or above the configured
// severity floor is present and is NOT covered by a non-expired allowlist entry
// in .npm-audit-allowlist.json. It exits 0 only when every such advisory is
// explicitly, currently allowlisted. It also exits 1 if an allowlist entry is
// EXPIRED or matches NOTHING (stale entry => re-review), so the allowlist cannot
// silently rot open.
//
// Offline/self-hosted-fork-friendly: pure Node stdlib, no network, no extra deps.
// Triage policy: docs/security/supply-chain-scanning.md.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const SEV_ORDER = { info: 0, low: 1, moderate: 2, high: 3, critical: 4 };
const here = dirname(fileURLToPath(import.meta.url));
const allowlistPath = join(here, "..", ".npm-audit-allowlist.json");

function fail(msg) {
  console.error(`npm-audit-gate: ${msg}`);
  process.exit(1);
}

// --- read npm audit --json from stdin ---
let raw = "";
try {
  raw = readFileSync(0, "utf8");
} catch (e) {
  fail(`could not read npm audit JSON from stdin: ${e.message}`);
}
let audit;
try {
  audit = JSON.parse(raw);
} catch (e) {
  fail(`stdin was not valid JSON (did you pipe \`npm audit --json\`?): ${e.message}`);
}

// --- validate the input is a GENUINE npm audit report, not an error envelope ---
// CI masks npm's exit code (`npm audit --json > npm-audit.json || true`) so this
// gate is the sole pass/fail authority. When `npm audit` fails (registry 5xx,
// offline mirror, network blip) npm still emits VALID JSON — an error envelope
// like {"error":{...}} — or a truncated report with no `vulnerabilities` block.
// Accepting that as "zero advisories => PASS" is a false-green: the gate would
// silently NOT BITE on a failed audit. A real report carries an
// `auditReportVersion` (npm v7+ schema) AND a `vulnerabilities` object. Require
// both, and reject any error envelope, so a failed audit is a RED gate.
if (audit == null || typeof audit !== "object" || Array.isArray(audit)) {
  fail("npm audit did not produce a JSON object report (audit run failed?)");
}
if (audit.error) {
  const code = audit.error.code ?? audit.error.summary ?? JSON.stringify(audit.error);
  fail(`npm audit reported an error, not a report (audit run failed?): ${code}`);
}
if (audit.auditReportVersion == null || audit.vulnerabilities == null) {
  fail(
    "npm audit output is not a complete report (missing auditReportVersion/vulnerabilities — audit run failed?)",
  );
}

// --- load reviewed allowlist ---
let allowlist;
try {
  allowlist = JSON.parse(readFileSync(allowlistPath, "utf8"));
} catch (e) {
  fail(`could not read allowlist ${allowlistPath}: ${e.message}`);
}
// Validate severityFloor up front. An unrecognized value would otherwise make
// `floor` undefined, and every `severity < undefined` comparison is false, so NO
// findings would be collected — the gate would silently NOT BITE (false-green).
// Fail fast instead (CR15).
const severityFloor = allowlist.severityFloor ?? "high";
if (!(severityFloor in SEV_ORDER)) {
  fail(
    `allowlist.severityFloor "${severityFloor}" is not one of ${Object.keys(SEV_ORDER).join(", ")}`,
  );
}
const floor = SEV_ORDER[severityFloor];
const today = new Date();
const allowByGhsa = new Map();
for (const entry of allowlist.allow ?? []) {
  if (!entry.ghsa) fail(`allowlist entry missing "ghsa": ${JSON.stringify(entry)}`);
  if (!entry.expires) fail(`allowlist entry ${entry.ghsa} missing "expires" (re-review date)`);
  if (!entry.justification) fail(`allowlist entry ${entry.ghsa} missing "justification"`);
  const exp = new Date(entry.expires);
  if (Number.isNaN(exp.getTime())) fail(`allowlist entry ${entry.ghsa} has invalid "expires"`);
  allowByGhsa.set(entry.ghsa, { ...entry, expDate: exp, matched: false });
}

// --- collect advisories at/above the floor from the npm audit report (npm v7+ schema) ---
// Each vulnerability's `via` array holds either advisory objects (with .url/.source)
// or strings (names of other vulnerable packages). We key on the GHSA id parsed
// from the advisory URL so the allowlist is stable across npm-version output churn.
const findings = []; // { ghsa, package, severity }
for (const [pkg, vuln] of Object.entries(audit.vulnerabilities ?? {})) {
  for (const via of vuln.via ?? []) {
    if (typeof via !== "object" || !via.url) continue;
    const m = /GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/i.exec(via.url);
    if (!m) continue;
    if ((SEV_ORDER[via.severity] ?? 0) < floor) continue;
    findings.push({ ghsa: m[0], package: via.title ? `${pkg} (${via.title})` : pkg, severity: via.severity });
  }
}

// --- evaluate ---
const blocking = [];
for (const f of findings) {
  const entry = allowByGhsa.get(f.ghsa);
  if (!entry) {
    blocking.push(`${f.severity.toUpperCase()} ${f.ghsa} in ${f.package} — NOT allowlisted`);
    continue;
  }
  if (entry.expDate < today) {
    blocking.push(
      `${f.severity.toUpperCase()} ${f.ghsa} in ${f.package} — allowlist entry EXPIRED ${entry.expires} (re-review)`,
    );
    continue;
  }
  entry.matched = true;
}

// allowlist-hygiene guards over EVERY entry (matched or not):
//   - EXPIRED: an entry past its re-review date is an error whether or not it
//     matched a current finding. The evaluate loop above only catches an expired
//     entry when a live finding maps to it; an expired entry that matches NOTHING
//     would otherwise slip through silently and could later mask a new advisory
//     once its GHSA reappears (CR16). Expiry is enforced unconditionally here.
//   - STALE: a NON-expired entry that matched no current finding is dead weight
//     that can later mask a new advisory — force re-review.
for (const e of allowByGhsa.values()) {
  if (e.expDate < today) {
    blocking.push(
      `allowlist entry ${e.ghsa} EXPIRED ${e.expires} — re-review or remove (expiry enforced even when it matches no current advisory)`,
    );
  } else if (!e.matched) {
    blocking.push(`allowlist entry ${e.ghsa} matched no current advisory — stale, remove or re-review`);
  }
}

if (blocking.length) {
  console.error(`npm-audit-gate: FAIL (severity floor = ${allowlist.severityFloor})`);
  for (const b of blocking) console.error(`  - ${b}`);
  process.exit(1);
}

const allowed = [...allowByGhsa.values()].filter((e) => e.matched).map((e) => e.ghsa);
console.log(
  `npm-audit-gate: PASS — no un-allowlisted advisories at/above ${allowlist.severityFloor}.` +
    (allowed.length ? ` Allowlisted (reviewed, non-expired): ${allowed.join(", ")}.` : ""),
);
process.exit(0);
