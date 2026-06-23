#!/usr/bin/env node
// Negative-validation harness for the npm-audit RED gate (P1 W6-T4).
//
//   node scripts/npm-audit-gate.negative.mjs
//
// Proves the gate (scripts/npm-audit-gate.mjs) BITES — exits non-zero — on the
// two failure modes the spec requires demonstrable negative validation for:
//   1. a known-vulnerable dep (planted GHSA NOT in the allowlist)  -> exit 1
//   2. a FAILED/incomplete audit (error envelope, masked by `|| true`) -> exit 1
// and STILL passes a genuinely clean report -> exit 0.
//
// Pure Node stdlib, no network, no live-tree mutation. The fixtures under
// scripts/__fixtures__/ are evidence-only (CI never consumes them). Run this on
// any host with node; see docs/security/supply-chain-scanning.md.
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const gate = join(here, "npm-audit-gate.mjs");
const fixtures = join(here, "__fixtures__");

// A report carrying exactly the two currently-allowlisted advisories (so the
// gate's stale-entry guard is satisfied) and NO un-allowlisted high/critical —
// i.e. the steady-state "clean modulo reviewed allowlist" the live tree is in.
const allowlist = JSON.parse(readFileSync(join(here, "..", ".npm-audit-allowlist.json"), "utf8"));
const CLEAN = JSON.stringify({
  auditReportVersion: 2,
  vulnerabilities: Object.fromEntries(
    (allowlist.allow ?? []).map((e) => [
      e.package,
      {
        name: e.package,
        severity: e.severity,
        via: [{ url: `https://github.com/advisories/${e.ghsa}`, severity: e.severity, title: e.advisory }],
      },
    ]),
  ),
  metadata: { vulnerabilities: { total: (allowlist.allow ?? []).length } },
});

const cases = [
  { name: "clean modulo reviewed allowlist", input: CLEAN, expectExit: 0 },
  {
    name: "planted known-vuln dep (high, not allowlisted)",
    input: readFileSync(join(fixtures, "npm-audit-planted-vuln.json"), "utf8"),
    expectExit: 1,
  },
  {
    name: "failed audit run (error envelope, would be false-green)",
    input: readFileSync(join(fixtures, "npm-audit-failed-run.json"), "utf8"),
    expectExit: 1,
  },
];

let ok = true;
for (const c of cases) {
  const r = spawnSync(process.execPath, [gate], { input: c.input, encoding: "utf8" });
  const got = r.status;
  const pass = got === c.expectExit;
  ok = ok && pass;
  console.log(`${pass ? "OK  " : "FAIL"} ${c.name}: expected exit ${c.expectExit}, got ${got}`);
  if (!pass) console.log(`     stderr: ${(r.stderr || "").trim()}`);
}

if (!ok) {
  console.error("npm-audit-gate negative validation FAILED");
  process.exit(1);
}
console.log("npm-audit-gate negative validation: all cases behaved as expected.");
