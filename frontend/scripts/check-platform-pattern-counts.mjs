import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const pages = join(process.cwd(), "src/pages");
const files = readdirSync(pages).filter((name) => name.endsWith(".tsx"));
const source = files.map((name) => readFileSync(join(pages, name), "utf8")).join("\n");
const component = readFileSync(join(process.cwd(), "src/components/EmptyState.tsx"), "utf8");
const count = (text, pattern) => [...text.matchAll(pattern)].length;
const census = (text) => ({
  tables: count(text, /<div className="panel overflow-x-auto"/g),
  emptyStates: count(text, /<div\s+data-testid="[^"]*empty-state"/g) + count(component, /border-dashed/g),
  errorAlerts: count(text, /role="alert"[\s\S]{0,100}className="panel border-status-error\/40/g),
});
const limits = { tables: 30, emptyStates: 13, errorAlerts: 4 };
const actual = census(source);
for (const [name, limit] of Object.entries(limits)) {
  if (actual[name] > limit) throw new Error(`${name} count ${actual[name]} exceeds post-T4 ratchet ${limit}`);
}
// Bite proof: each detector must recognize a re-rolled instance. This keeps a
// regex that silently stops matching from turning its ratchet into a no-op.
const plantedTable = census(`${source}\n<div className="panel overflow-x-auto"><table>`);
if (plantedTable.tables !== actual.tables + 1) throw new Error("table count ratchet self-test did not bite");
const plantedEmpty = census(`${source}\n<div data-testid="planted-empty-state">`);
if (plantedEmpty.emptyStates !== actual.emptyStates + 1) throw new Error("empty-state count ratchet self-test did not bite");
const plantedError = census(`${source}\n<div role="alert" className="panel border-status-error/40">`);
if (plantedError.errorAlerts !== actual.errorAlerts + 1) throw new Error("error-alert count ratchet self-test did not bite");
console.log(`platform-pattern ratchet OK: tables=${actual.tables}/30 emptyStates=${actual.emptyStates}/13 errorAlerts=${actual.errorAlerts}/4 (all detectors bite)`);
