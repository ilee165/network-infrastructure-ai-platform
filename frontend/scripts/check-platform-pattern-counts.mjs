import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import ts from "typescript";

const pages = join(process.cwd(), "src/pages");
const fixturePages = join(process.cwd(), "scripts/fixtures/pattern-ratchet/pages");
const sharedEmptyState = join(process.cwd(), "src/components/EmptyState.tsx");

function readPageSources(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return readPageSources(path);
    return entry.name.endsWith(".tsx") ? [{ path, source: readFileSync(path, "utf8") }] : [];
  });
}

function staticStrings(expression) {
  if (!expression) return [];
  if (ts.isStringLiteralLike(expression)) return [expression.text];
  if (ts.isJsxExpression(expression)) return staticStrings(expression.expression);
  if (ts.isParenthesizedExpression(expression)) return staticStrings(expression.expression);
  if (ts.isTemplateExpression(expression)) {
    return [
      expression.head.text,
      ...expression.templateSpans.flatMap((span) => [
        ...staticStrings(span.expression),
        span.literal.text,
      ]),
    ];
  }
  if (ts.isCallExpression(expression) || ts.isArrayLiteralExpression(expression)) {
    return expression.arguments?.flatMap(staticStrings) ?? expression.elements.flatMap(staticStrings);
  }
  if (ts.isConditionalExpression(expression)) {
    return [
      ...staticStrings(expression.whenTrue),
      ...staticStrings(expression.whenFalse),
    ];
  }
  if (ts.isBinaryExpression(expression) && expression.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    return [...staticStrings(expression.left), ...staticStrings(expression.right)];
  }
  return [];
}

function attributeStrings(opening, name) {
  const attribute = opening.attributes.properties.find(
    (candidate) => ts.isJsxAttribute(candidate) && candidate.name.text === name,
  );
  if (!attribute || !ts.isJsxAttribute(attribute) || !attribute.initializer) return [];
  return staticStrings(attribute.initializer);
}

function classTokens(opening) {
  return new Set(
    attributeStrings(opening, "className").flatMap((value) => value.split(/\s+/).filter(Boolean)),
  );
}

function structuralCounts(files) {
  const counts = { tables: 0, emptyStates: 0, errorAlerts: 0, dashedEmptyStates: 0 };
  for (const file of files) {
    const sourceFile = ts.createSourceFile(
      file.path,
      file.source,
      ts.ScriptTarget.Latest,
      true,
      ts.ScriptKind.TSX,
    );
    function visit(node) {
      if (ts.isJsxOpeningElement(node) || ts.isJsxSelfClosingElement(node)) {
        const tag = node.tagName.getText(sourceFile);
        const classes = classTokens(node);
        const testIds = attributeStrings(node, "data-testid");
        const roles = attributeStrings(node, "role");
        if (tag === "div" && classes.has("panel") && classes.has("overflow-x-auto")) {
          counts.tables += 1;
        }
        if (tag === "div" && testIds.some((value) => value.includes("empty-state"))) {
          counts.emptyStates += 1;
        }
        if (
          roles.includes("alert") &&
          classes.has("panel") &&
          classes.has("border-status-error/40")
        ) {
          counts.errorAlerts += 1;
        }
        if (classes.has("border-dashed")) counts.dashedEmptyStates += 1;
      }
      ts.forEachChild(node, visit);
    }
    visit(sourceFile);
  }
  return counts;
}

const pageSources = readPageSources(pages);
const sharedSources = [{ path: sharedEmptyState, source: readFileSync(sharedEmptyState, "utf8") }];
const census = (files, includeSharedEmptyState = false) => {
  const counts = structuralCounts(files);
  if (includeSharedEmptyState) {
    counts.emptyStates += structuralCounts(sharedSources).dashedEmptyStates;
  }
  return counts;
};

const limits = { tables: 30, emptyStates: 13, errorAlerts: 4 };
const actual = census(pageSources, true);
for (const [name, limit] of Object.entries(limits)) {
  if (actual[name] > limit) throw new Error(`${name} count ${actual[name]} exceeds post-T4 ratchet ${limit}`);
}

function planted(source) {
  return [...pageSources, { path: join(process.cwd(), "scripts/fixtures/planted.tsx"), source }];
}

const plantedTable = census(planted(`const fixture = <div className="panel overflow-x-auto"><table /></div>;`), true);
if (plantedTable.tables !== actual.tables + 1) throw new Error("table count ratchet self-test did not bite");
const plantedEmpty = census(planted(`const fixture = <div data-testid="planted-empty-state" />;`), true);
if (plantedEmpty.emptyStates !== actual.emptyStates + 1) throw new Error("empty-state count ratchet self-test did not bite");
const plantedError = census(planted(`const fixture = <div role="alert" className="panel border-status-error/40" />;`), true);
if (plantedError.errorAlerts !== actual.errorAlerts + 1) throw new Error("error-alert count ratchet self-test did not bite");

const nestedFixture = census(readPageSources(fixturePages));
if (nestedFixture.tables !== 2 || nestedFixture.emptyStates !== 2 || nestedFixture.errorAlerts !== 2) {
  throw new Error("nested and variant-syntax ratchet fixtures did not bite all detectors");
}

console.log(`platform-pattern ratchet OK: tables=${actual.tables}/30 emptyStates=${actual.emptyStates}/13 errorAlerts=${actual.errorAlerts}/4 (AST detectors bite)`);
