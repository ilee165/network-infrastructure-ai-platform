import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import ts from "typescript";

const testsRoot = join(process.cwd(), "src/__tests__");
const sharedFactories = new Map([
  ["auth", "mockAuthApi"],
  ["changes", "mockChangesApi"],
  ["credentials", "mockCredentialsApi"],
  ["integrations", "mockIntegrationsApi"],
  ["agents", "mockAgentsApi"],
]);
const queryClientConstruction = /new\s+QueryClient\s*\(/g;

function sourceFiles(root) {
  return readdirSync(root).flatMap((name) => {
    const path = join(root, name);
    return statSync(path).isDirectory()
      ? sourceFiles(path)
      : /\.[cm]?[jt]sx?$/.test(name)
        ? [path]
        : [];
  });
}

function unwrap(expression) {
  while (
    ts.isParenthesizedExpression(expression) ||
    ts.isAwaitExpression(expression)
  ) {
    expression = expression.expression;
  }
  return expression;
}

function importsTestUtils(expression) {
  expression = unwrap(expression);
  return (
    ts.isCallExpression(expression) &&
    expression.expression.kind === ts.SyntaxKind.ImportKeyword &&
    expression.arguments.length === 1 &&
    ts.isStringLiteralLike(expression.arguments[0]) &&
    expression.arguments[0].text === "../test/test-utils"
  );
}

function callbackUsesFactory(callback, expectedFactory) {
  if (!ts.isArrowFunction(callback) || ts.isBlock(callback.body)) return false;

  const body = unwrap(callback.body);
  const factoryCall =
    ts.isCallExpression(body) &&
    body.arguments.length === 0 &&
    ts.isCallExpression(body.expression)
      ? body.expression
      : undefined;
  return (
    factoryCall !== undefined &&
    ts.isPropertyAccessExpression(factoryCall.expression) &&
    factoryCall.expression.name.text === expectedFactory &&
    importsTestUtils(factoryCall.expression.expression)
  );
}

function apiMockViolations(source, fileName = "fixture.tsx") {
  const sourceFile = ts.createSourceFile(
    fileName,
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TSX,
  );
  const violations = [];

  function visit(node) {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      ts.isIdentifier(node.expression.expression) &&
      node.expression.expression.text === "vi" &&
      node.expression.name.text === "mock" &&
      node.arguments.length >= 1 &&
      ts.isStringLiteralLike(node.arguments[0])
    ) {
      const match = /^\.\.\/api\/([^/]+)$/.exec(node.arguments[0].text);
      if (match) {
        const expectedFactory = sharedFactories.get(match[1]);
        const callback = node.arguments[1];
        if (!expectedFactory || !callback || !callbackUsesFactory(callback, expectedFactory)) {
          violations.push(sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1);
        }
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(sourceFile);
  return violations;
}

const violations = [];
let routedMocks = 0;
for (const file of sourceFiles(testsRoot)) {
  const source = readFileSync(file, "utf8");
  const apiViolations = apiMockViolations(source, file);
  routedMocks += (source.match(/vi\.mock\(\s*["']\.\.\/api\//g) ?? []).length;
  for (const line of apiViolations) {
    violations.push(`${relative(process.cwd(), file)}:${line}: bare API module mock`);
  }
  for (const match of source.matchAll(queryClientConstruction)) {
    const line = source.slice(0, match.index).split("\n").length;
    violations.push(`${relative(process.cwd(), file)}:${line}: private QueryClient construction`);
  }
}

// Permanent bite proofs: bare callbacks, wrong factories, and unrelated nearby
// factory-shaped text must all fail the structural callback contract.
const nearbyBypass = readFileSync(
  join(process.cwd(), "scripts/__fixtures__/test-scaffolding-nearby-bypass.tsx"),
  "utf8",
);
if (apiMockViolations(nearbyBypass).length !== 1) {
  throw new Error("API mock detector accepted unrelated nearby factory text");
}
if (apiMockViolations(`vi.mock("../api/auth", () => ({}))`).length !== 1) {
  throw new Error("API mock detector self-test did not bite");
}
if (
  apiMockViolations(
    `vi.mock("../api/auth", async () => (await import("../test/test-utils")).mockChangesApi()())`,
  ).length !== 1
) {
  throw new Error("API mock detector accepted the wrong shared factory");
}
if (
  apiMockViolations(
    `vi.mock("../api/auth", async () => (await import("../test/test-utils")).mockAuthApi()())`,
  ).length
) {
  throw new Error("API mock detector rejected the matching shared factory");
}
if (![..."new QueryClient()".matchAll(queryClientConstruction)].length) {
  throw new Error("QueryClient construction detector self-test did not bite");
}

if (violations.length) {
  throw new Error(`test scaffolding violations (${violations.length}):\n${violations.join("\n")}`);
}

console.log(
  `test-scaffolding lint OK: ${routedMocks} API mocks use matching shared factories; zero private QueryClient constructions (both detectors bite)`,
);
