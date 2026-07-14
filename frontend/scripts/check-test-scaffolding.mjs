import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import ts from "typescript";

const testsRoot = join(process.cwd(), "src/__tests__");
const apiRoot = join(process.cwd(), "src/api");
const testUtilsModule = join(process.cwd(), "src/test/test-utils");
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

function importsTestUtils(expression, fileName) {
  expression = unwrap(expression);
  return (
    ts.isCallExpression(expression) &&
    expression.expression.kind === ts.SyntaxKind.ImportKeyword &&
    expression.arguments.length === 1 &&
    ts.isStringLiteralLike(expression.arguments[0]) &&
    resolve(dirname(fileName), expression.arguments[0].text) === testUtilsModule
  );
}

function callbackUsesFactory(callback, expectedFactory, fileName) {
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
    importsTestUtils(factoryCall.expression.expression, fileName)
  );
}

function apiModuleName(specifier, fileName) {
  if (!specifier.startsWith(".")) return undefined;

  const modulePath = relative(apiRoot, resolve(dirname(fileName), specifier));
  if (
    !modulePath ||
    modulePath === ".." ||
    modulePath.startsWith(`..${sep}`) ||
    isAbsolute(modulePath)
  ) {
    return undefined;
  }
  return modulePath;
}

function apiMockViolations(
  source,
  fileName = join(testsRoot, "fixture.tsx"),
  recordApiMock = () => {},
) {
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
      const moduleName = apiModuleName(node.arguments[0].text, fileName);
      if (moduleName) {
        recordApiMock();
        const expectedFactory = sharedFactories.get(moduleName);
        const callback = node.arguments[1];
        if (
          !expectedFactory ||
          !callback ||
          !callbackUsesFactory(callback, expectedFactory, fileName)
        ) {
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
  const apiViolations = apiMockViolations(source, file, () => {
    routedMocks += 1;
  });
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
const nestedApiBypass = readFileSync(
  join(process.cwd(), "scripts/__fixtures__/test-scaffolding-nested-api-bypass.tsx"),
  "utf8",
);
const nestedApiDescendantBypass = readFileSync(
  join(
    process.cwd(),
    "scripts/__fixtures__/test-scaffolding-nested-api-descendant-bypass.tsx",
  ),
  "utf8",
);
const nestedApiFactory = readFileSync(
  join(process.cwd(), "scripts/__fixtures__/test-scaffolding-nested-api-factory.tsx"),
  "utf8",
);
if (apiMockViolations(nearbyBypass).length !== 1) {
  throw new Error("API mock detector accepted unrelated nearby factory text");
}
if (
  apiMockViolations(
    nestedApiBypass,
    join(testsRoot, "routes/test-scaffolding-nested-api-bypass.test.tsx"),
  ).length !== 1
) {
  throw new Error("API mock detector accepted a nested relative API mock");
}
if (
  apiMockViolations(
    nestedApiDescendantBypass,
    join(testsRoot, "routes/test-scaffolding-nested-api-descendant-bypass.test.tsx"),
  ).length !== 1
) {
  throw new Error("API mock detector accepted an API descendant mock");
}
if (
  apiMockViolations(
    nestedApiFactory,
    join(testsRoot, "routes/test-scaffolding-nested-api-factory.test.tsx"),
  ).length
) {
  throw new Error("API mock detector rejected a nested matching shared factory");
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
