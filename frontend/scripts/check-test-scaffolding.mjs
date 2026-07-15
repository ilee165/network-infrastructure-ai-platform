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
  const viIdentifiers = new Set(["vi"]);
  const vitestNamespaces = new Set();

  for (const statement of sourceFile.statements) {
    if (
      !ts.isImportDeclaration(statement) ||
      !ts.isStringLiteralLike(statement.moduleSpecifier) ||
      statement.moduleSpecifier.text !== "vitest"
    ) {
      continue;
    }
    const bindings = statement.importClause?.namedBindings;
    if (bindings && ts.isNamedImports(bindings)) {
      for (const binding of bindings.elements) {
        if ((binding.propertyName ?? binding.name).text === "vi") {
          viIdentifiers.add(binding.name.text);
        }
      }
    } else if (bindings && ts.isNamespaceImport(bindings)) {
      vitestNamespaces.add(bindings.name.text);
    }
  }

  function mockMethod(expression) {
    if (!ts.isPropertyAccessExpression(expression)) return undefined;
    if (expression.name.text !== "mock" && expression.name.text !== "doMock") {
      return undefined;
    }
    if (ts.isIdentifier(expression.expression) && viIdentifiers.has(expression.expression.text)) {
      return expression.name.text;
    }
    const owner = expression.expression;
    if (
      ts.isPropertyAccessExpression(owner) &&
      owner.name.text === "vi" &&
      ts.isIdentifier(owner.expression) &&
      vitestNamespaces.has(owner.expression.text)
    ) {
      return expression.name.text;
    }
    return undefined;
  }

  function visit(node) {
    if (
      ts.isCallExpression(node) &&
      mockMethod(node.expression) &&
      node.arguments.length >= 1
    ) {
      const specifier = node.arguments[0];
      if (!ts.isStringLiteralLike(specifier)) {
        violations.push(sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1);
        ts.forEachChild(node, visit);
        return;
      }
      const moduleName = apiModuleName(specifier.text, fileName);
      if (moduleName !== undefined) {
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

function queryClientViolations(source, fileName = join(testsRoot, "fixture.tsx")) {
  const sourceFile = ts.createSourceFile(
    fileName,
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TSX,
  );
  const identifiers = new Set(["QueryClient"]);
  const namespaces = new Set();
  const violations = [];

  for (const statement of sourceFile.statements) {
    if (
      !ts.isImportDeclaration(statement) ||
      !ts.isStringLiteralLike(statement.moduleSpecifier) ||
      statement.moduleSpecifier.text !== "@tanstack/react-query"
    ) {
      continue;
    }
    const bindings = statement.importClause?.namedBindings;
    if (bindings && ts.isNamedImports(bindings)) {
      for (const binding of bindings.elements) {
        if ((binding.propertyName ?? binding.name).text === "QueryClient") {
          identifiers.add(binding.name.text);
        }
      }
    } else if (bindings && ts.isNamespaceImport(bindings)) {
      namespaces.add(bindings.name.text);
    }
  }

  function visit(node) {
    if (ts.isNewExpression(node)) {
      const constructor = unwrap(node.expression);
      const isDirect = ts.isIdentifier(constructor) && identifiers.has(constructor.text);
      const isNamespace =
        ts.isPropertyAccessExpression(constructor) &&
        constructor.name.text === "QueryClient" &&
        ts.isIdentifier(constructor.expression) &&
        namespaces.has(constructor.expression.text);
      if (isDirect || isNamespace) {
        violations.push(sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1);
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
  for (const line of queryClientViolations(source, file)) {
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
if (apiMockViolations(`vi.mock("../api", () => ({}))`).length !== 1) {
  throw new Error("API mock detector missed the API root module");
}
if (apiMockViolations(`vi.doMock("../api/auth", () => ({}))`).length !== 1) {
  throw new Error("API mock detector missed vi.doMock");
}
if (
  apiMockViolations(
    `import { vi as v } from "vitest"; v.mock("../api/auth", () => ({}));`,
  ).length !== 1
) {
  throw new Error("API mock detector missed a named vi alias");
}
if (
  apiMockViolations(
    `import * as vt from "vitest"; vt.vi.mock("../api/auth", () => ({}));`,
  ).length !== 1
) {
  throw new Error("API mock detector missed a vitest namespace alias");
}
if (
  apiMockViolations(
    `const moduleName = "auth"; vi.mock(\`../api/\${moduleName}\`, () => ({}));`,
  ).length !== 1
) {
  throw new Error("API mock detector accepted a non-literal mock path");
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
if (queryClientViolations(`new QueryClient()`).length !== 1) {
  throw new Error("QueryClient construction detector self-test did not bite");
}
if (queryClientViolations(`// new QueryClient()`).length !== 0) {
  throw new Error("QueryClient construction detector matched a comment");
}
if (queryClientViolations(`new (QueryClient)()`).length !== 1) {
  throw new Error("QueryClient construction detector missed parenthesized syntax");
}
if (
  queryClientViolations(
    `import { QueryClient as QC } from "@tanstack/react-query"; new QC();`,
  ).length !== 1
) {
  throw new Error("QueryClient construction detector missed an import alias");
}
if (
  queryClientViolations(
    `import * as RQ from "@tanstack/react-query"; new RQ.QueryClient();`,
  ).length !== 1
) {
  throw new Error("QueryClient construction detector missed a namespace import");
}

if (violations.length) {
  throw new Error(`test scaffolding violations (${violations.length}):\n${violations.join("\n")}`);
}

console.log(
  `test-scaffolding lint OK: ${routedMocks} API mocks use matching shared factories; zero private QueryClient constructions (both detectors bite)`,
);
