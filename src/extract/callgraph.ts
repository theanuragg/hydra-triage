import { Project, SyntaxKind, Node, SourceFile } from "ts-morph";
import path from "node:path";
import fs from "node:fs";
import type { CallGraph, CallEdge, FunctionNode } from "../types.js";

/**
 * Heuristics for "this function is reachable from outside the process" —
 * i.e. an entry point for reachability traversal. Kept deliberately simple
 * for the MVP: exported top-level functions, and functions passed directly
 * as Express-style route handlers. Both are checkable by eye in the demo.
 */
function classifyEntryPoint(node: Node, sourceFile: SourceFile): FunctionNode["entryKind"] | undefined {
  // app.get("/path", handler) / router.post("/x", handler) etc.
  const parent = node.getParent();
  if (parent && Node.isCallExpression(parent)) {
    const expr = parent.getExpression();
    if (Node.isPropertyAccessExpression(expr)) {
      const method = expr.getName();
      if (["get", "post", "put", "delete", "patch", "use", "all"].includes(method)) {
        return "http-route";
      }
    }
  }

  // exported top-level function declaration
  if (Node.isFunctionDeclaration(node) && node.isExported()) {
    return "public-export";
  }

  return undefined;
}

function functionId(sourceFile: SourceFile, name: string, startLine: number, repoRoot: string): string {
  const rel = path.relative(repoRoot, sourceFile.getFilePath());
  return `${rel}#${name}#${startLine}`;
}

function getFunctionName(node: Node): string {
  if (Node.isFunctionDeclaration(node) || Node.isMethodDeclaration(node)) {
    return node.getName() ?? "<anonymous>";
  }
  if (Node.isArrowFunction(node) || Node.isFunctionExpression(node)) {
    const parent = node.getParent();
    if (parent && Node.isVariableDeclaration(parent)) {
      return parent.getName();
    }
    if (parent && Node.isPropertyAssignment(parent)) {
      return parent.getName();
    }
    return "<anonymous>";
  }
  return "<anonymous>";
}

function isFunctionLike(node: Node): boolean {
  return (
    Node.isFunctionDeclaration(node) ||
    Node.isMethodDeclaration(node) ||
    Node.isArrowFunction(node) ||
    Node.isFunctionExpression(node)
  );
}

/**
 * Finds the id of the function whose body directly (not via a nested
 * function) contains `node`. This is the fix for the over-attribution bug
 * described in README §8: the earlier implementation walked each tracked
 * function's *entire* body subtree for call expressions, which meant a
 * call made only inside a nested closure got attributed to every
 * enclosing named function too, not just its true immediate parent —
 * inflating reachability results. Walking up from the call site to its
 * nearest function-like ancestor gives each call exactly one caller.
 */
function nearestEnclosingFunctionId(node: Node, idByDeclaration: Map<Node, string>): string | undefined {
  const enclosing = node.getFirstAncestor((n) => isFunctionLike(n));
  if (!enclosing) return undefined; // module-top-level call, not part of the call graph
  return idByDeclaration.get(enclosing);
}

export function extractCallGraph(repoRoot: string): CallGraph {
  const tsConfigPath = findTsConfig(repoRoot);
  const project = new Project(
    tsConfigPath ? { tsConfigFilePath: tsConfigPath, skipAddingFilesFromTsConfig: false } : {},
  );

  if (!tsConfigPath) {
    project.addSourceFilesAtPaths(path.join(repoRoot, "**/*.{ts,tsx,js,jsx}"));
  }

  const functions: FunctionNode[] = [];
  const edges: CallEdge[] = [];
  const externalCalls: CallGraph["externalCalls"] = [];

  // id -> node, used to resolve local call targets
  const idByDeclaration = new Map<Node, string>();

  const sourceFiles = project.getSourceFiles().filter((sf) => !sf.getFilePath().includes("node_modules"));
  for (const sourceFile of sourceFiles) {
    const candidates = [
      ...sourceFile.getDescendantsOfKind(SyntaxKind.FunctionDeclaration),
      ...sourceFile.getDescendantsOfKind(SyntaxKind.MethodDeclaration),
      ...sourceFile.getDescendantsOfKind(SyntaxKind.ArrowFunction),
      ...sourceFile.getDescendantsOfKind(SyntaxKind.FunctionExpression),
    ];

    for (const node of candidates) {
      const name = getFunctionName(node);
      const startLine = node.getStartLineNumber();
      const id = functionId(sourceFile, name, startLine, repoRoot);
      const entryKind = classifyEntryPoint(node, sourceFile);

      functions.push({
        id,
        name,
        modulePath: path.relative(repoRoot, sourceFile.getFilePath()),
        startLine,
        isEntryPoint: entryKind !== undefined,
        entryKind,
      });
      idByDeclaration.set(node, id);
    }
  }

  // Global function-name -> id index for resolving local call targets that
  // cross file boundaries (e.g. `const { renderProfile } = require("./render")`
  // called from index.js, declared in render.js). Same-name collisions
  // across files resolve to whichever declaration was indexed first — a
  // known, documented imprecision (README §8), not new to this pass.
  const globalNameIndex = new Map<string, string>();
  for (const [node, id] of idByDeclaration) {
    const name = getFunctionName(node);
    if (name !== "<anonymous>" && !globalNameIndex.has(name)) globalNameIndex.set(name, id);
  }

  // Pass 2: walk call expressions, resolve targets to either a local
  // function id or an external package export.
  for (const sourceFile of sourceFiles) {
    // import specifier -> package name, e.g. `template` -> "lodash" for
    // `import { template } from "lodash"`
    const importedFrom = new Map<string, string>();
    for (const imp of sourceFile.getImportDeclarations()) {
      const moduleSpecifier = imp.getModuleSpecifierValue();
      if (moduleSpecifier.startsWith(".")) continue; // local import, not an external package
      const pkgName = moduleSpecifier.startsWith("@")
        ? moduleSpecifier.split("/").slice(0, 2).join("/")
        : moduleSpecifier.split("/")[0];

      const def = imp.getDefaultImport();
      if (def) importedFrom.set(def.getText(), pkgName);
      for (const named of imp.getNamedImports()) {
        importedFrom.set(named.getAliasNode()?.getText() ?? named.getName(), pkgName);
      }
      const ns = imp.getNamespaceImport();
      if (ns) importedFrom.set(ns.getText(), pkgName);
    }

    // CommonJS: const x = require("pkg") / const { a, b } = require("pkg")
    for (const varDecl of sourceFile.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
      const init = varDecl.getInitializer();
      if (!init || !Node.isCallExpression(init)) continue;
      const callee = init.getExpression();
      if (!Node.isIdentifier(callee) || callee.getText() !== "require") continue;

      const arg = init.getArguments()[0];
      if (!arg || !Node.isStringLiteral(arg)) continue;
      const moduleSpecifier = arg.getLiteralValue();
      if (moduleSpecifier.startsWith(".")) continue;
      const pkgName = moduleSpecifier.startsWith("@")
        ? moduleSpecifier.split("/").slice(0, 2).join("/")
        : moduleSpecifier.split("/")[0];

      const nameNode = varDecl.getNameNode();
      if (Node.isIdentifier(nameNode)) {
        importedFrom.set(nameNode.getText(), pkgName);
      } else if (Node.isObjectBindingPattern(nameNode)) {
        for (const el of nameNode.getElements()) {
          const bindingName = el.getNameNode();
          if (Node.isIdentifier(bindingName)) importedFrom.set(bindingName.getText(), pkgName);
        }
      }
    }

    // Single pass over every call expression in the file. Each call is
    // attributed to its nearest enclosing function only (see
    // nearestEnclosingFunctionId) — not to every ancestor function whose
    // body textually contains it, which was the source of the
    // over-attribution bug this replaces.
    for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const callerId = nearestEnclosingFunctionId(call, idByDeclaration);
      if (!callerId) continue; // top-level call outside any tracked function

      const expr = call.getExpression();

      // direct identifier call: fn() or importedName()
      if (Node.isIdentifier(expr)) {
        const calleeName = expr.getText();
        const pkg = importedFrom.get(calleeName);
        if (pkg) {
          externalCalls.push({ callerId, packageName: pkg, importedName: calleeName });
          continue;
        }
        const localId = globalNameIndex.get(calleeName);
        if (localId && localId !== callerId) {
          edges.push({ callerId, calleeId: localId });
        }
        continue;
      }

      // member call: mod.fn() e.g. lodash.template(), jwt.verify()
      if (Node.isPropertyAccessExpression(expr)) {
        const objectName = expr.getExpression().getText();
        const memberName = expr.getName();
        const pkg = importedFrom.get(objectName);
        if (pkg) {
          externalCalls.push({ callerId, packageName: pkg, importedName: memberName });
        }
      }
    }
  }

  return { functions, edges, externalCalls };
}

function findTsConfig(repoRoot: string): string | undefined {
  const candidate = path.join(repoRoot, "tsconfig.json");
  return fs.existsSync(candidate) ? candidate : undefined;
}
