// Strips TS types from the dependency-free core (cypherLiteral, types,
// hydraClient, ingest/write, query/reachability) so run.mjs can execute
// the real logic with bare `node`, no `npm install` required. This is a
// self-test convenience only — the shipped build (`npm run build`) uses
// real `tsc` and covers the full project including the ts-morph-based
// extractor and CLI, which this self-test does not touch.
import { stripTypeScriptTypes } from "node:module";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, "..");

const files = [
  ["src/cypherLiteral.ts", ".selftest/build/cypherLiteral.js"],
  ["src/types.ts", ".selftest/build/types.js"],
  ["src/config.ts", ".selftest/build/config.js"],
  ["src/safeStatic.ts", ".selftest/build/safeStatic.js"],
  ["src/hydraClient.ts", ".selftest/build/hydraClient.js"],
  ["src/identity.ts", ".selftest/build/identity.js"],
  ["src/scanInput.ts", ".selftest/build/scanInput.js"],
  ["src/ingest/write.ts", ".selftest/build/ingest/write.js"],
  ["src/query/reachability.ts", ".selftest/build/query/reachability.js"],
  ["src/incident/ingest.ts", ".selftest/build/incident/ingest.js"],
  ["src/incident/query.ts", ".selftest/build/incident/query.js"],
  ["src/gate.ts", ".selftest/build/gate.js"],
];

for (const [src, out] of files) {
  const srcPath = path.join(root, src);
  const outPath = path.join(root, out);
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  const code = fs.readFileSync(srcPath, "utf-8");
  const stripped = stripTypeScriptTypes(code, { mode: "strip" });
  fs.writeFileSync(outPath, stripped);
  console.log(`stripped ${src} -> ${out}`);
}
