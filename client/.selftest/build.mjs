import { stripTypeScriptTypes } from "node:module";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, "..");

const files = [
  ["src/types.ts", ".selftest/build/types.js"],
  ["src/issuesLogic.ts", ".selftest/build/issuesLogic.js"],
];

for (const [src, out] of files) {
  const srcPath = path.join(root, src);
  const outPath = path.join(root, out);
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  const stripped = stripTypeScriptTypes(fs.readFileSync(srcPath, "utf-8"), { mode: "strip" });
  fs.writeFileSync(outPath, stripped);
  console.log(`stripped ${src} -> ${out}`);
}
