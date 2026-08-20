import { HydraClient } from "./build/hydraClient.js";
import { ingestCallGraph, ingestVulnDb, resetGraph } from "./build/ingest/write.js";
import { checkReachability } from "./build/query/reachability.js";
import { startFakeHydraDB, FakeGraph } from "./fakeHydraDB.mjs";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));

// ---- fixture: mirrors demo/vulnerable-app's intended shape ----
// E1 -> localA -> ejs.render               (REACHABLE)
// E2 -> localB -> lodash.template          (REACHABLE)
// E3 -> localC -> lodash.merge             (REACHABLE)
// localD (unreferenced) -> jsonwebtoken.verify        (present-unreachable)
// localE (unreferenced) -> minimist                   (present-unreachable)
// localF (unreferenced) -> node-serialize.unserialize (present-unreachable)
// left-pad CVE has no matching externalCalls entry -> not-present

const graph = {
  functions: [
    { id: "E1", name: "profileRoute", modulePath: "src/index.js", startLine: 1, isEntryPoint: true, entryKind: "http-route" },
    { id: "localA", name: "renderProfile", modulePath: "src/render.js", startLine: 1, isEntryPoint: false },
    { id: "E2", name: "welcomeRoute", modulePath: "src/index.js", startLine: 2, isEntryPoint: true, entryKind: "http-route" },
    { id: "localB", name: "buildWelcomeMessage", modulePath: "src/template.js", startLine: 1, isEntryPoint: false },
    { id: "E3", name: "settingsRoute", modulePath: "src/index.js", startLine: 3, isEntryPoint: true, entryKind: "http-route" },
    { id: "localC", name: "applyUserSettings", modulePath: "src/settings.js", startLine: 1, isEntryPoint: false },
    { id: "localD", name: "legacyAuthMiddleware", modulePath: "src/auth.js", startLine: 1, isEntryPoint: false },
    { id: "localE", name: "run", modulePath: "scripts/cli.js", startLine: 1, isEntryPoint: false },
    { id: "localF", name: "loadFromLegacyCache", modulePath: "src/legacy/cache.js", startLine: 1, isEntryPoint: false },
  ],
  edges: [
    { callerId: "E1", calleeId: "localA" },
    { callerId: "E2", calleeId: "localB" },
    { callerId: "E3", calleeId: "localC" },
  ],
  externalCalls: [
    { callerId: "localA", packageName: "ejs", importedName: "render" },
    { callerId: "localB", packageName: "lodash", importedName: "template" },
    { callerId: "localC", packageName: "lodash", importedName: "merge" },
    { callerId: "localD", packageName: "jsonwebtoken", importedName: "verify" },
    { callerId: "localE", packageName: "minimist", importedName: "default" },
    { callerId: "localF", packageName: "node-serialize", importedName: "unserialize" },
  ],
};

// Real source of truth — NOT a hand-copied duplicate. An earlier version
// of this file hardcoded its own copy of the six CVE entries; if
// vulnerable-functions.json were ever edited afterward, that copy would
// silently drift out of sync and "ALL CASES PASSED" would stop meaning
// anything. Reading the actual file means this test can only pass if it
// agrees with what ships.
const realVulndb = JSON.parse(
  fs.readFileSync(path.join(here, "..", "src", "vulndb", "vulnerable-functions.json"), "utf-8"),
).entries;

// Synthetic 7th entry, kept inline on purpose: it must NOT match anything
// in externalCalls above, to exercise the "not-present" branch. Adding it
// to the real vulndb file would be dishonest (left-pad has no such CVE);
// it belongs only in the test fixture.
const vulndb = [
  ...realVulndb,
  { cve: "CVE-9999-0000", packageName: "left-pad", vulnerableExport: "leftPad", severity: "low", summary: "synthetic case for the not-present branch, intentionally not in vulnerable-functions.json", reference: "n/a" },
];

const expected = {
  "CVE-2022-29078": "reachable",
  "CVE-2021-23337": "reachable",
  "CVE-2018-3721": "reachable",
  "CVE-2022-23529": "present-unreachable",
  "CVE-2020-7598": "present-unreachable",
  "CVE-2017-5941": "present-unreachable",
  "CVE-9999-0000": "not-present",
};

async function main() {
  // Guard against silent drift the other direction too: if someone adds
  // or removes an entry in vulnerable-functions.json without updating
  // `expected` here, fail loudly instead of quietly skipping the new CVE.
  const uncoveredCves = realVulndb.map((e) => e.cve).filter((cve) => !(cve in expected));
  if (uncoveredCves.length > 0) {
    console.error(`vulnerable-functions.json has entries with no expected outcome in this test: ${uncoveredCves.join(", ")}`);
    console.error("Update .selftest/run.mjs's `expected` map (and the graph/externalCalls fixture) to cover them.");
    process.exit(1);
  }

  const { server, baseUrl } = await startFakeHydraDB(new FakeGraph());
  const client = new HydraClient({ baseUrl, token: "x", namespace: "default", graph: "default", cellId: "cell-0" });

  await resetGraph(client);
  await ingestCallGraph(client, graph);
  const presentSinkIds = await ingestVulnDb(client, graph, vulndb);
  console.log("present sink ids:", [...presentSinkIds].sort());
  console.log();

  const results = await checkReachability(client, vulndb, presentSinkIds);

  let failures = 0;
  for (const r of results) {
    const want = expected[r.cve];
    const got = r.status;
    const ok = want === got;
    if (!ok) failures++;
    const pathStr = r.pathHumanReadable ? "  path=" + r.pathHumanReadable.join(" -> ") : "";
    console.log(`${ok ? "PASS" : "FAIL"}  ${r.cve.padEnd(16)} want=${want.padEnd(20)} got=${got}${pathStr}`);
  }

  server.close();
  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log(`\nALL ${results.length} CASES PASSED`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
