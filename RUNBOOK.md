# RUNBOOK — first real run against HydraDB

I can't execute this myself: this sandbox has no network access, so I
can't `git clone` HydraDB, `cargo build` it, or `npm install` ts-morph.
Everything below has been reasoned through and self-tested as far as it's
possible to without those two things (see README §12), but this is the
actual first contact with the real system. Run it in order; each step has
an expected checkpoint so you know exactly where it broke if it does.

Budget ~20-30 minutes for the Rust build (`cargo build` on a cold cache,
GraphBLAS included, is not fast) — run step 1 first and let it build in
the background while you read the rest.

---

## Step 1 — build and start HydraDB

```bash
git clone https://github.com/hydra-db/hydradb.git
cd hydradb
```

**Checkpoint:** confirm the repo actually has the local-dev-node
instructions I copied into `scripts/setup-hydradb.sh` — `cat README.md`
and look for the env vars (`CLOUD_PROVIDER`, `GRAPH_CELL_ID`, etc.) and the
`cargo run --features server-runtime --bin graph-node` invocation. If the
upstream README has changed since I read it, **the script will be wrong**
— diff it against the current README before running, don't assume it's
still accurate.

```bash
bash /path/to/hydra-triage/scripts/setup-hydradb.sh
```

**Expected output, roughly:**
```
Starting graph-node on :8443 (HTTP) / :7687 (Bolt) / :9090 (admin) ...
   Compiling ...
   ...
listening on 0.0.0.0:8443
```

**If it fails to compile:** almost certainly a missing system dependency
(GraphBLAS needs a C toolchain; macOS needs the `brew` block in the
script, which only fires if `brew` is on PATH). Send me the exact compiler
error — "it failed" isn't enough to fix a Rust build error from here.

**Leave this running in its own terminal.** Everything below assumes
`http://127.0.0.1:8443` is live.

---

## Step 2 — sanity-check the HTTP API shape before trusting hydraClient.ts

This is the single biggest unverified assumption in the whole project.
`hydraClient.ts` assumes the response body is `{ rows: [...] }` with each
row's values shaped `{ type, value }`, based on reading the HydraDB
README's query examples — it was never confirmed against a live response.
Before running hydra-triage at all, hit the API directly:

```bash
curl -s -X POST http://127.0.0.1:8443/v1/graphs/default/query \
  -H "Authorization: Bearer local-development-token-32-bytes" \
  -H "X-Graph-Namespace: default" \
  -H "Content-Type: application/json" \
  -d '{"cell_id":"cell-0","query":"CREATE (n:Test {id: \"x\"}) RETURN n.id AS id","consistency":"causal"}' \
  | python3 -m json.tool
```

**Checkpoint — compare the actual response shape against what
`hydraClient.ts`'s `HydraQueryResult` type expects:**
```ts
{ rows: Array<Record<string, { type: string; value: unknown }>> }
```

**If the real shape is different** (e.g. `{ results: [...] }`, or values
aren't wrapped in `{type, value}`, or the field is called `data` not
`rows`), stop here and tell me the actual JSON — this is a five-minute fix
in `hydraClient.ts` and `query/reachability.ts`'s row-unwrapping
(`row?.names?.value`), but every downstream step is silently wrong until
it's fixed.

Also confirm the map-literal Cypher syntax `cypherLiteral.ts` generates is
actually accepted — the `CREATE (n:Test {id: "x"})` above uses a bare
identifier key exactly like our generated writes do. If that curl command
itself fails to parse, the whole ingestion approach needs rethinking, not
just a field-name tweak.

---

## Step 3 — install and build hydra-triage

```bash
cd /path/to/hydra-triage
npm install
```

**Checkpoint:** should succeed cleanly. If `ts-morph` or `commander`
fail to resolve, check `package.json` version pins haven't drifted from
what's actually on npm — I picked reasonable-looking versions from memory
without being able to check the registry.

```bash
npm run build
```

**Checkpoint:** `tsc` should report zero errors. **This is the first real
type-check the code has ever had.** I hand-verified types by reading, and
ran Node's *type-stripping* (not type-*checking*) on the zero-dependency
modules in the self-test — neither of those catches real type errors.
Genuinely expect to fix a handful of small type issues here; that's normal
for code that's never touched a compiler, not a sign anything is deeply
wrong.

---

## Step 4 — run the self-test one more time, for real this time

```bash
npm run selftest
```

Same suite from before (26 assertions: config, path-safety, 7
reachability, 6 incident, 10 gate-logic), but now `ts-morph` etc. exist
as real packages, so this also implicitly confirms `npm install` didn't
break anything the self-test depends on transitively. Also run
`cd client && npm run selftest` (11 more assertions — the Issues-table
filter/sort logic, a separate npm project with the same self-test
pattern).

**Expected:** `ALL CONFIG CHECKS PASSED`, `ALL PATH-SAFETY CHECKS
PASSED`, `ALL 7 CASES PASSED`, `ALL INCIDENT-MODULE CHECKS PASSED — 4
exposed, 1 actually targeted`, `ALL GATE-LOGIC CHECKS PASSED`, and
separately `ALL ISSUES-LOGIC CHECKS PASSED` from `client/`.

---

## Step 4.5 — the headline demo: the real incident replay

```bash
npm run incident
```

**Do this before Step 5.** This is the strongest piece of evidence in the
submission — a real, cited 2018 npm supply-chain incident, not a
synthetic app — and it's the fastest thing here to sanity-check: no
extraction step, no ts-morph, just the incident JSON straight into
HydraDB and two queries back out.

**Expected output, roughly:**
```
Query 1 — exposure (reachability only):
  EXPOSED  copay
  EXPOSED  (illustrative) internal-analytics-dashboard  (illustrative)
  EXPOSED  (illustrative) marketing-site-build-tool  (illustrative)
  EXPOSED  (illustrative) ci-log-aggregator  (illustrative)
  4 consumers have the malicious version somewhere in their resolved tree.

Query 2 — actually targeted (reachability + activation-key filter "A Secure Bitcoin Wallet"):
  TARGETED  copay
  1 of those 4 exposed consumers match the real payload's actual activation condition.
```

**If Query 1 returns 0:** the `DEPENDS_ON` edge from `event-stream@3.3.6`
to `flatmap-stream@0.1.1` didn't get created — check that
`src/incident/ingest.ts`'s `MATCH (a:Version {id: row.from}), (b:Version
{id: row.to})` actually found both nodes. This exact failure mode already
happened once during self-testing (the data file originally pointed `to`
at a bare package name instead of a versioned id) — if it happens again
against the real engine, the fix is almost certainly the same shape:
check the referenced `id` actually exists as a `Version` node.

**If Query 2 returns anything other than exactly `copay`:** the property
filter on `packageDescription` isn't matching — check for a quoting or
escaping mismatch between what `ingestIncident` wrote and what
`queryActuallyTargeted` searches for.

---

## Step 5 — the actual first contact: scan the demo app

```bash
npm run scan -- ./demo/vulnerable-app --reset
```

**Expected, if everything above held:**
- Extraction log line with non-zero functions/edges/external calls/entry
  points (if entry points = 0, the Express-route-detection heuristic in
  `classifyEntryPoint` didn't fire — check `demo/vulnerable-app/src/index.js`
  parses the way I assumed).
- Terminal table with exactly 3 `REACHABLE`, 3 `present, not reachable`,
  0 `not called` (all 6 vulndb entries are wired to demo app code, so
  there's no `not-present` case here — that's only exercised in the
  self-test's synthetic 7th entry).
- `hydra-triage-report.html` written to the current directory.

**If the counts don't match 3/3/0:** this is the actual interesting
failure mode to send me — it means either the entry-point heuristic, the
CommonJS `require()` resolution, or the nearest-enclosing-function
attribution fix doesn't hold on real ts-morph AST shapes the way it did
in the self-test's hand-built fixture. Send me the full terminal output.

---

## Step 6 — the browser client (do this once Step 5 works)

```bash
npm run client:install   # first time only — separate npm project in client/
npm run client:build     # emits client/dist/
npm run web              # serves client/dist/ + /api/scan on :5173
```

Open `http://127.0.0.1:5173`, leave the repo path on
`./demo/vulnerable-app`, click **Scan**.

**Expected:** three animated lanes under "Traced attack paths" — each one
entry-point → intermediate function(s) → the vulnerable package export —
with the connecting lines drawing in about 150ms apart. Below that, a flat
list of the 3 present-but-unreachable CVEs. Click the "All issues" tab:
a sortable table of all 6 findings; typing "lodash" in the search box
should narrow it to 2 rows.

**`client:build` is the first real TypeScript+JSX compile this app has
ever had.** Everything self-tested in this project so far (§11) is
either plain TypeScript with zero dependencies, or plain JS/HTML/CSS —
Node's native type-stripping explicitly can't handle JSX (it's not
erasable-only syntax), so the four `.tsx` component files
(`App.tsx`, `TopBar.tsx`, `StatRail.tsx`, `TraceView.tsx`,
`IssuesTable.tsx`) have never been compiled, let alone run in a browser,
before this step. Expect this to be where real bugs surface — that's not
a hedge, it's the honest read of what's actually been verified versus
just carefully written.

**If `client:build` fails with a TypeScript error:** send me the exact
error — component prop typing mismatches are the most likely category,
since I wrote every component's props interface by hand without a
compiler checking them against actual usage.

**If it builds but the page is blank or broken in the browser:** open
devtools console first. Two things were self-tested and can be ruled out
immediately if they're not the problem: `client/src/issuesLogic.ts`'s
filter/sort logic (11/11 passing, `client/.selftest/`) and
`src/safeStatic.ts`'s path handling (8/8 passing, including the exact
sibling-directory-prefix payload that broke the previous static server).
Everything else — component rendering, the `useEffect` timing in
`TraceView.tsx`, prop drilling in `App.tsx` — is unverified. Send me the
console error and the `/api/scan` response from the Network tab.

---

## Step 7 — the actual headline: the PR gate

```bash
npm run gate -- --repo demo/vulnerable-app --base pre-pr --head pr-482
```

**Run this and watch it — this is the strongest evidence in the whole
submission, not an afterthought.** `demo/vulnerable-app` has two real git
commits (`pre-pr`, `pr-482`) simulating an actual pull request with a
plausible, boring commit message ("restore legacy token support for the
mobile client"). The gate should report exactly one newly reachable CVE
(`CVE-2022-23529`, `jsonwebtoken.verify`), zero newly-clear, and exit
non-zero.

**Expected output, roughly:**
```
scanning pre-pr (base) ...
scanning pr-482 (head) ...

✗ This change introduces 1 newly reachable CVE(s):
  CVE-2022-23529  jsonwebtoken.verify  [high]
    legacyAuthMiddleware (src/auth.js)
```

**If this fails with a git error:** confirm `demo/vulnerable-app` has its
own `.git` directory and both tags exist: `cd demo/vulnerable-app && git
tag` should list `pre-pr` and `pr-482`. If missing (e.g. dropped during a
zip/transfer), tell me and I'll regenerate the two commits.

**If it reports 0 newly reachable CVEs:** the `git worktree` mechanic
itself was already verified directly in the sandbox (`grep -c
legacyAuthMiddleware` returns `0` on `pre-pr` and `2` on `pr-482` — see
README §15.4), so a false negative here is more likely a real bug in
`extractCallGraph` not recognizing `app.use(legacyAuthMiddleware)` as
wiring a new entry point — check `classifyEntryPoint` in
`src/extract/callgraph.ts` against how ts-morph actually represents that
call shape on real ASTs, which this sandbox has never been able to test.

---

## What to send back after this run

Whichever step you get to, send:
1. The exact command run and its full output (not a paraphrase).
2. If it's Step 2, the raw JSON response.
3. If it's Step 5, the terminal table plus `entryPointCount` from the
   extraction log line.

That's enough for me to fix the actual bug instead of guessing at it.
