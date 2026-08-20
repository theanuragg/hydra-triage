import { computeGate } from "./build/gate.js";

const mk = (cve, status, extra = {}) => ({
  cve, packageName: "pkg", vulnerableExport: "fn", severity: "high", status, reachable: status === "reachable", ...extra,
});

let failures = 0;
const check = (label, cond) => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${label}`);
  if (!cond) failures++;
};

// ---- Scenario 1: mirrors the real demo (pre-pr -> PR #482) ----
// base: ejs/lodash-template/lodash-merge reachable, jwt/minimist/node-serialize present-unreachable
// head: same, EXCEPT jwt.verify becomes reachable because PR #482 mounted legacyAuthMiddleware
{
  const base = [
    mk("CVE-2022-29078", "reachable"),
    mk("CVE-2021-23337", "reachable"),
    mk("CVE-2018-3721", "reachable"),
    mk("CVE-2022-23529", "present-unreachable"), // jwt.verify — about to change
    mk("CVE-2020-7598", "present-unreachable"),
    mk("CVE-2017-5941", "present-unreachable"),
  ];
  const head = [
    mk("CVE-2022-29078", "reachable"),
    mk("CVE-2021-23337", "reachable"),
    mk("CVE-2018-3721", "reachable"),
    mk("CVE-2022-23529", "reachable", { pathHumanReadable: ["legacyAuthMiddleware (src/auth.js)"] }), // <- the PR's actual effect
    mk("CVE-2020-7598", "present-unreachable"),
    mk("CVE-2017-5941", "present-unreachable"),
  ];

  const gate = computeGate(base, head);
  check("exactly 1 newly reachable CVE", gate.newlyReachable.length === 1);
  check("the newly reachable CVE is CVE-2022-23529 (jwt.verify)", gate.newlyReachable[0]?.cve === "CVE-2022-23529");
  check("0 newly clear", gate.newlyClear.length === 0);
  check("5 unchanged (3 already-reachable + 2 still-unreachable)", gate.unchanged.length === 5);
  check("shouldBlock is true", gate.shouldBlock === true);
}

// ---- Scenario 2: a PR that fixes something, no new exposure ----
{
  const base = [mk("CVE-X", "reachable"), mk("CVE-Y", "present-unreachable")];
  const head = [mk("CVE-X", "present-unreachable"), mk("CVE-Y", "present-unreachable")];
  const gate = computeGate(base, head);
  check("fix-only PR: 0 newly reachable", gate.newlyReachable.length === 0);
  check("fix-only PR: 1 newly clear", gate.newlyClear.length === 1);
  check("fix-only PR: shouldBlock is false", gate.shouldBlock === false);
}

// ---- Scenario 3: no changes at all ----
{
  const base = [mk("CVE-X", "reachable"), mk("CVE-Y", "not-present")];
  const head = [mk("CVE-X", "reachable"), mk("CVE-Y", "not-present")];
  const gate = computeGate(base, head);
  check("no-op PR: shouldBlock is false", gate.shouldBlock === false);
  check("no-op PR: everything unchanged", gate.unchanged.length === 2);
}

// ---- Scenario 4: brand new CVE only present at head (e.g. vulndb was updated) ----
{
  const base = [mk("CVE-X", "reachable")];
  const head = [mk("CVE-X", "reachable"), mk("CVE-NEW", "reachable")];
  const gate = computeGate(base, head);
  check("new CVE entry, reachable at head, absent at base -> counts as newly reachable", gate.newlyReachable.some((e) => e.cve === "CVE-NEW"));
}

console.log();
if (failures > 0) {
  console.error(`${failures} FAILURE(S)`);
  process.exit(1);
}
console.log("ALL GATE-LOGIC CHECKS PASSED");
