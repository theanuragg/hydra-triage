import { filterAndSortIssues, DEFAULT_FILTER_STATE } from "./build/issuesLogic.js";

const findings = [
  { cve: "CVE-2022-29078", packageName: "ejs", vulnerableExport: "render", severity: "critical", status: "reachable", summary: "", reference: "" },
  { cve: "CVE-2021-23337", packageName: "lodash", vulnerableExport: "template", severity: "high", status: "reachable", summary: "", reference: "" },
  { cve: "CVE-2018-3721", packageName: "lodash", vulnerableExport: "merge", severity: "high", status: "reachable", summary: "", reference: "" },
  { cve: "CVE-2022-23529", packageName: "jsonwebtoken", vulnerableExport: "verify", severity: "high", status: "present-unreachable", summary: "", reference: "" },
  { cve: "CVE-2020-7598", packageName: "minimist", vulnerableExport: "default", severity: "critical", status: "present-unreachable", summary: "", reference: "" },
  { cve: "CVE-2017-5941", packageName: "node-serialize", vulnerableExport: "unserialize", severity: "critical", status: "present-unreachable", summary: "", reference: "" },
];

let failures = 0;
const check = (label, cond) => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${label}`);
  if (!cond) failures++;
};

// default: severity asc -> critical, critical, critical, high, high, high (stable-ish within tiers)
{
  const out = filterAndSortIssues(findings, DEFAULT_FILTER_STATE);
  check("default sort: 6 results, no filtering", out.length === 6);
  check("default sort: first result is a critical", out[0].severity === "critical");
  check("default sort: last result is a high", out[out.length - 1].severity === "high");
}

// severity filter
{
  const out = filterAndSortIssues(findings, { ...DEFAULT_FILTER_STATE, severity: "critical" });
  check("severity filter: exactly 3 critical findings", out.length === 3);
  check("severity filter: all results are critical", out.every((f) => f.severity === "critical"));
}

// status filter
{
  const out = filterAndSortIssues(findings, { ...DEFAULT_FILTER_STATE, status: "reachable" });
  check("status filter: exactly 3 reachable findings", out.length === 3);
}

// search: package name
{
  const out = filterAndSortIssues(findings, { ...DEFAULT_FILTER_STATE, search: "lodash" });
  check("search 'lodash': 2 results", out.length === 2);
}

// search: case-insensitive, matches CVE id
{
  const out = filterAndSortIssues(findings, { ...DEFAULT_FILTER_STATE, search: "cve-2022-23529" });
  check("search is case-insensitive and matches CVE id", out.length === 1 && out[0].cve === "CVE-2022-23529");
}

// combined filter + search with zero matches
{
  const out = filterAndSortIssues(findings, { ...DEFAULT_FILTER_STATE, severity: "low", search: "" });
  check("filter with no matches returns empty array, not an error", Array.isArray(out) && out.length === 0);
}

// sort by cve, descending
{
  const out = filterAndSortIssues(findings, { ...DEFAULT_FILTER_STATE, sortKey: "cve", sortDir: "desc" });
  const cves = out.map((f) => f.cve);
  const sorted = [...cves].sort().reverse();
  check("sort by cve desc matches manual string sort", JSON.stringify(cves) === JSON.stringify(sorted));
}

// original array not mutated
{
  const before = JSON.stringify(findings);
  filterAndSortIssues(findings, { ...DEFAULT_FILTER_STATE, sortDir: "desc", search: "lodash" });
  check("input array is not mutated by filtering/sorting", JSON.stringify(findings) === before);
}

console.log();
if (failures > 0) {
  console.error(`${failures} FAILURE(S)`);
  process.exit(1);
}
console.log("ALL ISSUES-LOGIC CHECKS PASSED");
