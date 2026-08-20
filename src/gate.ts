import type { ReachabilityResult } from "./types.js";

export interface DiffEntry {
  cve: string;
  packageName: string;
  vulnerableExport: string;
  severity: ReachabilityResult["severity"];
  baseStatus: ReachabilityResult["status"];
  headStatus: ReachabilityResult["status"];
  pathHumanReadable?: string[];
}

export interface GateResult {
  newlyReachable: DiffEntry[];
  newlyClear: DiffEntry[]; // a PR that fixes something — worth celebrating in the same report, not just gating
  unchanged: DiffEntry[];
  shouldBlock: boolean;
}

/**
 * The entire point of the PR-gate product: given a reachability scan of
 * the base ref and one of the head ref (same vulndb, same query logic —
 * see diffCli.ts for how those are produced), find CVEs whose status
 * *became* "reachable" that weren't before. That's the only thing worth
 * blocking a merge over — "still reachable, unchanged" is old news the
 * team already knows about, not a reason to fail this specific PR.
 *
 * Pure function, no I/O, so it's testable without HydraDB, ts-morph, or
 * git — see .selftest/run-gate.mjs.
 */
export function computeGate(base: ReachabilityResult[], head: ReachabilityResult[]): GateResult {
  const baseByCve = new Map(base.map((r) => [r.cve, r]));
  const headByCve = new Map(head.map((r) => [r.cve, r]));

  const allCves = new Set([...baseByCve.keys(), ...headByCve.keys()]);

  const newlyReachable: DiffEntry[] = [];
  const newlyClear: DiffEntry[] = [];
  const unchanged: DiffEntry[] = [];

  for (const cve of allCves) {
    const baseResult = baseByCve.get(cve);
    const headResult = headByCve.get(cve);
    if (!headResult) continue; // CVE dropped from the vulndb between scans — not this function's concern

    const baseStatus = baseResult?.status ?? "not-present";
    const headStatus = headResult.status;

    const entry: DiffEntry = {
      cve,
      packageName: headResult.packageName,
      vulnerableExport: headResult.vulnerableExport,
      severity: headResult.severity,
      baseStatus,
      headStatus,
      pathHumanReadable: headResult.pathHumanReadable,
    };

    if (baseStatus !== "reachable" && headStatus === "reachable") {
      newlyReachable.push(entry);
    } else if (baseStatus === "reachable" && headStatus !== "reachable") {
      newlyClear.push(entry);
    } else {
      unchanged.push(entry);
    }
  }

  return {
    newlyReachable,
    newlyClear,
    unchanged,
    shouldBlock: newlyReachable.length > 0,
  };
}
