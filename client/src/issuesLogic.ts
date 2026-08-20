import type { Finding, Severity, Status } from "./types";

export type SortKey = "cve" | "packageName" | "vulnerableExport" | "severity" | "status";
export type SortDir = "asc" | "desc";

export interface IssuesFilterState {
  search: string;
  severity: Severity | "";
  status: Status | "";
  sortKey: SortKey;
  sortDir: SortDir;
}

export const DEFAULT_FILTER_STATE: IssuesFilterState = {
  search: "",
  severity: "",
  status: "",
  sortKey: "severity",
  sortDir: "asc",
};

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

/**
 * The entire "Issues" tab's data logic, as one pure function: findings in,
 * filtered+sorted findings out. No component owns this — it's imported by
 * IssuesTable.tsx but doesn't know React exists, which is what makes it
 * testable via .selftest/run-issues-logic.mjs without a browser, Vite, or
 * npm install succeeding first (everything else in client/ does need that).
 */
export function filterAndSortIssues(findings: Finding[], filter: IssuesFilterState): Finding[] {
  const search = filter.search.trim().toLowerCase();

  const filtered = findings.filter((f) => {
    if (filter.severity && f.severity !== filter.severity) return false;
    if (filter.status && f.status !== filter.status) return false;
    if (search) {
      const haystack = `${f.cve} ${f.packageName} ${f.vulnerableExport}`.toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    return true;
  });

  const sorted = [...filtered].sort((a, b) => {
    let cmp: number;
    if (filter.sortKey === "severity") {
      cmp = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    } else {
      const av = String(a[filter.sortKey]).toLowerCase();
      const bv = String(b[filter.sortKey]).toLowerCase();
      cmp = av < bv ? -1 : av > bv ? 1 : 0;
    }
    return filter.sortDir === "asc" ? cmp : -cmp;
  });

  return sorted;
}
