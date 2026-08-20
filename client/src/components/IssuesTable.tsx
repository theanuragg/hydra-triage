import { useState } from "react";
import type { Finding, Severity, Status } from "../types";
import { filterAndSortIssues, DEFAULT_FILTER_STATE, type SortKey, type IssuesFilterState } from "../issuesLogic";

const COLUMNS: { key: SortKey; label: string }[] = [
  { key: "cve", label: "CVE" },
  { key: "packageName", label: "Package" },
  { key: "vulnerableExport", label: "Export" },
  { key: "severity", label: "Severity" },
  { key: "status", label: "Status" },
];

function statusLabel(status: Status): string {
  return status === "reachable" ? "Reachable" : status === "present-unreachable" ? "No path" : "Not called";
}

function csvCell(value: string): string {
  return /[",\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

function download(filename: string, content: string, type: string): void {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function exportCsv(findings: Finding[]): void {
  const header = "cve,packageName,vulnerableExport,severity,status,reachable,summary,reference";
  const rows = findings.map((f) =>
    [f.cve, f.packageName, f.vulnerableExport, f.severity, f.status, f.reachable, f.summary, f.reference]
      .map((v) => csvCell(String(v)))
      .join(","),
  );
  download("hydra-triage-findings.csv", `\uFEFF${[header, ...rows].join("\n")}`, "text/csv;charset=utf-8");
}

function exportJson(findings: Finding[]): void {
  download("hydra-triage-findings.json", JSON.stringify(findings, null, 2), "application/json");
}

export default function IssuesTable({ findings }: { findings: Finding[] }) {
  const [filter, setFilter] = useState<IssuesFilterState>(DEFAULT_FILTER_STATE);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const rows = filterAndSortIssues(findings, filter);

  const toggleSort = (key: SortKey) => {
    setFilter((f) => (f.sortKey === key ? { ...f, sortDir: f.sortDir === "asc" ? "desc" : "asc" } : { ...f, sortKey: key, sortDir: "asc" }));
  };

  const toggleExpanded = (cve: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(cve)) next.delete(cve);
      else next.add(cve);
      return next;
    });
  };

  return (
    <>
      <div className="issues-toolbar">
        <label className="visually-hidden" htmlFor="issues-search">
          Search findings
        </label>
        <input
          id="issues-search"
          className="issues-search mono"
          type="text"
          placeholder="search CVE, package, or export…"
          value={filter.search}
          onChange={(e) => setFilter((f) => ({ ...f, search: e.target.value }))}
        />
        <label className="visually-hidden" htmlFor="issues-severity">
          Filter by severity
        </label>
        <select
          id="issues-severity"
          className="issues-filter mono"
          value={filter.severity}
          onChange={(e) => setFilter((f) => ({ ...f, severity: e.target.value as Severity | "" }))}
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <label className="visually-hidden" htmlFor="issues-status">
          Filter by status
        </label>
        <select
          id="issues-status"
          className="issues-filter mono"
          value={filter.status}
          onChange={(e) => setFilter((f) => ({ ...f, status: e.target.value as Status | "" }))}
        >
          <option value="">All statuses</option>
          <option value="reachable">Reachable</option>
          <option value="present-unreachable">Present, no path</option>
          <option value="not-present">Not called</option>
        </select>
        {findings.length > 0 && (
          <button className="export-btn" type="button" onClick={() => exportCsv(findings)} title="Download findings as CSV">
            CSV
          </button>
        )}
        {findings.length > 0 && (
          <button className="export-btn" type="button" onClick={() => exportJson(findings)} title="Download findings as JSON">
            JSON
          </button>
        )}
      </div>

      <div className="issues-table-wrap">
        <table className="issues-table">
          <thead>
            <tr>
              {COLUMNS.map((col) => (
                <th key={col.key} className="mono" onClick={() => toggleSort(col.key)}>
                  {col.label}
                  {filter.sortKey === col.key && <span className="arrow">{filter.sortDir === "asc" ? "▲" : "▼"}</span>}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={5} className="empty-state">
                  {findings.length === 0 ? "Run a scan to populate findings." : "No findings match this filter."}
                </td>
              </tr>
            ) : (
              rows.map((r) => (
                <RowGroup key={r.cve} finding={r} isExpanded={expanded.has(r.cve)} onToggle={() => toggleExpanded(r.cve)} />
              ))
            )}
          </tbody>
        </table>
      </div>
      <div className="issues-count-line mono">
        {rows.length} of {findings.length} findings shown
      </div>
    </>
  );
}

function RowGroup({ finding, isExpanded, onToggle }: { finding: Finding; isExpanded: boolean; onToggle: () => void }) {
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onToggle();
    }
  };
  return (
    <>
      <tr
        className={`issue-row status-${finding.status}`}
        onClick={onToggle}
        tabIndex={0}
        aria-expanded={isExpanded}
        onKeyDown={onKeyDown}
      >
        <td className="cve data">{finding.cve}</td>
        <td className="pkg">{finding.packageName}</td>
        <td className="exp data">{finding.vulnerableExport}</td>
        <td>
          <span className={`sev-pill sev-${finding.severity}`}>{finding.severity}</span>
        </td>
        <td>
          <span className={`issue-status-badge status-${finding.status}`}>{statusLabel(finding.status)}</span>
        </td>
      </tr>
      {isExpanded && (
        <tr className="issue-detail">
          <td colSpan={5}>
            <div className="issue-detail-summary">{finding.summary || "No summary available."}</div>
            {finding.pathHumanReadable && finding.pathHumanReadable.length > 0 && (
              <div className="issue-detail-path data">
                {finding.pathHumanReadable.map((step, i) => (
                  <span key={i}>
                    {i > 0 && <span className="arrow-sep">→</span>}
                    {step}
                  </span>
                ))}
                <span className="arrow-sep">→</span>
                {finding.packageName}.{finding.vulnerableExport}
              </div>
            )}
            {finding.reference && finding.reference !== "n/a" && (
              <div className="issue-detail-ref">
                <a href={finding.reference} target="_blank" rel="noopener noreferrer">
                  advisory →
                </a>
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  );
}