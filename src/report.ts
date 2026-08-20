import Table from "cli-table3";
import pc from "picocolors";
import fs from "node:fs";
import type { ReachabilityResult } from "./types.js";

export function printConsoleReport(results: ReachabilityResult[]): void {
  const reachable = results.filter((r) => r.status === "reachable");
  const presentUnreachable = results.filter((r) => r.status === "present-unreachable");
  const notPresent = results.filter((r) => r.status === "not-present");

  const table = new Table({
    head: ["CVE", "Package", "Export", "Severity", "Verdict"],
    style: { head: ["cyan"] },
  });

  for (const r of [...reachable, ...presentUnreachable, ...notPresent]) {
    table.push([r.cve, r.packageName, r.vulnerableExport, severityColor(r.severity), verdictLabel(r.status)]);
  }

  console.log(table.toString());
  console.log();
  console.log(
    pc.bold(
      `${reachable.length}/${results.length} flagged CVEs have a live call path from an entry point. ` +
        `${presentUnreachable.length} are called somewhere in the repo but not on any executable path from an entry ` +
        `point — noise, not risk. ${notPresent.length} are in the vuln database but never called at all.`,
    ),
  );

  for (const r of reachable) {
    console.log();
    console.log(pc.red(pc.bold(`  ${r.cve} — ${r.packageName}.${r.vulnerableExport}`)));
    if (r.pathHumanReadable) {
      console.log("    " + r.pathHumanReadable.join(pc.dim("  ->  ")));
    }
  }
}

function verdictLabel(status: ReachabilityResult["status"]): string {
  switch (status) {
    case "reachable":
      return pc.red(pc.bold("REACHABLE"));
    case "present-unreachable":
      return pc.yellow("present, not reachable");
    case "not-present":
      return pc.dim("not called");
  }
}

function severityColor(sev: ReachabilityResult["severity"]): string {
  switch (sev) {
    case "critical":
      return pc.bgRed(pc.white(" critical "));
    case "high":
      return pc.red("high");
    case "medium":
      return pc.yellow("medium");
    default:
      return pc.dim("low");
  }
}

export function writeHtmlReport(results: ReachabilityResult[], outPath: string): void {
  const reachable = results.filter((r) => r.status === "reachable");
  const presentUnreachable = results.filter((r) => r.status === "present-unreachable");
  const notPresent = results.filter((r) => r.status === "not-present");

  const verdictHtml = (status: ReachabilityResult["status"]) => {
    switch (status) {
      case "reachable":
        return '<span class="verdict bad">REACHABLE</span>';
      case "present-unreachable":
        return '<span class="verdict warn">present, not reachable</span>';
      case "not-present":
        return '<span class="verdict ok">not called</span>';
    }
  };

  const row = (r: ReachabilityResult) => `
    <tr class="${r.status}">
      <td>${r.cve}</td>
      <td>${r.packageName}</td>
      <td><code>${r.vulnerableExport}</code></td>
      <td><span class="pill ${r.severity}">${r.severity}</span></td>
      <td>${verdictHtml(r.status)}</td>
      <td>${r.pathHumanReadable ? r.pathHumanReadable.join(" &rarr; ") : "&mdash;"}</td>
      <td>${r.reference && r.reference !== "n/a" ? `<a href="${r.reference}" target="_blank" rel="noopener">advisory</a>` : "&mdash;"}</td>
    </tr>`;

  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8" />
<title>hydra-triage report</title>
<style>
  :root { color-scheme: dark; }
  body { font-family: ui-monospace, "SF Mono", Menlo, monospace; background:#0b0d12; color:#e6e8ee; margin:0; padding:2.5rem; }
  h1 { font-size:1.4rem; margin:0 0 .25rem; }
  .sub { color:#8b93a7; margin-bottom:2rem; }
  table { width:100%; border-collapse:collapse; font-size:.85rem; }
  th, td { text-align:left; padding:.6rem .8rem; border-bottom:1px solid #1c202b; vertical-align:top; }
  th { color:#8b93a7; font-weight:600; text-transform:uppercase; letter-spacing:.04em; font-size:.7rem; }
  tr.reachable { background:rgba(240,70,70,0.06); }
  .pill { padding:.1rem .5rem; border-radius:999px; font-size:.7rem; text-transform:uppercase; }
  .pill.critical { background:#7f1d1d; color:#fecaca; }
  .pill.high { background:#7c2d12; color:#fed7aa; }
  .pill.medium { background:#713f12; color:#fef08a; }
  .pill.low { background:#1e293b; color:#94a3b8; }
  .verdict.bad { color:#fca5a5; font-weight:700; }
  .verdict.warn { color:#fde68a; }
  .verdict.ok { color:#86efac; }
  .summary { margin:1.5rem 0; padding:1rem 1.2rem; background:#131722; border-radius:8px; border:1px solid #1c202b; }
  code { color:#a5b4fc; }
</style></head>
<body>
  <h1>hydra-triage</h1>
  <div class="sub">reachability-based CVE triage over a HydraDB call graph</div>
  <div class="summary">
    <strong>${reachable.length}/${results.length}</strong> flagged CVEs have a live call path from an entry point.
    <strong>${presentUnreachable.length}</strong> are called somewhere in the repo but on no executable path — noise your SCA tool
    would still flag. <strong>${notPresent.length}</strong> are never called at all.
  </div>
  <table>
    <thead><tr><th>CVE</th><th>Package</th><th>Export</th><th>Severity</th><th>Verdict</th><th>Call path</th><th>Reference</th></tr></thead>
    <tbody>${[...reachable, ...presentUnreachable, ...notPresent].map(row).join("")}</tbody>
  </table>
</body></html>`;

  fs.writeFileSync(outPath, html, "utf-8");
}
