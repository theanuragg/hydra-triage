#!/usr/bin/env node
import { Command } from "commander";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import pc from "picocolors";
import { extractCallGraph } from "./extract/callgraph.js";
import { HydraClient } from "./hydraClient.js";
import { ingestCallGraph, ingestVulnDb, resetGraph } from "./ingest/write.js";
import { checkReachability } from "./query/reachability.js";
import { computeGate } from "./gate.js";
import { loadHydraConfig } from "./config.js";
import type { VulnerableFunctionEntry, ReachabilityResult } from "./types.js";

/**
 * The actual product pitch: this isn't a report you read after the fact,
 * it's a check that runs on every PR and blocks the merge if — and only
 * if — that specific PR makes a previously-unreachable CVE reachable.
 * "Still reachable, unchanged since last week" doesn't fail this PR;
 * that's not this PR's fault and re-flagging it every time is exactly
 * the alert fatigue this whole project exists to fix.
 */

const defaults = loadHydraConfig();
const program = new Command();

program
  .name("hydra-triage-gate")
  .description("PR gate: blocks a merge only if it makes a new CVE reachable.")
  .requiredOption("--repo <path>", "path to the git repo to check")
  .requiredOption("--base <ref>", "base ref (e.g. the PR's target branch)")
  .requiredOption("--head <ref>", "head ref (e.g. the PR's commit)")
  .option("--base-url <url>", "HydraDB HTTP base URL (env: HYDRA_BASE_URL)", defaults.baseUrl)
  .option("--token <token>", "HydraDB auth token (env: HYDRA_TOKEN)", defaults.token)
  .option("--namespace <ns>", "HydraDB namespace (env: HYDRA_NAMESPACE)", defaults.namespace)
  .option("--graph <graph>", "HydraDB graph id (env: HYDRA_GRAPH)", defaults.graph)
  .option("--cell <cell>", "HydraDB cell id (env: HYDRA_CELL)", defaults.cellId)
  .option("--vulndb <path>", "path to vulnerable-function JSON db", path.join(import.meta.dirname, "vulndb/vulnerable-functions.json"))
  .option("--pr-comment-out <path>", "write a Markdown PR-comment-ready report here")
  .action(async (opts) => {
    const client = new HydraClient({
      baseUrl: opts.baseUrl,
      token: opts.token,
      namespace: opts.namespace,
      graph: opts.graph,
      cellId: opts.cell,
    });

    const vulndb: VulnerableFunctionEntry[] = JSON.parse(fs.readFileSync(opts.vulndb, "utf-8")).entries;

    console.log(pc.dim(`scanning ${opts.base} (base) ...`));
    const baseResults = await scanRef(client, opts.repo, opts.base, vulndb);

    console.log(pc.dim(`scanning ${opts.head} (head) ...`));
    const headResults = await scanRef(client, opts.repo, opts.head, vulndb);

    const gate = computeGate(baseResults, headResults);

    console.log();
    if (gate.newlyReachable.length === 0) {
      console.log(pc.green(pc.bold("✓ No new reachable CVEs introduced by this change.")));
    } else {
      console.log(pc.red(pc.bold(`✗ This change introduces ${gate.newlyReachable.length} newly reachable CVE(s):`)));
      for (const e of gate.newlyReachable) {
        console.log(`  ${pc.red(pc.bold(e.cve))}  ${e.packageName}.${e.vulnerableExport}  [${e.severity}]`);
        if (e.pathHumanReadable) console.log("    " + e.pathHumanReadable.join(pc.dim("  ->  ")));
      }
    }
    if (gate.newlyClear.length > 0) {
      console.log();
      console.log(pc.green(`Also fixed ${gate.newlyClear.length} previously-reachable CVE(s):`));
      for (const e of gate.newlyClear) console.log(`  ${pc.green(e.cve)}  ${e.packageName}.${e.vulnerableExport}`);
    }

    if (opts.prCommentOut) {
      fs.writeFileSync(opts.prCommentOut, renderMarkdown(gate, opts.base, opts.head));
      console.log();
      console.log(pc.dim(`PR comment written to ${opts.prCommentOut}`));
    }

    process.exit(gate.shouldBlock ? 1 : 0);
  });

async function scanRef(
  client: HydraClient,
  repoPath: string,
  ref: string,
  vulndb: VulnerableFunctionEntry[],
): Promise<ReachabilityResult[]> {
  const worktreeDir = fs.mkdtempSync(path.join(os.tmpdir(), "hydra-triage-gate-"));
  try {
    // Real git, not a diff parser: checking out the actual ref means the
    // extractor sees exactly the files that ref contains, with zero
    // special-casing for what changed — the same code path as scanning
    // any other repo.
    execFileSync("git", ["worktree", "add", "--detach", worktreeDir, ref], { cwd: repoPath, stdio: "pipe" });

    const graph = extractCallGraph(worktreeDir);
    await resetGraph(client);
    await ingestCallGraph(client, graph);
    const presentSinkIds = await ingestVulnDb(client, graph, vulndb);
    return await checkReachability(client, vulndb, presentSinkIds);
  } finally {
    try {
      execFileSync("git", ["worktree", "remove", "--force", worktreeDir], { cwd: repoPath, stdio: "pipe" });
    } catch {
      fs.rmSync(worktreeDir, { recursive: true, force: true });
    }
  }
}

function renderMarkdown(gate: ReturnType<typeof computeGate>, base: string, head: string): string {
  const lines: string[] = [];
  lines.push(`### hydra-triage — reachability gate (\`${base}\` → \`${head}\`)`);
  lines.push("");
  if (gate.shouldBlock) {
    lines.push(`❌ **This PR introduces ${gate.newlyReachable.length} newly reachable CVE(s).**`);
    lines.push("");
    lines.push("| CVE | Package | Export | Severity | Call path |");
    lines.push("|---|---|---|---|---|");
    for (const e of gate.newlyReachable) {
      lines.push(`| ${e.cve} | ${e.packageName} | \`${e.vulnerableExport}\` | ${e.severity} | ${(e.pathHumanReadable ?? []).join(" → ") || "—"} |`);
    }
  } else {
    lines.push("✅ No new reachable CVEs introduced by this change.");
  }
  if (gate.newlyClear.length > 0) {
    lines.push("");
    lines.push(`Also resolved ${gate.newlyClear.length} previously-reachable CVE(s): ${gate.newlyClear.map((e) => e.cve).join(", ")}.`);
  }
  return lines.join("\n") + "\n";
}

program.parseAsync().catch((err) => {
  console.error(pc.red("hydra-triage-gate failed:"), err instanceof Error ? err.message : err);
  process.exit(1);
});
