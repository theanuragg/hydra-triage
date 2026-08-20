/**
 * Shared types for hydra-triage.
 *
 * The pipeline is: extract (source -> call graph) -> ingest (call graph +
 * vuln db -> HydraDB) -> query (HydraDB -> reachability report).
 */

export interface FunctionNode {
  /** Stable id: `${modulePath}#${functionName}#${startLine}` */
  id: string;
  name: string;
  modulePath: string; // path relative to repo root
  startLine: number;
  /** True if this function is reachable from outside the process boundary:
   *  an exported HTTP handler, a CLI command, a package's public export, etc. */
  isEntryPoint: boolean;
  entryKind?: "http-route" | "cli-command" | "public-export";
}

export interface CallEdge {
  callerId: string;
  calleeId: string;
  /** The import specifier the callee was resolved through, e.g. "lodash" or "./util" */
  viaImport?: string;
}

export interface CallGraph {
  functions: FunctionNode[];
  edges: CallEdge[];
  /** node_modules package name -> set of local function ids that call directly into it */
  externalCalls: Array<{
    callerId: string;
    packageName: string;
    importedName: string; // the specific export called, e.g. "template" from lodash
  }>;
}

/** One row in the vulnerable-function seed database. */
export interface VulnerableFunctionEntry {
  cve: string;
  packageName: string;
  /** semver range this entry applies to, informational only in the MVP */
  affectedVersions: string;
  /** the exported function name that carries the vulnerable code path */
  vulnerableExport: string;
  severity: "critical" | "high" | "medium" | "low";
  summary: string;
  /** URL to the advisory, for the report */
  reference: string;
}

export interface ReachabilityResult {
  cve: string;
  packageName: string;
  vulnerableExport: string;
  severity: VulnerableFunctionEntry["severity"];
  /** carried through from the vulndb entry so a findings UI can show what
   *  the CVE actually is, not just its id — an earlier version of this
   *  type dropped both fields between ingestion and the report. */
  summary: string;
  reference: string;
  /**
   * "not-present"          — repo never calls the vulnerable export at all;
   *                          computed locally, HydraDB is never queried for it.
   * "present-unreachable"  — the call exists somewhere in the repo, but no
   *                          entry point has a bounded-length path to it.
   * "reachable"            — an entry point can reach it; this is the real finding.
   */
  status: "not-present" | "present-unreachable" | "reachable";
  reachable: boolean;
  /** ordered list of function ids from an entry point down to the vulnerable call, if reachable */
  path?: string[];
  pathHumanReadable?: string[];
}
