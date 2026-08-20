export type Severity = "critical" | "high" | "medium" | "low";
export type Status = "reachable" | "present-unreachable" | "not-present";

export interface Finding {
  cve: string;
  packageName: string;
  vulnerableExport: string;
  severity: Severity;
  summary: string;
  reference: string;
  status: Status;
  reachable: boolean;
  /** ordered id chain: entry function -> ... -> caller function -> sink key */
  path?: string[];
  pathHumanReadable?: string[];
}

export interface ScanStats {
  functions: number;
  localCalls: number;
  externalCalls: number;
  entryPoints: number;
}

export interface GraphNode {
  id: string;
  name: string;
  modulePath: string;
  startLine: number;
  isEntryPoint: boolean;
  entryKind: "http-route" | "cli-command" | "public-export" | null;
}

export interface GraphCall {
  callerId: string;
  calleeId: string;
}

export interface GraphSink {
  key: string;
  cve: string;
  packageName: string;
  vulnerableExport: string;
  severity: Severity;
  /** true when the repo actually calls this (package, export) pair somewhere */
  present: boolean;
}

export interface ScanGraph {
  functions: GraphNode[];
  calls: GraphCall[];
  sinks: GraphSink[];
  /** function id -> sink key, for every present sink */
  sinkCalls: Array<{ callerId: string; sinkKey: string }>;
}

export interface ScanResponse {
  stats: ScanStats;
  results: Finding[];
  graph: ScanGraph;
}