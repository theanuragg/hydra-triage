import type { CallGraph, VulnerableFunctionEntry } from "../types.js";
import type { HydraClient } from "../hydraClient.js";
import { vertexId, edgeId } from "../identity.js";

/**
 * Graph model:
 *
 *   (:Function {id, key, name, modulePath, startLine, isEntryPoint, entryKind})
 *   (:Function)-[:CALLS {id}]->(:Function)                       local call graph
 *   (:VulnerableSink {id, key, cve, packageName, vulnerableExport,
 *                      severity, summary, reference})
 *   (:Function)-[:CALLS_VULNERABLE_SINK {id}]->(:VulnerableSink)
 *
 * `id` is HydraDB's internal u64 vertex id (see identity.ts) — edges can
 * only address endpoints by integer id. The original string id is kept as
 * `key` for property-predicate MATCHes and the path procedures'
 * sourceValues/targetValues selectors.
 *
 * Every write below follows HydraDB's UNWIND-update BNF strictly:
 *  - vertex upserts MERGE on {id} alone and apply label + properties via
 *    SET (a label in the MERGE pattern is rejected);
 *  - edge upserts MATCH both endpoints by integer id, and MERGE the
 *    relationship with an explicit {id} (a relationship without one is
 *    treated as a fresh create on every run);
 *  - everything reads from $rows, never from an inlined literal.
 */

const FUNCTION_UPSERT = `
MERGE (f {id: row.id})
SET f:Function, f.key = row.key, f.name = row.name, f.modulePath = row.modulePath,
    f.startLine = row.startLine, f.isEntryPoint = row.isEntryPoint, f.entryKind = row.entryKind`;

const SINK_UPSERT = `
MERGE (v {id: row.id})
SET v:VulnerableSink, v.key = row.key, v.cve = row.cve, v.packageName = row.packageName,
    v.vulnerableExport = row.vulnerableExport, v.severity = row.severity,
    v.summary = row.summary, v.reference = row.reference`;

const CALLS_MERGE = `
MATCH (a:Function {id: row.src}), (b:Function {id: row.dst})
MERGE (a)-[r:CALLS {id: row.relId}]->(b)`;

const SINK_EDGE_MERGE = `
MATCH (a:Function {id: row.src}), (b:VulnerableSink {id: row.dst})
MERGE (a)-[r:CALLS_VULNERABLE_SINK {id: row.relId}]->(b)`;

export async function ingestCallGraph(client: HydraClient, graph: CallGraph): Promise<void> {
  await client.batchWrite(
    FUNCTION_UPSERT,
    graph.functions.map((f) => ({
      id: vertexId(f.id),
      key: f.id,
      name: f.name,
      modulePath: f.modulePath,
      startLine: f.startLine,
      isEntryPoint: f.isEntryPoint,
      entryKind: f.entryKind ?? "",
    })),
  );

  await client.batchWrite(
    CALLS_MERGE,
    graph.edges.map((e) => ({
      src: vertexId(e.callerId),
      dst: vertexId(e.calleeId),
      relId: edgeId(e.callerId, e.calleeId, "CALLS"),
    })),
  );
}

/**
 * Every (caller function, vulnerable sink) pair implied by the repo's
 * external calls: a function calls (packageName, importedName) and the
 * vuln db flags that exact export. Shared by ingestVulnDb (which wires
 * the edges into HydraDB) and webServer (which renders the same edges in
 * the browser graph), so the two can never disagree about what "present"
 * means.
 */
export function sinkEdgePairs(
  graph: CallGraph,
  entries: VulnerableFunctionEntry[],
): Array<{ callerId: string; sinkKey: string }> {
  return graph.externalCalls.flatMap((call) =>
    entries
      .filter(
        (e) => e.packageName === call.packageName && e.vulnerableExport === call.importedName,
      )
      .map((m) => ({
        callerId: call.callerId,
        sinkKey: `${m.packageName}::${m.vulnerableExport}::${m.cve}`,
      })),
  );
}

/**
 * Returns the set of VulnerableSink keys that received at least one
 * CALLS_VULNERABLE_SINK edge — i.e. the repo actually calls that
 * (package, export) pair somewhere, regardless of whether it's reachable
 * from an entry point. query/reachability.ts uses this to short-circuit
 * "not-present" CVEs without ever hitting HydraDB for them.
 */
export async function ingestVulnDb(
  client: HydraClient,
  graph: CallGraph,
  entries: VulnerableFunctionEntry[],
): Promise<Set<string>> {
  const sinkKeyOf = (e: VulnerableFunctionEntry) => `${e.packageName}::${e.vulnerableExport}::${e.cve}`;

  const sinkRows = entries.map((e) => {
    const key = sinkKeyOf(e);
    return {
      id: vertexId(key),
      key,
      cve: e.cve,
      packageName: e.packageName,
      vulnerableExport: e.vulnerableExport,
      severity: e.severity,
      summary: e.summary,
      reference: e.reference,
    };
  });

  await client.batchWrite(SINK_UPSERT, sinkRows);

  const pairs = sinkEdgePairs(graph, entries);
  const sinkEdges = pairs.map(({ callerId, sinkKey }) => ({
    src: vertexId(callerId),
    dst: vertexId(sinkKey),
    relId: edgeId(callerId, sinkKey, "CALLS_VULNERABLE_SINK"),
  }));

  await client.batchWrite(SINK_EDGE_MERGE, sinkEdges);

  return new Set(pairs.map((p) => p.sinkKey));
}

/** Wipes the graph for this cell. Handy for repeated demo runs.
 *  HydraDB rejects bare `MATCH (n)` scans ("node-only MATCH requires an
 *  id, label, or property predicate"), so this is scoped per label —
 *  Function nodes cover the CALLS edges via DETACH, then sinks. */
export async function resetGraph(client: HydraClient): Promise<void> {
  await client.query("MATCH (n:Function) DETACH DELETE n");
  await client.query("MATCH (v:VulnerableSink) DETACH DELETE v");
}