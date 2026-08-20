import type { HydraClient } from "../hydraClient.js";
import { unwrapHydraValue } from "../hydraClient.js";
import type { VulnerableFunctionEntry, ReachabilityResult } from "../types.js";
import { cypherString } from "../cypherLiteral.js";

const MAX_HOPS = 8;

interface MSpathsPathNode {
  id: number;
  labels: string[];
  properties: Record<string, unknown>;
}

interface MSpathsResult {
  nodes: MSpathsPathNode[];
}

/** Path-procedure results carry each vertex property as a type-wrapped
 *  map {"String": ...} / {"Bool": ...}; MATCH-read cells carry plain
 *  `.value`s instead. Only the former needs unwrapping. */
function propStr(props: Record<string, unknown>, key: string): string | null {
  const v = unwrapHydraValue(props[key]);
  if (v === null || v === undefined) return null;
  return String(v);
}

/**
 * For each entry in the vuln db, first checks whether the repo's code
 * calls the vulnerable export at all (`presentSinkIds`, computed during
 * ingestion — see ingest/write.ts). If it doesn't, the CVE is reported as
 * "not-present" without ever querying HydraDB, since we already know a
 * CALLS_VULNERABLE_SINK edge doesn't exist. If it does, asks HydraDB via
 * the native MSpaths procedure: does a bounded call path exist from any
 * entry-point function (addressed by its `key` property) to this
 * VulnerableSink? That's the actual triage decision.
 *
 * MAX_HOPS now bounds the TOTAL number of traced edges (CALLS hops plus
 * the final CALLS_VULNERABLE_SINK hop), matching the native procedure's
 * maxLen config; the pre-rewrite MATCH allowed 8 CALLS hops plus the sink
 * hop, a distinction only visible in contrived deep graphs.
 */
export async function checkReachability(
  client: HydraClient,
  entries: VulnerableFunctionEntry[],
  presentSinkIds: Set<string>,
): Promise<ReachabilityResult[]> {
  const entryRes = await client.query(
    "MATCH (e:Function {isEntryPoint: true}) RETURN e.key AS key",
  );
  const entryKeys = entryRes.rows.map((r) => r[0].value as string);

  const results: ReachabilityResult[] = [];

  for (const entry of entries) {
    const sinkId = `${entry.packageName}::${entry.vulnerableExport}::${entry.cve}`;
    const base = {
      cve: entry.cve,
      packageName: entry.packageName,
      vulnerableExport: entry.vulnerableExport,
      severity: entry.severity,
      summary: entry.summary,
      reference: entry.reference,
    };

    if (!presentSinkIds.has(sinkId)) {
      results.push({ ...base, status: "not-present", reachable: false });
      continue;
    }

    // No entry points means no path can exist — skip the procedure
    // entirely (it rejects an empty sourceValues list as a parse error).
    if (entryKeys.length === 0) {
      results.push({ ...base, status: "present-unreachable", reachable: false });
      continue;
    }

    const pathRes = await client.query(
      `CALL algo.MSpaths({` +
        `sourceValues: [${entryKeys.map((k) => cypherString(k)).join(", ")}], ` +
        `sourceLabel: "Function", sourceProperty: "key", ` +
        `targetValues: [${cypherString(sinkId)}], ` +
        `targetLabel: "VulnerableSink", targetProperty: "key", ` +
        `relTypes: ["CALLS", "CALLS_VULNERABLE_SINK"], relDirection: "outgoing", ` +
        `maxLen: ${MAX_HOPS}, pathCount: 1, resultLimit: 1}) ` +
        `YIELD path RETURN path`,
    );

    if (pathRes.rows.length === 0) {
      results.push({ ...base, status: "present-unreachable", reachable: false });
      continue;
    }

    const path = pathRes.rows[0][0].value as MSpathsResult;
    results.push({
      ...base,
      status: "reachable",
      reachable: true,
      path: path.nodes.map((n) => propStr(n.properties, "key") ?? String(n.id)),
      pathHumanReadable: path.nodes.map((n) => {
        const props = n.properties;
        const isSink = props["cve"] !== undefined;
        if (isSink) {
          return `${propStr(props, "vulnerableExport") ?? "?"} (via ${propStr(props, "packageName") ?? "?"} — ${propStr(props, "cve") ?? ""})`;
        }
        return `${propStr(props, "name") ?? "?"} (${propStr(props, "modulePath") ?? "?"})`;
      }),
    });
  }

  return results;
}