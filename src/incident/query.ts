import type { HydraClient } from "../hydraClient.js";
import { unwrapHydraValue } from "../hydraClient.js";
import { cypherString } from "../cypherLiteral.js";

/** RESOLVED (1 hop) + DEPENDS_ON*0..N, expressed as the procedure's maxLen. */
const MAX_HOPS = 5;

export interface ExposureRow {
  consumerId: string;
  isSynthetic: boolean;
  packageDescription: string;
}

interface PathNode {
  id: number;
  labels: string[];
  properties: Record<string, unknown>;
}

function propStr(props: Record<string, unknown>, key: string): string | null {
  const v = unwrapHydraValue(props[key]);
  if (v === null || v === undefined) return null;
  return String(v);
}

function propBool(props: Record<string, unknown>, key: string): boolean {
  return unwrapHydraValue(props[key]) === true;
}

async function readConsumerKeys(client: HydraClient, packageDescription: string | null): Promise<string[]> {
  const predicate =
    packageDescription === null
      ? ""
      : ` {packageDescription: ${cypherString(packageDescription)}}`;
  const res = await client.query(`MATCH (c:Consumer${predicate}) RETURN c.key AS key`);
  return res.rows.map((r) => r[0].value as string);
}

async function readMaliciousVersionKeys(client: HydraClient): Promise<string[]> {
  const res = await client.query("MATCH (v:Version {malicious: true}) RETURN v.key AS key");
  return res.rows.map((r) => r[0].value as string);
}

/**
 * One MSpaths call: every Consumer in sourceKeys that reaches any
 * malicious Version through RESOLVED/DEPENDS_ON, up to MAX_HOPS edges.
 * A Consumer appears at most once (first path found wins); its node
 * properties ride along on the path's first node so the caller can build
 * ExposureRows without extra round trips.
 */
async function exposedConsumers(
  client: HydraClient,
  sourceKeys: string[],
  maliciousKeys: string[],
): Promise<Array<{ key: string; props: Record<string, unknown> }>> {
  if (sourceKeys.length === 0 || maliciousKeys.length === 0) return [];

  const res = await client.query(
    `CALL algo.MSpaths({` +
      `sourceValues: [${sourceKeys.map((k) => cypherString(k)).join(", ")}], ` +
      `sourceLabel: "Consumer", sourceProperty: "key", ` +
      `targetValues: [${maliciousKeys.map((k) => cypherString(k)).join(", ")}], ` +
      `targetLabel: "Version", targetProperty: "key", ` +
      `relTypes: ["RESOLVED", "DEPENDS_ON"], relDirection: "outgoing", ` +
      `maxLen: ${MAX_HOPS}, pathCount: 1, pairwise: true, resultLimit: 100}) ` +
      `YIELD path RETURN path`,
  );

  const bySource = new Map<string, Record<string, unknown>>();
  for (const row of res.rows) {
    const path = row[0].value as unknown as { nodes: PathNode[] };
    const source = path.nodes[0];
    const key = propStr(source.properties, "key") ?? "";
    if (key && !bySource.has(key)) bySource.set(key, source.properties);
  }
  return [...bySource.entries()].map(([key, props]) => ({ key, props }));
}

/**
 * Query 1 — exposure: every Consumer whose resolved dependency tree
 * reaches a Version flagged malicious, within a bounded number of hops.
 * This is the query a generic "blast radius" tool stops at — and on its
 * own, in the real incident, it would flag every one of ~2M weekly
 * event-stream installs as "at risk," which is true but not useful.
 */
export async function queryExposed(client: HydraClient): Promise<ExposureRow[]> {
  const [consumers, malicious] = await Promise.all([
    readConsumerKeys(client, null),
    readMaliciousVersionKeys(client),
  ]);
  const found = await exposedConsumers(client, consumers, malicious);
  return found.map((c) => ({
    consumerId: c.key,
    isSynthetic: propBool(c.props, "isSynthetic"),
    packageDescription: propStr(c.props, "packageDescription") ?? "",
  }));
}

/**
 * Query 2 — actually targeted: the same reachability question, restricted
 * to Consumers carrying the one property that mattered in reality. This is
 * the payload's real activation check (process.env.npm_package_description
 * === "A Secure Bitcoin Wallet"), expressed as a graph property predicate
 * instead of runtime JS. It's the difference between "everyone who has the
 * malicious code" and "the one application it was built to actually harm."
 */
export async function queryActuallyTargeted(client: HydraClient, activationKey: string): Promise<ExposureRow[]> {
  const [consumers, malicious] = await Promise.all([
    readConsumerKeys(client, activationKey),
    readMaliciousVersionKeys(client),
  ]);
  const found = await exposedConsumers(client, consumers, malicious);
  return found.map((c) => ({
    consumerId: c.key,
    isSynthetic: propBool(c.props, "isSynthetic"),
    packageDescription: propStr(c.props, "packageDescription") ?? "",
  }));
}