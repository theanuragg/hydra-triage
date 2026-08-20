import type { HydraClient } from "../hydraClient.js";
import { vertexId, edgeId } from "../identity.js";

/**
 * Graph model for the incident replay (same HydraDB write contracts as
 * ingest/write.ts — integer vertex ids, string ids mirrored as `key`,
 * UNWIND bound to $rows, edges MERGEd with explicit {id}):
 *
 *   (:Version {id, key, package, version, malicious})
 *   (:Version)-[:DEPENDS_ON {id, range}]->(:Version)
 *   (:Consumer {id, key, name, vendor, packageDescription, isSynthetic})
 *   (:Consumer)-[:RESOLVED {id}]->(:Version)
 *
 * The real chain (event-stream@3.3.6 -> flatmap-stream@0.1.1, Consumer
 * "copay") is sourced entirely from src/incident/event-stream-2018.json,
 * which cites its primary sources. The decoy consumers below are added
 * ONLY to make the "exposed vs. actually targeted" contrast visible with
 * more than a single data point — every decoy is explicitly
 * isSynthetic: true and is never presented as a real project.
 */

export interface DecoyConsumer {
  name: string;
  packageDescription: string;
}

export const DECOY_CONSUMERS: DecoyConsumer[] = [
  { name: "(illustrative) internal-analytics-dashboard", packageDescription: "Internal analytics dashboard" },
  { name: "(illustrative) marketing-site-build-tool", packageDescription: "Static site generator for the marketing site" },
  { name: "(illustrative) ci-log-aggregator", packageDescription: "Aggregates CI logs across services" },
];

export interface IncidentData {
  compromisedVersions: Array<{ package: string; version: string; malicious: boolean }>;
  dependencyEdges: Array<{ from: string; to: string; range: string }>;
  targetedConsumer: { name: string; vendor: string; packageDescription: string };
}

const VERSION_UPSERT = `
MERGE (v {id: row.id})
SET v:Version, v.key = row.key, v.package = row.package, v.version = row.version, v.malicious = row.malicious`;

const DEPENDS_ON_MERGE = `
MATCH (a:Version {id: row.src}), (b:Version {id: row.dst})
MERGE (a)-[r:DEPENDS_ON {id: row.relId}]->(b)
SET r.range = row.range`;

const CONSUMER_UPSERT = `
MERGE (c {id: row.id})
SET c:Consumer, c.key = row.key, c.name = row.name, c.vendor = row.vendor,
    c.packageDescription = row.packageDescription, c.isSynthetic = row.isSynthetic`;

const RESOLVED_MERGE = `
MATCH (a:Consumer {id: row.src}), (b:Version {id: row.dst})
MERGE (a)-[r:RESOLVED {id: row.relId}]->(b)`;

export async function ingestIncident(client: HydraClient, data: IncidentData): Promise<void> {
  const versionRows = data.compromisedVersions.map((v) => {
    const key = `${v.package}@${v.version}`;
    return {
      id: vertexId(key),
      key,
      package: v.package,
      version: v.version,
      malicious: v.malicious,
    };
  });

  await client.batchWrite(VERSION_UPSERT, versionRows);

  const depRows = data.dependencyEdges.map((e) => ({
    src: vertexId(e.from),
    dst: vertexId(e.to),
    relId: edgeId(e.from, e.to, "DEPENDS_ON"),
    range: e.range,
  }));
  if (depRows.length > 0) {
    await client.batchWrite(DEPENDS_ON_MERGE, depRows);
  }

  // The one real, documented target.
  const realConsumerRow = {
    id: vertexId(data.targetedConsumer.name),
    key: data.targetedConsumer.name,
    name: data.targetedConsumer.name,
    vendor: data.targetedConsumer.vendor,
    packageDescription: data.targetedConsumer.packageDescription,
    isSynthetic: false,
  };

  // Illustrative decoys — same exposure, different (harmless) description,
  // so the activation-key filter has something to actually exclude.
  const decoyRows = DECOY_CONSUMERS.map((d) => ({
    id: vertexId(d.name),
    key: d.name,
    name: d.name,
    vendor: "(illustrative)",
    packageDescription: d.packageDescription,
    isSynthetic: true,
  }));

  const consumerRows = [realConsumerRow, ...decoyRows];
  await client.batchWrite(CONSUMER_UPSERT, consumerRows);

  // Every consumer here — real and decoy alike — resolved the same
  // compromised event-stream@3.3.6 during the exposure window. That's the
  // point: identical exposure, different outcome, decided entirely by the
  // packageDescription property filter downstream.
  const resolvedRows = consumerRows.map((c) => ({
    src: c.id,
    dst: vertexId("event-stream@3.3.6"),
    relId: edgeId(c.key, "event-stream@3.3.6", "RESOLVED"),
  }));
  await client.batchWrite(RESOLVED_MERGE, resolvedRows);
}