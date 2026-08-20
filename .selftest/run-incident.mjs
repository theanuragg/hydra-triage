import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { HydraClient } from "./build/hydraClient.js";
import { ingestIncident, DECOY_CONSUMERS } from "./build/incident/ingest.js";
import { queryExposed, queryActuallyTargeted } from "./build/incident/query.js";
import { startFakeIncidentDB } from "./fakeIncidentDB.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));

async function main() {
  const incident = JSON.parse(
    fs.readFileSync(path.join(here, "..", "src", "incident", "event-stream-2018.json"), "utf-8"),
  );

  const { server, baseUrl } = await startFakeIncidentDB();
  const client = new HydraClient({ baseUrl, token: "x", namespace: "default", graph: "default", cellId: "cell-0" });

  await ingestIncident(client, {
    compromisedVersions: incident.compromisedVersions,
    dependencyEdges: incident.dependencyEdges,
    targetedConsumer: incident.targetedConsumer,
  });

  const exposed = await queryExposed(client);
  const targeted = await queryActuallyTargeted(client, incident.targetedConsumer.packageDescription);

  server.close();

  let failures = 0;
  const check = (label, cond) => {
    console.log(`${cond ? "PASS" : "FAIL"}  ${label}`);
    if (!cond) failures++;
  };

  const expectedExposedCount = 1 + DECOY_CONSUMERS.length; // real target + every decoy
  check(`exposed count is ${expectedExposedCount} (1 real + ${DECOY_CONSUMERS.length} decoys, all resolved the compromised version)`, exposed.length === expectedExposedCount);
  check("exposed includes the real target (copay)", exposed.some((c) => c.consumerId === incident.targetedConsumer.name));
  check("exposed includes every decoy", DECOY_CONSUMERS.every((d) => exposed.some((c) => c.consumerId === d.name)));

  check("targeted count is exactly 1", targeted.length === 1);
  check("the one targeted consumer is the real target (copay), not a decoy", targeted[0]?.consumerId === incident.targetedConsumer.name);
  check("none of the decoys pass the activation-key filter", targeted.every((c) => !c.isSynthetic));

  console.log();
  if (failures > 0) {
    console.error(`${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log(`ALL INCIDENT-MODULE CHECKS PASSED — ${exposed.length} exposed, ${targeted.length} actually targeted.`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});