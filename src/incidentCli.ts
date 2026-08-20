#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import pc from "picocolors";
import { HydraClient } from "./hydraClient.js";
import { ingestIncident } from "./incident/ingest.js";
import { queryExposed, queryActuallyTargeted } from "./incident/query.js";
import { resetGraph } from "./ingest/write.js";
import { loadHydraConfig } from "./config.js";

const here = path.dirname(fileURLToPath(import.meta.url));

const client = new HydraClient(loadHydraConfig());

async function main() {
  const incident = JSON.parse(fs.readFileSync(path.join(here, "incident", "event-stream-2018.json"), "utf-8"));

  console.log(pc.dim("resetting graph cell ..."));
  await resetGraph(client);

  console.log(pc.dim("ingesting the event-stream/flatmap-stream incident graph ..."));
  await ingestIncident(client, {
    compromisedVersions: incident.compromisedVersions,
    dependencyEdges: incident.dependencyEdges,
    targetedConsumer: incident.targetedConsumer,
  });

  console.log();
  console.log(pc.bold("Query 1 — exposure (reachability only):"));
  const exposed = await queryExposed(client);
  for (const c of exposed) {
    console.log(`  ${pc.yellow("EXPOSED")}  ${c.consumerId}${c.isSynthetic ? pc.dim("  (illustrative)") : ""}`);
  }
  console.log(pc.dim(`  ${exposed.length} consumers have the malicious version somewhere in their resolved tree.`));

  console.log();
  console.log(pc.bold(`Query 2 — actually targeted (reachability + activation-key filter "${incident.targetedConsumer.packageDescription}"):`));
  const targeted = await queryActuallyTargeted(client, incident.targetedConsumer.packageDescription);
  for (const c of targeted) {
    console.log(`  ${pc.red(pc.bold("TARGETED"))}  ${c.consumerId}`);
  }
  console.log(pc.dim(`  ${targeted.length} of those ${exposed.length} exposed consumers match the real payload's actual activation condition.`));

  console.log();
  console.log(
    pc.bold(
      `This is the real event-stream/flatmap-stream/Copay incident (Sept-Nov 2018): ` +
        `${exposed.length} exposed by graph reachability alone, ${targeted.length} actually targeted once the ` +
        `real activation-key property filter is applied — exactly the distinction a package-presence scanner can't make.`,
    ),
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
