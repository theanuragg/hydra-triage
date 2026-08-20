import { safeResolve } from "./build/safeStatic.js";
import path from "node:path";

const root = "/home/claude/hydra-triage/client/dist";

let failures = 0;
const check = (label, cond) => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${label}`);
  if (!cond) failures++;
};

// ---- legitimate requests should resolve inside root ----
check("plain file resolves inside root", safeResolve(root, "/index.html") === path.join(root, "index.html"));
check("nested asset path resolves inside root", safeResolve(root, "/assets/index-a1b2c3.js") === path.join(root, "assets", "index-a1b2c3.js"));
check("root itself (\"/\") resolves to root/index.html when caller passes that", safeResolve(root, "/index.html") !== null);

// ---- classic traversal payloads must be rejected ----
check("../../../etc/passwd is rejected", safeResolve(root, "/../../../etc/passwd") === null);
check("deeply nested ../ escape is rejected", safeResolve(root, "/../../../../../../etc/passwd") === null);
check("encoded ../ (%2e%2e) is rejected", safeResolve(root, "/%2e%2e/%2e%2e/etc/passwd") === null);
check("mixed traversal with valid-looking prefix is rejected", safeResolve(root, "/assets/../../../../etc/passwd") === null);

// ---- the exact bug class that shipped once already: sibling dir sharing a string prefix ----
// A naive `resolved.startsWith(root)` check would have let this through,
// because "/home/claude/hydra-triage/client/dist-evil/secret.txt" DOES
// start with the string "/home/claude/hydra-triage/client/dist". This is
// the specific regression this test exists to catch.
{
  const evilRoot = root + "-evil";
  const attackPath = "/../dist-evil/secret.txt";
  const resolved = safeResolve(root, attackPath);
  check(
    "path resolving into a sibling dir sharing root as a string prefix is rejected (the original bug class)",
    resolved === null || !resolved.startsWith(evilRoot),
  );
}

console.log();
if (failures > 0) {
  console.error(`${failures} FAILURE(S)`);
  process.exit(1);
}
console.log("ALL PATH-SAFETY CHECKS PASSED");
