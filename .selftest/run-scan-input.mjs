import assert from "node:assert/strict";
import {
  sanitizePastedFilename,
  validateZipEntries,
  validateZipSize,
  validateExtractedSize,
  validatePastedContent,
  MAX_PASTED_CONTENT_BYTES,
  MAX_ZIP_BYTES,
  MAX_EXTRACTED_BYTES,
  MAX_ZIP_ENTRIES,
} from "./build/scanInput.js";

let failures = 0;
function check(cond, msg) {
  if (cond) {
    console.log(`PASS  ${msg}`);
  } else {
    console.error(`FAIL  ${msg}`);
    failures++;
  }
}
function assertThrows(fn, pattern, msg) {
  try {
    fn();
    console.error(`FAIL  ${msg} — expected error but none thrown`);
    failures++;
  } catch (e) {
    const ok = pattern.test(String(e.message));
    if (ok) {
      console.log(`PASS  ${msg}`);
    } else {
      console.error(`FAIL  ${msg} — error "${e.message}" does not match ${pattern}`);
      failures++;
    }
  }
}

// --- sanitizePastedFilename ---
check(sanitizePastedFilename(null) === "main.js", "null -> main.js");
check(sanitizePastedFilename(undefined) === "main.js", "undefined -> main.js");
check(sanitizePastedFilename("") === "main.js", "empty -> main.js");
check(sanitizePastedFilename("app.js") === "app.js", "bare filename preserved");
check(sanitizePastedFilename("src/index.js") === "index.js", "strips directory prefix");
check(sanitizePastedFilename("C:\\Users\\x\\foo.ts") === "foo.ts", "strips windows path");
// Traversal is stripped — only the basename is kept, which is safe
check(sanitizePastedFilename("../../../etc/passwd") === "passwd", "traversal stripped to basename");
check(sanitizePastedFilename("hello world.js") === "main.js", "rejects spaces -> main.js");
check(sanitizePastedFilename("a@b.js") === "main.js", "rejects @ -> main.js");
check(sanitizePastedFilename("my-app_v2.0.ts") === "my-app_v2.0.ts", "allows hyphens/underscores/dots");

// --- validateZipEntries ---
assert.deepStrictEqual(validateZipEntries(["src/index.js", "lib/util.ts"]), ["src/index.js", "lib/util.ts"], "normal entries pass through");
assert.deepStrictEqual(validateZipEntries([]), [], "empty list returns empty array");
assertThrows(() => validateZipEntries(["/etc/passwd"]), /absolute/, "absolute path rejected");
assertThrows(() => validateZipEntries(["../evil.js"]), /escapes/, "traversal rejected");
assertThrows(() => validateZipEntries(["C:\\Windows\\x"]), /drive prefix/, "drive prefix rejected");
assertThrows(() => validateZipEntries([{ path: "a", isSymlink: true }]), /symlink/, "symlink rejected");
assert.deepStrictEqual(validateZipEntries(["dir/"]), [], "directory entries filtered out");
assert.deepStrictEqual(validateZipEntries(["./foo.js"]), ["foo.js"], "./ prefix stripped");

// exceeds max entries
const tooMany = Array.from({ length: MAX_ZIP_ENTRIES + 1 }, (_, i) => `f${i}.js`);
assertThrows(() => validateZipEntries(tooMany), /refusing more than/, "too many entries rejected");

// --- size validators ---
assertThrows(() => validateZipSize(MAX_ZIP_BYTES + 1), /cap/, "zip too big rejected");
validateZipSize(MAX_ZIP_BYTES); // should not throw
assertThrows(() => validateExtractedSize(MAX_EXTRACTED_BYTES + 1), /exceed/, "extracted too big rejected");
validateExtractedSize(MAX_EXTRACTED_BYTES); // should not throw
assertThrows(() => validatePastedContent(MAX_PASTED_CONTENT_BYTES + 1), /cap/, "pasted content too big rejected");
validatePastedContent(MAX_PASTED_CONTENT_BYTES); // should not throw

if (failures > 0) {
  console.error(`\n${failures} FAILURE(S)`);
  process.exit(1);
}
console.log("\nALL scanInput CASES PASSED");