/**
 * Deterministic integer vertex/relationship ids for HydraDB.
 *
 * HydraDB stores vertices with an internal u64 id, and edge endpoints
 * must reference those ids — string ids (what the extraction layer
 * produces, e.g. "scripts/cli.js#run#7") are rejected with "field
 * callerId must be a non-negative integer". So every string id is mapped
 * to a stable integer at the ingest boundary, and the original string is
 * carried as a `key` property so property-predicate MATCHes and the path
 * procedures' sourceValues/targetValues selectors can still address
 * vertices by name.
 *
 * FNV-1a 64-bit, masked to 53 bits so ids survive JSON round-tripping
 * through the server's u64 parser and JS's Number without precision loss.
 * Identical seeds always produce identical ids, so repeated scans of the
 * same source tree (re-)MERGE onto the same vertices instead of
 * duplicating them.
 */

const FNV_OFFSET = 0xcbf29ce484222325n;
const FNV_PRIME = 0x100000001b3n;
const MASK_64 = 0xffffffffffffffffn;
const MASK_53 = 0x1fffffffffffffn;

export function vertexId(seed: string): number {
  let h = FNV_OFFSET;
  for (let i = 0; i < seed.length; i++) {
    h ^= BigInt(seed.charCodeAt(i));
    h = (h * FNV_PRIME) & MASK_64;
  }
  return Number(h & MASK_53);
}

/** Relationship ids share the same namespace and constraints as vertex ids. */
export function edgeId(srcSeed: string, dstSeed: string, type: string): number {
  return vertexId(`${srcSeed}::${dstSeed}::${type}`);
}