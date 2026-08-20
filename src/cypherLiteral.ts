/**
 * Renders JS strings as OpenCypher string literals for inlining into a
 * query string. The only remaining use is quoting `key` values inside the
 * path procedures' sourceValues/targetValues config maps, where the
 * libcypher-parser-backed config parser wants literal text, not bindings.
 *
 * This once shipped cypherValue/cypherMap/cypherList for inlining whole
 * row arrays into UNWIND ... AS row writes. Real HydraDB's bindings were
 * verified against a live graph node and the API only accepts row data as
 * the `parameters` body map — inlined list literals fail to parse, so
 * batched writes now go through hydraClient.batchWrite with real $rows
 * bindings and those renderers are gone; inlining was also a
 * Cypher-injection risk if row data ever came from anywhere less trusted
 * than "our own AST extraction," which is a stated assumption of this
 * tool, not a general-purpose ingestion path.
 */

export function cypherString(s: string): string {
  const escaped = s
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r")
    .replace(/\t/g, "\\t");
  return `"${escaped}"`;
}