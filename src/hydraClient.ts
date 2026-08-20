/**
 * Minimal client for HydraDB's HTTPS query API (POST /v1/graphs/{graph}/query).
 * See https://github.com/hydra-db/hydradb#querying — we deliberately don't
 * pull in the Bolt/Neo4j driver for this tool since the JSON API is enough
 * for batched writes and the path-procedure reads we need.
 *
 * Real API shape (verified against a running graph node):
 *  - the request body is {cell_id, query, consistency, parameters?}; bound
 *    parameters go in the `parameters` map (e.g. {"rows": [...]} feeding
 *    `UNWIND $rows AS row`), not inlined in the query text. An earlier
 *    draft inlined rows as a Cypher list-of-maps literal; libcypher-parser
 *    rejects that form with "Invalid input ... expected STARTS WITH".
 *  - responses are positional: a `columns` array plus `rows` of
 *    {type, value} cells in column order — NOT keyed by column name.
 */

export interface HydraClientOptions {
  baseUrl: string; // e.g. http://127.0.0.1:8443
  token: string;
  namespace: string; // X-Graph-Namespace
  graph: string; // path segment, e.g. "default"
  cellId: string; // e.g. "cell-0"
  /** Request timeout in ms. Without this, a hung/unreachable HydraDB node
   *  hangs the caller indefinitely with no error — a real reliability gap
   *  an earlier version of this file shipped with. Default 30s. */
  timeoutMs?: number;
}

export interface HydraRowValue {
  type: string;
  value: unknown;
}

export interface HydraQueryResult {
  columns: string[];
  rows: Array<Array<HydraRowValue>>;
}

/** Path-procedure results carry vertex properties value-wrapped per type:
 *  {"String": "..."} / {"Bool": true} / {"Integer": 7}. Unwraps to the
 *  plain JS value, or null when the property is absent. */
export function unwrapHydraValue(v: unknown): unknown {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return v;
  const wrapped = v as Record<string, unknown>;
  if ("String" in wrapped) return wrapped.String;
  if ("Bool" in wrapped) return wrapped.Bool;
  if ("Integer" in wrapped) return wrapped.Integer;
  if ("Float" in wrapped) return wrapped.Float;
  return wrapped;
}

export class HydraClient {
  private opts: HydraClientOptions;

  constructor(opts: HydraClientOptions) {
    this.opts = opts;
  }

  async query(
    cypher: string,
    consistency: "causal" | "strong" = "causal",
    parameters?: Record<string, unknown>,
  ): Promise<HydraQueryResult> {
    const url = `${this.opts.baseUrl}/v1/graphs/${this.opts.graph}/query`;
    const timeoutMs = this.opts.timeoutMs ?? 30_000;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    let res: Response;
    try {
      res = await fetch(url, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.opts.token}`,
          "X-Graph-Namespace": this.opts.namespace,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          cell_id: this.opts.cellId,
          query: cypher,
          consistency,
          ...(parameters !== undefined ? { parameters } : {}),
        }),
        signal: controller.signal,
      });
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") {
        throw new Error(`HydraDB query timed out after ${timeoutMs}ms (is it running at ${this.opts.baseUrl}?)\nQuery: ${cypher}`);
      }
      throw new Error(`HydraDB request failed: ${err instanceof Error ? err.message : String(err)}\nQuery: ${cypher}`);
    } finally {
      clearTimeout(timer);
    }

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`HydraDB query failed (${res.status}): ${text}\nQuery: ${cypher}`);
    }

    return (await res.json()) as HydraQueryResult;
  }

  /** Batched write helper: UNWIND over a Cypher template, driven by real
   *  bound parameters ($rows) rather than an inlined literal. Each chunk
   *  of up to batchSize rows is one round trip. */
  async batchWrite(cypherTemplate: string, rows: Array<object>, batchSize = 500): Promise<void> {
    for (let i = 0; i < rows.length; i += batchSize) {
      const chunk = rows.slice(i, i + batchSize);
      if (chunk.length === 0) continue;
      await this.query(`UNWIND $rows AS row\n${cypherTemplate}`, "causal", { rows: chunk });
    }
  }
}