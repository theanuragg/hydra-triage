import http from "node:http";

/**
 * A tiny in-process stand-in for HydraDB's HTTP query API, used only to
 * validate that hydra-triage's own client/query code is internally
 * consistent — that batchWrite sends the API's `parameters` map shape,
 * that the ingestion writes land where the reachability reads expect them,
 * and that the reachable / present-unreachable / not-present
 * classification is correct end to end. It is NOT a Cypher engine; it
 * recognizes exactly the query shapes this project's own code generates
 * and nothing else — anything else (including the pre-rewrite inlined
 * UNWIND literals) fails loudly so protocol regressions can't pass
 * silently.
 *
 * The engine is schema-generic: every handler is driven by labels and
 * property predicates parsed out of the query text, so the incident
 * module's Version/Consumer/DEPENDS_ON/RESOLVED schema exercises the
 * exact same handler code as the Function/VulnerableSink schema (see
 * fakeIncidentDB.mjs, which re-exports this engine).
 */

// ---- OpenCypher literal parser (double-quoted strings, lists, maps, numbers, booleans) ----
function parseLiteral(text) {
  let i = 0;
  const err = (msg) => {
    throw new Error(`literal parse error at ${i}: ${msg}\n...${text.slice(Math.max(0, i - 20), i + 20)}...`);
  };
  const skipWs = () => {
    while (i < text.length && /\s/.test(text[i])) i++;
  };
  function parseValue() {
    skipWs();
    const c = text[i];
    if (c === '"') return parseString();
    if (c === "[") return parseList();
    if (c === "{") return parseMap();
    if (text.startsWith("true", i)) {
      i += 4;
      return true;
    }
    if (text.startsWith("false", i)) {
      i += 5;
      return false;
    }
    if (text.startsWith("null", i)) {
      i += 4;
      return null;
    }
    const start = i;
    while (i < text.length && /[-0-9.eE]/.test(text[i])) i++;
    if (i === start) err(`unexpected character '${c}'`);
    return Number(text.slice(start, i));
  }
  function parseString() {
    i++;
    let s = "";
    while (text[i] !== '"') {
      if (text[i] === "\\") {
        i++;
        const esc = text[i];
        s += { n: "\n", r: "\r", t: "\t", '"': '"', "\\": "\\" }[esc] ?? esc;
        i++;
      } else {
        s += text[i];
        i++;
      }
    }
    i++;
    return s;
  }
  function parseList() {
    i++;
    const arr = [];
    skipWs();
    if (text[i] === "]") {
      i++;
      return arr;
    }
    while (true) {
      arr.push(parseValue());
      skipWs();
      if (text[i] === ",") {
        i++;
        continue;
      }
      if (text[i] === "]") {
        i++;
        break;
      }
      err("expected , or ] in list");
    }
    return arr;
  }
  function parseMap() {
    i++;
    const obj = {};
    skipWs();
    if (text[i] === "}") {
      i++;
      return obj;
    }
    while (true) {
      skipWs();
      let key;
      if (text[i] === '"') key = parseString();
      else {
        const start = i;
        while (/[A-Za-z0-9_]/.test(text[i])) i++;
        key = text.slice(start, i);
      }
      skipWs();
      if (text[i] !== ":") err("expected ':' after map key");
      i++;
      const val = parseValue();
      obj[key] = val;
      skipWs();
      if (text[i] === ",") {
        i++;
        continue;
      }
      if (text[i] === "}") {
        i++;
        break;
      }
      err("expected , or } in map");
    }
    return obj;
  }
  const result = parseValue();
  if (i < text.length) err(`trailing input: ${text.slice(i)}`);
  return result;
}

/** Mirrors the real backend's cell wrapping; types are informational. */
function wrapCell(bytes) {
  return { type: "string", value: bytes };
}

// ---- in-memory graph store ----
export class FakeGraph {
  constructor() {
    this.vertices = new Map(); // integer id -> { id, label, props }
    this.edges = new Map(); // relId -> { id, type, src, dst, props }
    this.adj = new Map(); // type -> Map(src -> Set<dst>)
  }

  reset() {
    this.vertices.clear();
    this.edges.clear();
    this.adj.clear();
  }

  upsertVertex(id, label, props) {
    const existing = this.vertices.get(id);
    this.vertices.set(id, { id, label, props: { ...(existing?.props ?? {}), ...props } });
  }

  upsertEdge(relId, type, src, dst, props) {
    // Enforce real MATCH semantics: the edge only merges when both
    // endpoints were actually found. A permissive fake that links
    // dangling ids masks exactly the class of bug this module shipped
    // with once already.
    if (!this.vertices.has(src) || !this.vertices.has(dst)) return;
    const existing = this.edges.get(relId);
    this.edges.set(relId, { id: relId, type, src, dst, props: { ...(existing?.props ?? {}), ...props } });
    if (!this.adj.has(type)) this.adj.set(type, new Map());
    if (!this.adj.get(type).has(src)) this.adj.get(type).set(src, new Set());
    this.adj.get(type).get(src).add(dst);
  }

  /** DETACH DELETE, label-scoped (matches src/ingest/write.ts resetGraph). */
  dropLabel(label) {
    const doomed = new Set();
    for (const [id, v] of this.vertices) if (v.label === label) doomed.add(id);
    for (const e of this.edges.keys()) {
      const edge = this.edges.get(e);
      if (doomed.has(edge.src) || doomed.has(edge.dst)) this.edges.delete(e);
    }
    this.adj = new Map();
    for (const e of this.edges.values()) {
      if (!this.adj.has(e.type)) this.adj.set(e.type, new Map());
      if (!this.adj.get(e.type).has(e.src)) this.adj.get(e.type).set(e.src, new Set());
      this.adj.get(e.type).get(e.src).add(e.dst);
    }
    for (const id of doomed) this.vertices.delete(id);
  }

  /**
   * Multicast shortest-path over the edges whose type is in
   * config.relTypes (outgoing), from every vertex matching
   * sourceLabel/sourceProperty/sourceValues to any vertex matching
   * targetLabel/targetProperty/targetValues, up to config.maxLen edges.
   * Returns one node-id chain per source that reaches a target, source
   * first, target last (mirrors MSpaths path YIELD output).
   */
  mspaths(config) {
    const matchVertices = (label, property, values) =>
      [...this.vertices.values()].filter(
        (v) => v.label === label && values.includes(v.props[property]),
      );
    const sources = matchVertices(config.sourceLabel, config.sourceProperty, config.sourceValues);
    const targets = new Set(matchVertices(config.targetLabel, config.targetProperty, config.targetValues).map((v) => v.id));

    const out = [];
    for (const s of sources) {
      const parent = new Map([[s.id, null]]);
      let frontier = [s.id];
      let found = null;
      for (let hop = 0; hop <= config.maxLen && found === null; hop++) {
        for (const id of frontier) {
          if (targets.has(id)) {
            found = id;
            break;
          }
        }
        if (found !== null) break;
        const next = [];
        for (const id of frontier) {
          for (const type of config.relTypes) {
            for (const dst of this.adj.get(type)?.get(id) ?? []) {
              if (!parent.has(dst)) {
                parent.set(dst, id);
                next.push(dst);
              }
            }
          }
        }
        frontier = next;
        if (frontier.length === 0) break;
      }
      if (found !== null) {
        const chain = [];
        for (let cur = found; cur !== null; cur = parent.get(cur)) chain.push(cur);
        out.push(chain.reverse());
      }
    }
    return out;
  }
}

function nodeValue(v) {
  const properties = {};
  for (const [k, val] of Object.entries(v.props)) {
    if (k === "id") continue; // id is a top-level field, not a property (mirrors the real backend)
    if (typeof val === "boolean") properties[k] = { Bool: val };
    else if (typeof val === "number") properties[k] = { Integer: val };
    else properties[k] = { String: String(val) };
  }
  return { id: v.id, labels: [v.label], properties };
}

function handleQuery(store, body) {
  const query = body.query;
  const q = query.trim();

  const detach = q.match(/^MATCH \((\w):(\w+)\) DETACH DELETE \1$/);
  if (detach) {
    store.dropLabel(detach[2]);
    return { columns: [], rows: [] };
  }

  if (q.startsWith("UNWIND $rows AS row")) {
    if (!body.parameters || !Array.isArray(body.parameters.rows)) {
      throw new Error("expected body.parameters.rows (inlined UNWIND literals are not accepted)");
    }
    const rows = body.parameters.rows;

    const vertex = q.match(/MERGE \((\w) \{id: row\.id\}\)\s*SET \w:(\w+)([\s\S]*)$/);
    if (vertex) {
      const [, , label, rest] = vertex;
      const fields = [];
      for (const m of rest.matchAll(/(\w+)\.(\w+) = row\.(\w+)/g)) fields.push({ prop: m[2], from: m[3] });
      for (const row of rows) {
        const props = {};
        for (const f of fields) props[f.prop] = row[f.from];
        store.upsertVertex(row.id, label, props);
      }
      return { columns: [], rows: [] };
    }

    const edge = q.match(/MERGE \((\w)\)-\[(\w):(\w+) \{id: row\.relId\}\]->\((\w)\)([\s\S]*)$/);
    if (edge) {
      const [, , , type, , rest] = edge;
      // e.g. "SET r.range = row.range" — relationship SET after MERGE
      const props = {};
      for (const m of rest.matchAll(/\.(\w+) = row\.(\w+)/g)) props[m[1]] = m[2];
      for (const row of rows) {
        const relProps = {};
        for (const [prop, from] of Object.entries(props)) relProps[prop] = row[from];
        store.upsertEdge(row.relId, type, row.src, row.dst, relProps);
      }
      return { columns: [], rows: [] };
    }

    throw new Error("unrecognized UNWIND template:\n" + query);
  }

  const matcher = q.match(/^MATCH \((\w):(\w+)( \{([^}]*)\})?\) RETURN ([\s\S]+)$/);
  if (matcher) {
    const [, binding, label, , predicateText, returnClause] = matcher;
    const predicate = new Map();
    if (predicateText) {
      const pm = predicateText.match(/(\w+):\s*([^,]+)\s*$/);
      if (!pm) throw new Error("unsupported MATCH predicate:\n" + query);
      predicate.set(pm[1], parseLiteral(pm[2].trim()));
    }
    const selectors = [...returnClause.matchAll(new RegExp(`${binding}\\.(\\w+) AS (\\w+)`, "g"))];
    if (selectors.length === 0) throw new Error("unsupported RETURN clause:\n" + query);

    const out = [];
    for (const v of store.vertices.values()) {
      if (v.label !== label) continue;
      let ok = true;
      for (const [k, want] of predicate) if (v.props[k] !== want) {
        ok = false;
        break;
      }
      if (!ok) continue;
      out.push(
        selectors.map(([, prop, as]) => {
          if (prop === "id") return { type: "vertex_id", value: v.props.id };
          return wrapCell(v.props[prop]);
        }),
      );
    }
    return { columns: selectors.map((m) => m[3]), rows: out };
  }

  const msp = q.match(/MSpaths\((\{[\s\S]*?\})\) YIELD/);
  if (msp) {
    const config = parseLiteral(msp[1]);
    const chains = store.mspaths(config).slice(0, config.resultLimit ?? 100);
    const rows = chains.map((ids) => [
      {
        type: "path",
        value: {
          nodes: ids.map((id) => nodeValue(store.vertices.get(id))),
          relationships: [],
        },
      },
    ]);
    return { columns: ["path"], rows };
  }

  throw new Error("unrecognized query shape:\n" + query);
}

export function startFakeHydraDB(graph, { port = 0 } = {}) {
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      try {
        const parsed = JSON.parse(body);
        const result = handleQuery(graph, parsed);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(result));
      } catch (e) {
        res.writeHead(500);
        res.end(String(e.stack || e));
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(port, "127.0.0.1", () => {
      const addr = server.address();
      resolve({ server, baseUrl: `http://127.0.0.1:${addr.port}` });
    });
  });
}