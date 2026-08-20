import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { loadHydraConfig } from "./config.js";
import { safeResolve, CONTENT_TYPES } from "./safeStatic.js";
import { extractCallGraph } from "./extract/callgraph.js";
import { HydraClient } from "./hydraClient.js";
import { ingestCallGraph, ingestVulnDb, resetGraph, sinkEdgePairs } from "./ingest/write.js";
import { checkReachability } from "./query/reachability.js";
import {
  sanitizePastedFilename,
  validateZipEntries,
  validateZipSize,
  validateExtractedSize,
  validatePastedContent,
} from "./scanInput.js";
import type { VulnerableFunctionEntry, CallGraph } from "./types.js";

/**
 * Thin HTTP wrapper around the exact same pipeline cli.ts runs
 * (extractCallGraph -> ingestCallGraph -> ingestVulnDb -> checkReachability).
 * No new logic lives here — this file's only job is JSON in, JSON out, so
 * the browser client and the CLI stay provably in sync with each other.
 *
 * Three input modes, one pipeline (`runScanPipeline`):
 *  - POST /api/scan        — {repoPath, reset?}: scan a directory on disk
 *  - POST /api/scan-code   — {filename, content}: scan code pasted into the
 *                            web page (written to a throwaway temp dir)
 *  - POST /api/scan-upload — raw .zip bytes: scan an uploaded repo
 *                            (extracted to a throwaway temp dir)
 * The code modes never touch real files on the server beyond os.tmpdir(),
 * and nothing here ever executes user code — ts-morph is a parser only.
 */

const here = path.dirname(fileURLToPath(import.meta.url));

const HYDRA_CONFIG = loadHydraConfig();

const vulndbPath = path.join(here, "vulndb", "vulnerable-functions.json");

/**
 * The shared scan: extract the call graph, push it into HydraDB, ask for
 * reachability, and assemble the payload the UI renders (stats + verdicts
 * + graph topology). `repoRoot` is a real directory on disk — for the
 * paste/upload modes that's a throwaway temp dir.
 */
async function runScanPipeline(repoRoot: string): Promise<{
  stats: { functions: number; localCalls: number; externalCalls: number; entryPoints: number };
  results: Awaited<ReturnType<typeof checkReachability>>;
  graph: {
    functions: Array<{ id: string; name: string; modulePath: string; startLine: number; isEntryPoint: boolean; entryKind: string | null }>;
    calls: Array<{ callerId: string; calleeId: string }>;
    sinks: Array<{ key: string; cve: string; packageName: string; vulnerableExport: string; severity: string; present: boolean }>;
    sinkCalls: Array<{ callerId: string; sinkKey: string }>;
  };
}> {
  const client = new HydraClient(HYDRA_CONFIG);
  const graph: CallGraph = extractCallGraph(path.resolve(repoRoot));
  const entryPointCount = graph.functions.filter((f) => f.isEntryPoint).length;

  await ingestCallGraph(client, graph);
  const vulndb: VulnerableFunctionEntry[] = JSON.parse(fs.readFileSync(vulndbPath, "utf-8")).entries;
  const presentSinkIds = await ingestVulnDb(client, graph, vulndb);
  const results = await checkReachability(client, vulndb, presentSinkIds);

  const sinkKeyOf = (e: VulnerableFunctionEntry) => `${e.packageName}::${e.vulnerableExport}::${e.cve}`;

  return {
    stats: {
      functions: graph.functions.length,
      localCalls: graph.edges.length,
      externalCalls: graph.externalCalls.length,
      entryPoints: entryPointCount,
    },
    results,
    graph: {
      functions: graph.functions.map((f) => ({
        id: f.id,
        name: f.name,
        modulePath: f.modulePath,
        startLine: f.startLine,
        isEntryPoint: f.isEntryPoint,
        entryKind: f.entryKind ?? null,
      })),
      calls: graph.edges.map((e) => ({ callerId: e.callerId, calleeId: e.calleeId })),
      sinks: vulndb.map((e) => {
        const key = sinkKeyOf(e);
        return {
          key,
          cve: e.cve,
          packageName: e.packageName,
          vulnerableExport: e.vulnerableExport,
          severity: e.severity,
          present: presentSinkIds.has(key),
        };
      }),
      sinkCalls: sinkEdgePairs(graph, vulndb),
    },
  };
}

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text) });
  res.end(text);
}

async function readBody(req: http.IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks);
}

function withTempDir<T>(prefix: string, fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `${prefix}-`));
  return fn(dir).finally(() => fs.rmSync(dir, { recursive: true, force: true }));
}

async function handleScan(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  try {
    const body = JSON.parse((await readBody(req)).toString("utf-8")) as { repoPath?: string; reset?: boolean };
    if (!body.repoPath) {
      sendJson(res, 400, { error: "repoPath is required" });
      return;
    }

    const client = new HydraClient(HYDRA_CONFIG);
    if (body.reset) await resetGraph(client);
    const payload = await runScanPipeline(body.repoPath);
    sendJson(res, 200, payload);
  } catch (err) {
    sendJson(res, 500, { error: err instanceof Error ? err.message : String(err) });
  }
}

async function handleScanCode(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  try {
    const body = JSON.parse((await readBody(req)).toString("utf-8")) as { filename?: string; content?: string };
    if (typeof body.content !== "string" || !body.content.trim()) {
      sendJson(res, 400, { error: "content is required — paste at least one JS/TS file" });
      return;
    }
    const pastedContent = body.content;
    validatePastedContent(Buffer.byteLength(pastedContent, "utf-8"));
    const filename = sanitizePastedFilename(body.filename);

    const payload = await withTempDir("hydra-triage-code", async (dir) => {
      fs.writeFileSync(path.join(dir, filename), pastedContent, "utf-8");
      const client = new HydraClient(HYDRA_CONFIG);
      await resetGraph(client);
      return runScanPipeline(dir);
    });
    sendJson(res, 200, payload);
  } catch (err) {
    sendJson(res, 500, { error: err instanceof Error ? err.message : String(err) });
  }
}

async function handleScanUpload(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  try {
    const body = await readBody(req);
    validateZipSize(body.length);

    const payload = await withTempDir("hydra-triage-upload", async (dir) => {
      const zipPath = path.join(dir, "repo.zip");
      fs.writeFileSync(zipPath, body);

      const listing = execFileSync("unzip", ["-Z1", zipPath], { encoding: "utf-8" });
      const entries = validateZipEntries(listing.split("\n").filter((l) => l.trim() !== ""));
      if (entries.length === 0) {
        throw new Error("zip contains no files");
      }

      const outDir = path.join(dir, "repo");
      fs.mkdirSync(outDir);
      execFileSync("unzip", ["-q", "-o", zipPath, "-d", outDir]);

      // Post-extraction safety: reject symlinks (a zip can't write outside
      // its extraction root on its own, but a symlink inside the tree could
      // point somewhere worse later) and enforce the extracted-size cap.
      let extractedBytes = 0;
      const walk = (d: string, depth: number): void => {
        if (depth > 32) throw new Error("zip nests deeper than 32 directories");
        for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
          const full = path.join(d, entry.name);
          if (entry.isSymbolicLink()) throw new Error(`zip contains a symlink, refusing: ${full}`);
          if (entry.isDirectory()) walk(full, depth + 1);
          else if (entry.isFile()) {
            extractedBytes += fs.statSync(full).size;
            if (extractedBytes > 100 * 1024 * 1024) throw new Error("extracted contents exceed the size cap — refusing");
          }
        }
      };
      walk(outDir, 0);
      validateExtractedSize(extractedBytes);

      const client = new HydraClient(HYDRA_CONFIG);
      await resetGraph(client);
      return runScanPipeline(outDir);
    });
    sendJson(res, 200, payload);
  } catch (err) {
    sendJson(res, 500, { error: err instanceof Error ? err.message : String(err) });
  }
}

const clientDistDir = path.join(here, "..", "client", "dist");

/**
 * Vite's build emits hashed asset filenames (assets/index-a1b2c3.js), so
 * a single hardcoded path won't do — see safeStatic.ts for the actual
 * containment check and why it's not a naive startsWith prefix test.
 */
function serveClient(req: http.IncomingMessage, res: http.ServerResponse): void {
  const urlPath = req.url === "/" ? "/index.html" : (req.url ?? "/index.html");
  const filePath = safeResolve(clientDistDir, urlPath);
  if (!filePath) {
    res.writeHead(403);
    res.end("forbidden");
    return;
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      // Fall back to index.html for any unmatched GET (SPA-style routing,
      // and the common case of a missing asset) rather than a bare 404 —
      // but if index.html itself is missing, the client was never built.
      fs.readFile(path.join(clientDistDir, "index.html"), (err2: NodeJS.ErrnoException | null, data2: Buffer) => {
        if (err2) {
          res.writeHead(500);
          res.end(
            `client build not found at ${clientDistDir}. Run "cd client && npm install && npm run build" first.`,
          );
          return;
        }
        res.writeHead(200, { "Content-Type": "text/html" });
        res.end(data2);
      });
      return;
    }
    const contentType = CONTENT_TYPES[path.extname(filePath)] ?? "application/octet-stream";
    res.writeHead(200, { "Content-Type": contentType });
    res.end(data);
  });
}

const server = http.createServer((req, res) => {
  if (req.method === "POST" && req.url === "/api/scan") {
    void handleScan(req, res);
    return;
  }
  if (req.method === "POST" && req.url === "/api/scan-code") {
    void handleScanCode(req, res);
    return;
  }
  if (req.method === "POST" && req.url === "/api/scan-upload") {
    void handleScanUpload(req, res);
    return;
  }
  if (req.method === "GET") {
    serveClient(req, res);
    return;
  }
  res.writeHead(405);
  res.end("method not allowed");
});

const PORT = Number(process.env.PORT ?? 5173);
server.listen(PORT, () => {
  console.log(`hydra-triage web client: http://127.0.0.1:${PORT}`);
  console.log(`(for local development with hot reload instead, run "cd client && npm run dev" on :5174 — it proxies /api here)`);
  console.log(`talking to HydraDB at: ${HYDRA_CONFIG.baseUrl}`);
});