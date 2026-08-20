import path from "node:path";

export const CONTENT_TYPES: Record<string, string> = {
  ".html": "text/html",
  ".js": "application/javascript",
  ".css": "text/css",
  ".svg": "image/svg+xml",
  ".json": "application/json",
  ".woff2": "font/woff2",
};

/**
 * Resolves requestPath against root and returns null if the result would
 * escape root. Uses path.relative + an explicit ".." / isAbsolute check —
 * NOT `resolved.startsWith(root)`, which is a well-known broken pattern:
 * it lets through any path that merely shares root as a string prefix
 * (e.g. root "/a/public" matches a resolved path of "/a/public-evil/x").
 * This exact bug shipped once already in this project's static file
 * server (see webServer.ts's history) — this function exists specifically
 * so it can be tested against real traversal payloads instead of trusted
 * on inspection a second time.
 */
export function safeResolve(root: string, requestPath: string): string | null {
  const decoded = decodeURIComponent(requestPath.split("?")[0] ?? "/");
  const resolved = path.resolve(root, "." + decoded); // leading "." keeps it relative to root
  const rel = path.relative(root, resolved);
  if (rel.startsWith("..") || path.isAbsolute(rel)) return null;
  return resolved;
}
