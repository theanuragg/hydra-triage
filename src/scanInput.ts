/**
 * Input validation for code that arrives over the web (paste / zip upload)
 * and is written to a temp dir for scanning. Everything here is pure so the
 * selftests can exercise it without a running server.
 *
 * Safety model: the pipeline never executes user code (ts-morph is a
 * parser only), but bad paths can still escape the temp dir on write, and
 * zip bombs can exhaust disk. These helpers enforce:
 *  - pasted filenames are single bare basenames ([A-Za-z0-9._-]);
 *  - zip entries are relative, non-escaping, non-absolute paths and not
 *    symlinks;
 *  - upload sizes stay within caps that make a demo-scale machine happy.
 */

export const MAX_PASTED_CONTENT_BYTES = 2 * 1024 * 1024; // 2 MB
export const MAX_ZIP_BYTES = 50 * 1024 * 1024; // 50 MB upload
export const MAX_EXTRACTED_BYTES = 100 * 1024 * 1024; // 100 MB on disk
export const MAX_ZIP_ENTRIES = 1000;

/** Returns a bare, slash-free filename usable inside a temp dir, or the default. */
export function sanitizePastedFilename(name: string | null | undefined): string {
  if (!name) return "main.js";
  const base = name.replace(/\\/g, "/").split("/").filter(Boolean).pop() ?? "";
  if (/^[A-Za-z0-9._-]+$/.test(base)) return base;
  return "main.js";
}

export interface ZipEntryInfo {
  path: string;
  isSymlink: boolean;
}

/**
 * Validates `unzip -Z1`-style listing output (one entry path per line, or
 * entries passed as an array). Rejects absolute paths ("/etc/passwd"),
 * traversal ("../x"), Windows drive prefixes ("C:\\x"), and anything that
 * resolves outside the extraction root. Returns the safe entry list.
 */
export function validateZipEntries(entries: Array<ZipEntryInfo> | string[]): string[] {
  const infos: Array<ZipEntryInfo> = entries.map((e) =>
    typeof e === "string" ? { path: e, isSymlink: false } : e,
  );

  if (infos.length > MAX_ZIP_ENTRIES) {
    throw new Error(`zip has ${infos.length} entries — refusing more than ${MAX_ZIP_ENTRIES}`);
  }

  const out: string[] = [];
  for (const { path, isSymlink } of infos) {
    if (isSymlink) throw new Error(`zip entry is a symlink, refusing: ${path}`);
    const normalized = path.replace(/\\/g, "/").replace(/^\.\//, "");
    if (normalized === "" || normalized.endsWith("/")) continue; // directory entries
    if (/^[A-Za-z]:/.test(normalized)) throw new Error(`zip entry uses a drive prefix, refusing: ${path}`);
    if (normalized.startsWith("/")) throw new Error(`zip entry is absolute, refusing: ${path}`);
    const parts = normalized.split("/");
    if (parts.some((p) => p === ".." || p === ".")) {
      throw new Error(`zip entry escapes the extraction root, refusing: ${path}`);
    }
    out.push(normalized);
  }
  return out;
}

export function validateZipSize(bytes: number): void {
  if (bytes > MAX_ZIP_BYTES) {
    throw new Error(`zip is ${(bytes / 1024 / 1024).toFixed(1)} MB — the cap is ${Math.floor(MAX_ZIP_BYTES / 1024 / 1024)} MB`);
  }
}

export function validateExtractedSize(bytes: number): void {
  if (bytes > MAX_EXTRACTED_BYTES) {
    throw new Error("extracted contents exceed the size cap — refusing");
  }
}

export function validatePastedContent(bytes: number): void {
  if (bytes > MAX_PASTED_CONTENT_BYTES) {
    throw new Error(`pasted code is ${(bytes / 1024 / 1024).toFixed(1)} MB — the cap is 2 MB`);
  }
}