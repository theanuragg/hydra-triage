import type { ScanResponse } from "./types";

async function handleResponse(res: Response): Promise<ScanResponse> {
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error ?? `scan failed (${res.status})`);
  }
  return data as ScanResponse;
}

export async function scanRepo(repoPath: string, reset: boolean): Promise<ScanResponse> {
  const res = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repoPath, reset }),
  });
  return handleResponse(res);
}

export async function scanCode(filename: string, content: string): Promise<ScanResponse> {
  const res = await fetch("/api/scan-code", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ filename, content }),
  });
  return handleResponse(res);
}

export async function scanUploadZip(file: File): Promise<ScanResponse> {
  const res = await fetch("/api/scan-upload", {
    method: "POST",
    headers: { "Content-Type": "application/zip" },
    body: file,
  });
  return handleResponse(res);
}