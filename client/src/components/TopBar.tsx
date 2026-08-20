import { useState } from "react";
import type { FormEvent } from "react";

interface Props {
  onScan: (repoPath: string, reset: boolean) => void;
  scanning: boolean;
  statusText: string;
  statusKind: "idle" | "busy" | "live" | "error";
  onHome: () => void;
}

export default function TopBar({ onScan, scanning, statusText, statusKind, onHome }: Props) {
  const [repoPath, setRepoPath] = useState("./demo/vulnerable-app");

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (repoPath.trim()) onScan(repoPath, false);
  };

  return (
    <form className="topbar" onSubmit={submit} aria-label="Scan a repository">
      <button type="button" className="home-link" onClick={onHome} aria-label="Back to home">
        <span className="brand" aria-hidden="true">
          <span className="sub">hydra</span>
          <span className="dash">/</span>triage
        </span>
      </button>
      <label className="visually-hidden" htmlFor="repo-path">
        Repository path
      </label>
      <input
        id="repo-path"
        className="repo-input mono"
        type="text"
        placeholder="/path/to/repo  (e.g. ./demo/vulnerable-app)"
        value={repoPath}
        onChange={(e) => setRepoPath(e.target.value)}
        disabled={scanning}
      />
      <button type="button" disabled={scanning} onClick={() => onScan(repoPath, true)}>
        Reset graph
      </button>
      <button type="submit" className="primary" disabled={scanning} aria-busy={scanning}>
        {scanning ? "Scanning…" : "Scan"}
      </button>
      <div className="status-pill mono" role="status" aria-live="polite">
        <span className={`status-dot ${scanning ? "busy" : statusKind}`} aria-hidden="true" />
        <span>{statusText}</span>
      </div>
    </form>
  );
}