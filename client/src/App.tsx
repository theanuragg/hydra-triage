import { useState } from "react";
import TopBar from "./components/TopBar";
import StatRail from "./components/StatRail";
import GraphView from "./components/GraphView";
import IssuesTable from "./components/IssuesTable";
import Landing from "./components/Landing";
import { scanRepo, scanCode, scanUploadZip } from "./api";
import type { Finding, ScanStats, ScanGraph, ScanResponse } from "./types";

type Tab = "graph" | "issues";
type StatusKind = "idle" | "busy" | "live" | "error";

function formatDuration(ms: number): string {
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${Math.round(ms)}ms`;
}

function ScanSkeleton() {
  return (
    <>
      <div className="skeleton skeleton-lane" aria-hidden="true" />
      <div className="skeleton skeleton-lane" aria-hidden="true" />
      <div className="skeleton skeleton-row" aria-hidden="true" />
      <div className="skeleton skeleton-row" aria-hidden="true" />
      <div className="skeleton skeleton-row" aria-hidden="true" />
      <div className="skeleton skeleton-row" aria-hidden="true" />
    </>
  );
}

export default function App() {
  const [view, setView] = useState<"landing" | "app">("landing");
  const [scanning, setScanning] = useState(false);
  const [statusText, setStatusText] = useState("idle — enter a repo path or run the demo");
  const [statusKind, setStatusKind] = useState<StatusKind>("idle");
  const [stats, setStats] = useState<ScanStats | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [graph, setGraph] = useState<ScanGraph | null>(null);
  const [errorText, setErrorText] = useState<string | null>(null);
  const [lastRepo, setLastRepo] = useState<string | null>(null);
  const [durationMs, setDurationMs] = useState<number | null>(null);
  const [tab, setTab] = useState<Tab>("graph");

  const runScan = async (scanPromise: Promise<ScanResponse>, label: string) => {
    setView("app");
    const started = performance.now();
    setScanning(true);
    setStatusText("scanning…");
    setStatusKind("busy");
    setErrorText(null);
    setDurationMs(null);
    try {
      const data = await scanPromise;
      const elapsed = performance.now() - started;
      setStats(data.stats);
      setFindings(data.results);
      setGraph(data.graph);
      setDurationMs(elapsed);
      setLastRepo(label);
      if (data.stats.entryPoints === 0) {
        setStatusText("done — 0 entry points found");
        setStatusKind("error");
        setErrorText(`No entry points found. Export an HTTP handler or CLI command so the call graph has somewhere to start.`);
      } else {
        setStatusText(`scan complete · ${formatDuration(elapsed)}`);
        setStatusKind("live");
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setStatusText("scan failed");
      setStatusKind("error");
      setErrorText(message);
    } finally {
      setScanning(false);
    }
  };

  const handleScan = (repoPath: string, reset: boolean) => {
    if (!repoPath.trim()) return;
    runScan(scanRepo(repoPath.trim(), reset), repoPath.trim());
  };

  const handleScanCode = (filename: string, content: string) => {
    runScan(scanCode(filename, content), `pasted: ${filename}`);
  };

  const handleScanZip = (file: File) => {
    runScan(scanUploadZip(file), file.name);
  };

  const goHome = () => {
    setView("landing");
  };

  if (view === "landing") {
    return (
      <Landing
        onScan={(p) => handleScan(p, false)}
        onScanCode={handleScanCode}
        onScanZip={handleScanZip}
      />
    );
  }

  return (
    <>
      <TopBar
        onScan={handleScan}
        scanning={scanning}
        statusText={statusText}
        statusKind={statusKind}
        onHome={goHome}
      />
      {scanning && <div className="loading-line" aria-hidden="true" />}

      {errorText && !scanning && (
        <div className="error-banner" role="alert">
          <span className="error-copy">{errorText}</span>
          <button type="button" onClick={() => setErrorText(null)}>
            Dismiss
          </button>
        </div>
      )}

      <div className="tabbar">
        <button className={`tab${tab === "graph" ? " active" : ""}`} onClick={() => setTab("graph")}>
          Graph
        </button>
        <button className={`tab${tab === "issues" ? " active" : ""}`} onClick={() => setTab("issues")}>
          All issues
        </button>
      </div>

      <div className="layout">
        <StatRail stats={stats} findings={findings} />
        <div className="main">
          {scanning ? (
            <ScanSkeleton />
          ) : (
            <>
              {tab === "graph" ? (
                <GraphView graph={graph} findings={findings} />
              ) : (
                <IssuesTable findings={findings} />
              )}
              {!lastRepo && (
                <div className="empty-state" style={{ marginTop: "1rem" }}>
                  <div>Type a repository path above and press Enter, or run the demo.</div>
                  <div className="empty-action">{`try: ./demo/vulnerable-app — a deliberately vulnerable demo app`}</div>
                  <button
                    className="primary"
                    onClick={() => handleScan("./demo/vulnerable-app", false)}
                  >
                    Scan demo app
                  </button>
                </div>
              )}
            </>
          )}
        </div>
      </div>

      <footer>
        <div>
          hydra-triage — reachability-based CVE triage over a HydraDB call graph · Hack Hydra 2026
        </div>
        <div className="footer-note">
          Reachability is computed by HydraDB as a bounded <code>MSpaths</code> search of up to 8 hops from
          an entry point to a known vulnerable export. A CVE beyond that bound is reported as{" "}
          <code>no path</code> — not proven safe. This is a triage signal, not a formal proof; treat
          solid as exploitable, outlined as needs-review, dashed as not-called.
        </div>
      </footer>
    </>
  );
}