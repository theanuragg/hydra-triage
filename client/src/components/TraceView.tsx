import { useEffect, useState } from "react";
import type { Finding } from "../types";

interface ChainNode {
  fn: string;
  file: string;
  entry?: boolean;
  sink?: boolean;
}

function parseChain(f: Finding): ChainNode[] {
  const chain: ChainNode[] = (f.pathHumanReadable ?? []).map((entry, idx) => {
    const m = entry.match(/^(.*) \((.*)\)$/);
    const node = m ? { fn: m[1], file: m[2] } : { fn: entry, file: "" };
    return { ...node, entry: idx === 0 };
  });
  chain.push({ fn: `${f.packageName}.${f.vulnerableExport}`, file: f.cve, sink: true });
  return chain;
}

function EdgeSvg() {
  return (
    <svg viewBox="0 0 34 16" preserveAspectRatio="none">
      <path d="M0,8 L34,8" />
    </svg>
  );
}

function Lane({ finding, traced }: { finding: Finding; traced: boolean }) {
  const chain = parseChain(finding);
  return (
    <div className={`lane${traced ? " traced" : ""}`}>
      <div className="lane-head">
        <span className="lane-cve mono">{finding.cve}</span>
        <span className={`sev-pill sev-${finding.severity}`}>{finding.severity}</span>
        <span className="lane-summary">
          {finding.packageName}.{finding.vulnerableExport} — reachable from an entry point
        </span>
      </div>
      <div className="trace-chain">
        {chain.map((node, idx) => (
          <div key={idx} style={{ display: "contents" }}>
            {idx > 0 && (
              <div className="trace-edge">
                <EdgeSvg />
              </div>
            )}
            <div className={`trace-node${node.entry ? " entry" : ""}${node.sink ? " sink" : ""}`}>
              <div className="tag-row">
                {node.entry && <span className="node-tag">entry</span>}
                {node.sink && <span className="node-tag sink-tag">vulnerable export</span>}
              </div>
              <div className="fn data">{node.fn}</div>
              <div className="file">{node.file}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function TraceView({ findings }: { findings: Finding[] }) {
  const reachable = findings.filter((f) => f.status === "reachable");
  const flat = findings.filter((f) => f.status !== "reachable");

  // Stagger the "traced" class onto each lane after mount, so the edges
  // animate in sequentially instead of all appearing pre-drawn — this is
  // the one place this component intentionally has side-effecting state.
  const [tracedCount, setTracedCount] = useState(0);
  useEffect(() => {
    setTracedCount(0);
    if (reachable.length === 0) return;
    const timers = reachable.map((_, i) => setTimeout(() => setTracedCount((c) => Math.max(c, i + 1)), i * 180));
    return () => timers.forEach(clearTimeout);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [findings]);

  return (
    <>
      <div className="section-title mono">
        Traced attack paths <span className="count tnum mono">{reachable.length}</span>
      </div>
      {reachable.length === 0 ? (
        <div className="empty-state">
          {findings.length === 0
            ? "Run a scan to trace reachable CVEs from entry points to vulnerable exports."
            : "No flagged CVE has a live path from an entry point. Everything is either called-but-unreachable or never called."}
        </div>
      ) : (
        reachable.map((f, i) => <Lane key={f.cve} finding={f} traced={i < tracedCount} />)
      )}

      <div className="section-title mono" style={{ marginTop: "2rem" }}>
        No path from any entry point <span className="count tnum mono">{flat.length}</span>
      </div>
      {flat.length === 0 ? (
        <div className="empty-state">Nothing here yet.</div>
      ) : (
        <div className="flat-list">
          {flat.map((f) => (
            <div className="flat-row" key={f.cve}>
              <span className="cve data">{f.cve}</span>
              <span className="pkg">{f.packageName}</span>
              <span className="exp data">{f.vulnerableExport}</span>
              <span className={`verdict ${f.status === "present-unreachable" ? "present" : "clear"} mono`}>
                {f.status === "present-unreachable" ? "no path" : "not called"}
              </span>
            </div>
          ))}
        </div>
      )}
    </>
  );
}
