import type { ScanStats, Finding, Severity } from "../types";

interface Props {
  stats: ScanStats | null;
  findings: Finding[];
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

export default function StatRail({ stats, findings }: Props) {
  const reachable = findings.filter((f) => f.status === "reachable").length;
  const present = findings.filter((f) => f.status === "present-unreachable").length;
  const clear = findings.filter((f) => f.status === "not-present").length;

  const sevCounts = SEVERITIES.map((s) => ({ severity: s, count: findings.filter((f) => f.severity === s).length }));

  return (
    <div className="rail">
      <div className="rail-section">
        <div className="rail-label mono">Extraction</div>
        <StatRow label="functions" value={stats?.functions} />
        <StatRow label="local calls" value={stats?.localCalls} />
        <StatRow label="external calls" value={stats?.externalCalls} />
        <StatRow label="entry points" value={stats?.entryPoints} />
      </div>

      <div className="rail-section">
        <div className="rail-label mono">Triage</div>
        <StatRow label="reachable" value={stats ? reachable : undefined} />
        <StatRow label="present, no path" value={stats ? present : undefined} />
        <StatRow label="not called" value={stats ? clear : undefined} />
      </div>

      <div className="rail-section">
        <div className="rail-label mono">Severity</div>
        <div className="severity-bar" role="img" aria-label="finding counts by severity">
          {stats &&
            sevCounts.map(({ severity, count }) =>
              count > 0 ? <span key={severity} className={severity} style={{ width: `${(count / findings.length) * 100}%` }} /> : null,
            )}
        </div>
        {sevCounts.map(({ severity, count }) => (
          <div className="sev-row" key={severity}>
            <span>{severity}</span>
            <span className={`sev-count tnum ${severity}`}>{stats ? count : "—"}</span>
          </div>
        ))}
      </div>

      <div className="rail-section">
        <div className="rail-label mono">Legend</div>
        <div className="legend-item">
          <span className="legend-dot reachable" />
          reachable from an entry point
        </div>
        <div className="legend-item">
          <span className="legend-dot present" />
          called, but no path in
        </div>
        <div className="legend-item">
          <span className="legend-dot clear" />
          never called at all
        </div>
      </div>
    </div>
  );
}

function StatRow({ label, value }: { label: string; value: number | undefined }) {
  return (
    <div className="stat-row">
      <span>{label}</span>
      <span className="n data tnum">{value ?? "—"}</span>
    </div>
  );
}