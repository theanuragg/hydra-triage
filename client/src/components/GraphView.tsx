import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import type { PointerEvent as ReactPointerEvent } from "react";
import type { Finding, ScanGraph } from "../types";

interface GNode {
  id: string;
  kind: "entry" | "fn" | "sink";
  label: string;
  sub: string;
  severity?: "critical" | "high" | "medium" | "low";
  present?: boolean;
  x: number;
  y: number;
  vx: number;
  vy: number;
}

interface GEdge {
  a: string;
  b: string;
  sinkKey?: string;
}

const REPULSION = 5200;
const SPRING_LEN = 130;
const SPRING_K = 0.02;
const CENTER_K = 0.012;
const DAMP = 0.85;
const MAX_SPEED = 40;
const TICKS = 240;

function buildGraph(graph: ScanGraph): { nodes: GNode[]; edges: GEdge[] } {
  const nodes: GNode[] = [];
  const push = (n: GNode) => {
    nodes.push(n);
  };

  for (const f of graph.functions) {
    const label = f.name === "<anonymous>" || f.name === "" ? f.modulePath : f.name;
    push({
      id: f.id,
      kind: f.isEntryPoint ? "entry" : "fn",
      label,
      sub: f.isEntryPoint && f.entryKind ? `${f.modulePath} · ${f.entryKind}` : f.modulePath,
      x: 0,
      y: 0,
      vx: 0,
      vy: 0,
    });
  }
  for (const s of graph.sinks) {
    push({
      id: s.key,
      kind: "sink",
      label: `${s.packageName}.${s.vulnerableExport}`,
      sub: s.cve,
      severity: s.severity,
      present: s.present,
      x: 0,
      y: 0,
      vx: 0,
      vy: 0,
    });
  }

  const byId = new Map(nodes.map((n) => [n.id, n]));
  const edges: GEdge[] = graph.calls.map((c) => ({ a: c.callerId, b: c.calleeId }));
  for (const sc of graph.sinkCalls) {
    if (byId.has(sc.sinkKey)) edges.push({ a: sc.callerId, b: sc.sinkKey, sinkKey: sc.sinkKey });
  }

  return { nodes, edges };
}

function tick(nodes: GNode[], edges: GEdge[]) {
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i];
      const b = nodes[j];
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      let d2 = dx * dx + dy * dy + 1;
      let d = Math.sqrt(d2);
      if (d < 1) {
        d = 1;
        d2 = 1;
      }
      const f = REPULSION / d2;
      const fx = (f * dx) / d;
      const fy = (f * dy) / d;
      a.vx -= fx;
      a.vy -= fy;
      b.vx += fx;
      b.vy += fy;
    }
  }
  const index = new Map(nodes.map((n) => [n.id, n]));
  for (const e of edges) {
    const a = index.get(e.a);
    const b = index.get(e.b);
    if (!a || !b) continue;
    const dx = b.x - a.x;
    const dy = b.y - a.y;
    const d = Math.sqrt(dx * dx + dy * dy) || 1;
    const f = (d - SPRING_LEN) * SPRING_K;
    const fx = (f * dx) / d;
    const fy = (f * dy) / d;
    a.vx += fx;
    a.vy += fy;
    b.vx -= fx;
    b.vy -= fy;
  }
  for (const n of nodes) {
    n.vx += -n.x * CENTER_K;
    n.vy += -n.y * CENTER_K;
    n.vx *= DAMP;
    n.vy *= DAMP;
    const sp = Math.sqrt(n.vx * n.vx + n.vy * n.vy);
    if (sp > MAX_SPEED) {
      n.vx = (n.vx / sp) * MAX_SPEED;
      n.vy = (n.vy / sp) * MAX_SPEED;
    }
    n.x += n.vx;
    n.y += n.vy;
  }
}

interface Viewport {
  x: number;
  y: number;
  k: number;
}

function fitViewport(nodes: GNode[], vw: number, vh: number, pad: number): Viewport {
  let minX = Infinity;
  let maxX = -Infinity;
  let minY = Infinity;
  let maxY = -Infinity;
  for (const n of nodes) {
    minX = Math.min(minX, n.x);
    maxX = Math.max(maxX, n.x);
    minY = Math.min(minY, n.y);
    maxY = Math.max(maxY, n.y);
  }
  const w = Math.max(maxX - minX, 1);
  const h = Math.max(maxY - minY, 1);
  const k = Math.min((vw - pad * 2) / w, (vh - pad * 2) / h, 1.4);
  return {
    k: Math.max(k, 0.05),
    x: (minX + maxX) / 2 - vw / k / 2,
    y: (minY + maxY) / 2 - vh / k / 2,
  };
}

const sinkKeyOf = (f: Finding) => `${f.packageName}::${f.vulnerableExport}::${f.cve}`;

export default function GraphView({
  graph,
  findings,
}: {
  graph: ScanGraph | null;
  findings: Finding[];
}) {
  const { nodes, edges } = useMemo(() => (graph ? buildGraph(graph) : { nodes: [], edges: [] }), [graph]);
  const byIdRef = useRef(new Map<string, GNode>());
  byIdRef.current = new Map(nodes.map((n) => [n.id, n]));

  const svgRef = useRef<SVGSVGElement | null>(null);
  const [vp, setVp] = useState<Viewport>({ x: 0, y: 0, k: 1 });
  const [, setFrame] = useState(0);
  const dragging = useRef<{ node: GNode | null; startX: number; startY: number; panStart: Viewport | null; moved: boolean } | null>(null);
  const lastDragMoved = useRef(false);
  const [hovered, setHovered] = useState<GNode | null>(null);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [size, setSize] = useState({ w: 900, h: 540 });
  const sizeRef = useRef({ w: 900, h: 540 });
  const vpRef = useRef(vp);
  vpRef.current = vp;

  const runSim = useCallback(() => {
    let t = 0;
    const loop = () => {
      t++;
      if (t <= TICKS) tick(nodes, edges);
      if (svgRef.current) {
        const rect = svgRef.current.getBoundingClientRect();
        if (rect.width > 0 && rect.height > 0) sizeRef.current = { w: rect.width, h: rect.height };
      }
      setFrame((f) => f + 1);
      if (t === TICKS) {
        setVp(fitViewport(nodes, sizeRef.current.w, sizeRef.current.h, 90));
        setSize(sizeRef.current);
        return;
      }
      requestAnimationFrame(loop);
    };
    requestAnimationFrame(loop);
  }, [nodes, edges]);

  useEffect(() => {
    runSim();
  }, [runSim]);

  useEffect(() => {
    if (!graph || findings.length === 0) return;
    const first = findings.find((f) => f.status === "reachable") ?? findings[0];
    setSelected(first);
  }, [graph, findings]);

  // Wheel zoom needs a native listener: React's synthetic wheel events are
  // attached passively, so preventDefault would not stop page scrolling.
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    const onWheel = (ev: WheelEvent) => {
      ev.preventDefault();
      const rect = svg.getBoundingClientRect();
      const cur = vpRef.current;
      const px = ev.clientX - rect.left;
      const py = ev.clientY - rect.top;
      const factor = ev.deltaY < 0 ? 1.15 : 1 / 1.15;
      const nextK = Math.min(Math.max(cur.k * factor, 0.35), 3);
      const ratio = nextK / cur.k;
      setVp({ k: nextK, x: px / cur.k - (px / cur.k - cur.x) * ratio, y: py / cur.k - (py / cur.k - cur.y) * ratio });
    };
    svg.addEventListener("wheel", onWheel, { passive: false });
    return () => svg.removeEventListener("wheel", onWheel);
  }, []);

  const toWorld = (clientX: number, clientY: number) => {
    const rect = svgRef.current!.getBoundingClientRect();
    return {
      wx: vpRef.current.x + (clientX - rect.left) / vpRef.current.k,
      wy: vpRef.current.y + (clientY - rect.top) / vpRef.current.k,
    };
  };

  const onPointerDown = (e: ReactPointerEvent<SVGSVGElement>) => {
    const world = toWorld(e.clientX, e.clientY);
    const nodeId = (e.target as Element).getAttribute("data-node");
    const node = nodeId ? byIdRef.current.get(nodeId) : undefined;
    dragging.current = { node: node ?? null, startX: world.wx, startY: world.wy, panStart: node ? null : vpRef.current, moved: false };
    lastDragMoved.current = false;
    e.currentTarget.setPointerCapture(e.pointerId);
  };

  const onPointerMove = (e: ReactPointerEvent<SVGSVGElement>) => {
    const d = dragging.current;
    if (!d) return;
    const world = toWorld(e.clientX, e.clientY);
    if (Math.abs(world.wx - d.startX) > 4 || Math.abs(world.wy - d.startY) > 4) d.moved = true;
    if (d.node) {
      d.node.x = world.wx;
      d.node.y = world.wy;
      setFrame((f) => f + 1);
    } else if (d.panStart) {
      setVp({ ...d.panStart, x: d.panStart.x - (world.wx - d.startX), y: d.panStart.y - (world.wy - d.startY) });
    }
  };

  const onPointerUp = () => {
    if (dragging.current) {
      lastDragMoved.current = dragging.current.moved;
      dragging.current = null;
    }
  };

  const selectSink = (sinkKey: string) => {
    const hit = findings.find((x) => sinkKeyOf(x) === sinkKey);
    setSelected(hit ?? null);
  };

  const pathIds = useMemo(() => new Set(selected?.path ?? []), [selected]);

  const edgeClass = (e: GEdge) => {
    if (pathIds.has(e.a) && pathIds.has(e.b)) return "graph-edge path";
    if (e.sinkKey) {
      const f = findingForSink(e.sinkKey);
      if (f?.status === "present-unreachable") return "graph-edge sink";
      if (f?.status === "reachable") return "graph-edge sinkedge-reachable";
      return "graph-edge unseen";
    }
    return "graph-edge";
  };

  const findingForSink = (key: string) => findings.find((x) => sinkKeyOf(x) === key);

  const nodeClass = (n: GNode) => {
    const onPath = pathIds.has(n.id);
    if (n.kind === "sink") {
      const f = findingForSink(n.id);
      const status = n.present ? (f?.status ?? "present-unreachable") : "not-present";
      return `graph-node sink ${status}${onPath ? " on-path" : ""}`;
    }
    return `graph-node ${n.kind}${onPath ? " on-path" : ""}`;
  };

  return (
    <div className="graph-card">
      <svg
        ref={svgRef}
        className="graph-svg"
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerLeave={onPointerUp}
        role="img"
        aria-label="Call graph with reachability paths"
        viewBox={`${vp.x} ${vp.y} ${size.w / vp.k} ${size.h / vp.k}`}
      >
        {edges.map((e, i) => {
          const a = byIdRef.current.get(e.a);
          const b = byIdRef.current.get(e.b);
          if (!a || !b) return null;
          return (
            <line key={i} className={edgeClass(e)} x1={a.x} y1={a.y} x2={b.x} y2={b.y} />
          );
        })}
        {nodes.map((n) => (
          <g
            key={n.id}
            className={nodeClass(n)}
            transform={`translate(${n.x} ${n.y})`}
            data-node={n.id}
            style={{ cursor: n.kind === "sink" ? "pointer" : "grab" }}
            onMouseEnter={() => setHovered(n)}
            onMouseLeave={() => setHovered((h) => (h?.id === n.id ? null : h))}
            onClick={() => {
              if (n.kind === "sink" && !lastDragMoved.current) selectSink(n.id);
            }}
          >
            {n.kind === "sink" ? <path d="M0,-14 L14,0 L0,14 L-14,0 Z" /> : <circle r="19" />}
            <text className="node-label" y="-26">
              {n.label}
            </text>
            <text className="node-sub" y="-10">
              {n.sub}
            </text>
          </g>
        ))}
      </svg>

      <div className="graph-legend">
        <span>
          <i className="dot entry" /> entry point
        </span>
        <span>
          <i className="dot fn" /> function
        </span>
        <span>
          <i className="dot sink-reachable" /> vulnerable export, reachable
        </span>
        <span>
          <i className="dot sink-present" /> present, no path
        </span>
        <span>
          <i className="dot sink-unseen" /> never called
        </span>
        <span className="legend-hint">drag nodes · scroll to zoom · click a diamond to trace its path</span>
      </div>

      <div className="graph-detail">
        {selected ? (
          <>
            <div className="graph-detail-head">
              <span className="mono cve">{selected.cve}</span>
              <span className={`sev-pill sev-${selected.severity}`}>{selected.severity}</span>
              <span className="graph-detail-verdict mono">{selected.status.replace("-", " ")}</span>
              {selected.reference && (
                <a className="graph-detail-ref" href={selected.reference} target="_blank" rel="noreferrer">
                  advisory ↗
                </a>
              )}
            </div>
            <div className="graph-detail-body">{selected.summary}</div>
            {selected.pathHumanReadable && selected.pathHumanReadable.length > 0 && (
              <div className="graph-detail-chain mono">
                {selected.pathHumanReadable.map((step, i) => (
                  <span className="chain-step" key={i}>
                    {i > 0 && <span className="chain-arrow">→</span>}
                    {step}
                  </span>
                ))}
              </div>
            )}
          </>
        ) : (
          <div className="graph-detail-empty">
            {findings.length === 0
              ? "Run a scan to build the call graph."
              : "Click a vulnerable-export diamond to trace its reachability path."}
          </div>
        )}
      </div>

      {hovered && (
        <div className="graph-tooltip">
          <div className="tooltip-title">{hovered.label}</div>
          <div className="tooltip-sub">{hovered.sub}</div>
          {hovered.kind === "sink" && hovered.severity && (
            <div className={`tooltip-sev sev-${hovered.severity}`}>{hovered.severity}</div>
          )}
        </div>
      )}
    </div>
  );
}