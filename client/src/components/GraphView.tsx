import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import type { PointerEvent as ReactPointerEvent } from "react";
import {
  forceSimulation,
  forceManyBody,
  forceLink,
  forceCenter,
  forceCollide,
  forceX,
  forceY,
} from "d3-force";
import type { Finding, ScanGraph } from "../types";

interface GNode {
  id: string;
  kind: "entry" | "fn" | "sink";
  label: string;
  sub: string;
  severity?: "critical" | "high" | "medium" | "low";
  present?: boolean;
  degree: number;
  x: number;
  y: number;
  vx: number;
  vy: number;
}

interface GEdge {
  source: string;
  target: string;
  sinkKey?: string;
}

const NODE_R_BASE = 4;
const NODE_R_MAX = 10;
const LINK_DIST = 85;
const CHARGE_STRENGTH = -220;
const COLLISION_PAD = 4;

function buildGraph(graph: ScanGraph): { nodes: GNode[]; edges: GEdge[] } {
  const nodes: GNode[] = [];
  for (const f of graph.functions) {
    const label = f.name === "<anonymous>" || f.name === "" ? f.modulePath : f.name;
    nodes.push({
      id: f.id,
      kind: f.isEntryPoint ? "entry" : "fn",
      label,
      sub: f.isEntryPoint && f.entryKind ? `${f.modulePath} · ${f.entryKind}` : f.modulePath,
      degree: 0,
      x: 0,
      y: 0,
      vx: 0,
      vy: 0,
    });
  }
  for (const s of graph.sinks) {
    nodes.push({
      id: s.key,
      kind: "sink",
      label: `${s.packageName}.${s.vulnerableExport}`,
      sub: s.cve,
      severity: s.severity,
      present: s.present,
      degree: 0,
      x: 0,
      y: 0,
      vx: 0,
      vy: 0,
    });
  }

  const byId = new Map(nodes.map((n) => [n.id, n]));
  const edges: GEdge[] = graph.calls.map((c) => ({ source: c.callerId, target: c.calleeId }));
  for (const sc of graph.sinkCalls) {
    if (byId.has(sc.sinkKey)) edges.push({ source: sc.callerId, target: sc.sinkKey, sinkKey: sc.sinkKey });
  }

  for (const e of edges) {
    const a = byId.get(e.source);
    const b = byId.get(e.target);
    if (a) a.degree++;
    if (b) b.degree++;
  }

  return { nodes, edges };
}

function nodeRadius(n: GNode): number {
  return NODE_R_BASE + Math.min(NODE_R_MAX - NODE_R_BASE, n.degree * 1.2);
}

const sinkKeyOf = (f: Finding) => `${f.packageName}::${f.vulnerableExport}::${f.cve}`;

interface Viewport {
  x: number;
  y: number;
  k: number;
}

function fitViewport(nodes: GNode[], vw: number, vh: number, pad: number): Viewport {
  if (nodes.length === 0) return { x: 0, y: 0, k: 1 };
  let minX = Infinity,
    maxX = -Infinity,
    minY = Infinity,
    maxY = -Infinity;
  for (const n of nodes) {
    minX = Math.min(minX, n.x);
    maxX = Math.max(maxX, n.x);
    minY = Math.min(minY, n.y);
    maxY = Math.max(maxY, n.y);
  }
  const w = Math.max(maxX - minX, 1);
  const h = Math.max(maxY - minY, 1);
  const k = Math.min((vw - pad * 2) / w, (vh - pad * 2) / h, 1.6);
  return {
    k: Math.max(k, 0.08),
    x: (minX + maxX) / 2 - vw / k / 2,
    y: (minY + maxY) / 2 - vh / k / 2,
  };
}

export default function GraphView({
  graph,
  findings,
}: {
  graph: ScanGraph | null;
  findings: Finding[];
}) {
  const { nodes, edges } = useMemo(() => (graph ? buildGraph(graph) : { nodes: [], edges: [] }), [graph]);

  const svgRef = useRef<SVGSVGElement | null>(null);
  const [vp, setVp] = useState<Viewport>({ x: 0, y: 0, k: 1 });
  const [, setFrame] = useState(0);
  const dragging = useRef<{
    node: GNode | null;
    startX: number;
    startY: number;
    panStart: Viewport | null;
    moved: boolean;
  } | null>(null);
  const lastDragMoved = useRef(false);
  const [hovered, setHovered] = useState<GNode | null>(null);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [size, setSize] = useState({ w: 900, h: 540 });
  const sizeRef = useRef({ w: 900, h: 540 });
  const vpRef = useRef(vp);
  vpRef.current = vp;
  const nodesRef = useRef(nodes);
  nodesRef.current = nodes;
  const byIdRef = useRef(new Map<string, GNode>());
  byIdRef.current = new Map(nodes.map((n) => [n.id, n]));

  // Compute neighbor set for hover dim
  const neighborMap = useMemo(() => {
    const map = new Map<string, Set<string>>();
    for (const n of nodes) map.set(n.id, new Set());
    for (const e of edges) {
      map.get(e.source)?.add(e.target);
      map.get(e.target)?.add(e.source);
    }
    return map;
  }, [nodes, edges]);

  // Run d3-force synchronously before first render
  useEffect(() => {
    if (nodes.length === 0) return;

    const rect = svgRef.current?.getBoundingClientRect();
    const w = rect?.width || 900;
    const h = rect?.height || 540;
    sizeRef.current = { w, h };

    // Seed positions: entries center, fn ring, sinks outer ring
    const entries = nodes.filter((n) => n.kind === "entry");
    const fns = nodes.filter((n) => n.kind === "fn");
    const sinks = nodes.filter((n) => n.kind === "sink");
    entries.forEach((n, i) => {
      const angle = (i / Math.max(entries.length, 1)) * Math.PI * 2;
      n.x = Math.cos(angle) * 30;
      n.y = Math.sin(angle) * 30;
    });
    fns.forEach((n, i) => {
      const angle = (i / Math.max(fns.length, 1)) * Math.PI * 2;
      n.x = Math.cos(angle) * 120;
      n.y = Math.sin(angle) * 120;
    });
    sinks.forEach((n, i) => {
      const angle = (i / Math.max(sinks.length, 1)) * Math.PI * 2;
      n.x = Math.cos(angle) * 200;
      n.y = Math.sin(angle) * 200;
    });

    const linkData = edges.map((e) => ({ source: e.source, target: e.target }));
    const linkForce = forceLink<GNode, { source: string; target: string }>(linkData)
      .id((d: GNode) => d.id)
      .distance(LINK_DIST);

    const sim = forceSimulation(nodes)
      .force("charge", forceManyBody().strength(CHARGE_STRENGTH))
      .force("link", linkForce)
      .force("center", forceCenter(0, 0))
      .force("collide", forceCollide<GNode>((d) => nodeRadius(d) + COLLISION_PAD))
      .force("x", forceX<GNode>(0).strength(0.03))
      .force("y", forceY<GNode>(0).strength(0.03))
      .alphaTarget(0)
      .stop();

    // Run synchronously: up to 300 ticks
    for (let i = 0; i < 300; i++) {
      sim.tick();
      if (sim.alpha() < 0.01) break;
    }

    setVp(fitViewport(nodes, w, h, 60));
    setSize({ w, h });
    setFrame((f) => f + 1);

    return () => { sim.stop(); };
  }, [nodes, edges]);

  // Wheel zoom
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
      const nextK = Math.min(Math.max(cur.k * factor, 0.08), 4);
      const ratio = nextK / cur.k;
      setVp({
        k: nextK,
        x: px / cur.k - (px / cur.k - cur.x) * ratio,
        y: py / cur.k - (py / cur.k - cur.y) * ratio,
      });
    };
    svg.addEventListener("wheel", onWheel, { passive: false });
    return () => svg.removeEventListener("wheel", onWheel);
  }, []);

  // Resize observer
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    const obs = new ResizeObserver(() => {
      const rect = svg.getBoundingClientRect();
      if (rect.width > 0 && rect.height > 0) {
        sizeRef.current = { w: rect.width, h: rect.height };
        setSize({ w: rect.width, h: rect.height });
      }
    });
    obs.observe(svg);
    return () => obs.disconnect();
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
    const nodeId = (e.target as Element).closest("[data-node]")?.getAttribute("data-node");
    const node = nodeId ? byIdRef.current.get(nodeId) : undefined;
    dragging.current = {
      node: node ?? null,
      startX: world.wx,
      startY: world.wy,
      panStart: node ? null : vpRef.current,
      moved: false,
    };
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
      d.node.vx = 0;
      d.node.vy = 0;
      setFrame((f) => f + 1);
    } else if (d.panStart) {
      setVp({
        ...d.panStart,
        x: d.panStart.x - (world.wx - d.startX),
        y: d.panStart.y - (world.wy - d.startY),
      });
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
    if (pathIds.has(e.source) && pathIds.has(e.target)) return "graph-edge path";
    if (e.sinkKey) {
      const f = findings.find((x) => sinkKeyOf(x) === e.sinkKey);
      if (f?.status === "present-unreachable") return "graph-edge sink-edge";
      if (f?.status === "reachable") return "graph-edge sink-edge-reachable";
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

  // Hover dim logic: non-neighbor nodes get dimmed
  const isDimmed = (n: GNode) => {
    if (!hovered) return false;
    if (n.id === hovered.id) return false;
    return !neighborMap.get(hovered.id)?.has(n.id);
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
          const a = byIdRef.current.get(e.source);
          const b = byIdRef.current.get(e.target);
          if (!a || !b) return null;
          const dimmed = hovered && !neighborMap.get(hovered.id)?.has(e.source) && !neighborMap.get(hovered.id)?.has(e.target) && hovered.id !== e.source && hovered.id !== e.target;
          return (
            <line
              key={i}
              className={edgeClass(e)}
              x1={a.x}
              y1={a.y}
              x2={b.x}
              y2={b.y}
              opacity={dimmed ? 0.08 : undefined}
            />
          );
        })}
        {nodes.map((n) => (
          <g
            key={n.id}
            className={`${nodeClass(n)}${isDimmed(n) ? " dimmed" : ""}`}
            transform={`translate(${n.x} ${n.y})`}
            data-node={n.id}
            style={{ cursor: n.kind === "sink" ? "pointer" : "grab" }}
            onMouseEnter={() => setHovered(n)}
            onMouseLeave={() => setHovered((h) => (h?.id === n.id ? null : h))}
            onClick={() => {
              if (n.kind === "sink" && !lastDragMoved.current) selectSink(n.id);
            }}
          >
            {n.kind === "sink" ? (
              <path d={`M0,-${nodeRadius(n) + 3} L${nodeRadius(n) + 3},0 L0,${nodeRadius(n) + 3} L-${nodeRadius(n) + 3},0 Z`} />
            ) : (
              <circle r={nodeRadius(n)} />
            )}
            {(hovered?.id === n.id || pathIds.has(n.id)) && (
              <>
                <text className="node-label" y={-(nodeRadius(n) + 8)}>
                  {n.label}
                </text>
                <text className="node-sub" y={-(nodeRadius(n) - 4)}>
                  {n.sub}
                </text>
              </>
            )}
          </g>
        ))}
      </svg>

      <div className="graph-legend">
        <span>
          <i className="dot entry" /> entry
        </span>
        <span>
          <i className="dot fn" /> function
        </span>
        <span>
          <i className="dot sink-reachable" /> reachable
        </span>
        <span>
          <i className="dot sink-present" /> present, no path
        </span>
        <span>
          <i className="dot sink-unseen" /> never called
        </span>
        <span className="legend-hint">drag nodes · scroll to zoom · click diamond to trace</span>
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
