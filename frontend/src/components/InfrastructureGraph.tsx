"use client";

import { useEffect, useRef, useState } from "react";
import type { Dashboard } from "@/src/lib/api";
import {
  buildGraph,
  buildTrainingGraph,
  type GraphEdge,
  type GraphNode,
  type NodeStatus,
} from "@/src/lib/view";
import { SectionHead } from "@/src/components/StatusIndicator";

const HW = 84; // node half-width  (px)
const HH = 33; // node half-height (px)

const statusChrome: Record<
  NodeStatus,
  { box: string; name: string; dot: string; rule: string }
> = {
  EXTERNAL: {
    box: "border-line bg-panel",
    name: "text-muted",
    dot: "bg-dim",
    rule: "bg-line-2",
  },
  NOMINAL: {
    box: "border-line bg-panel",
    name: "text-ink-2",
    dot: "bg-good/70",
    rule: "bg-line-2",
  },
  FLAGGED: {
    box: "border-warn/30 bg-raised",
    name: "text-ink",
    dot: "bg-warn",
    rule: "bg-warn/60",
  },
  AFFECTED: {
    box: "border-warn/35 bg-raised",
    name: "text-ink",
    dot: "bg-warn",
    rule: "bg-warn/70",
  },
  CRITICAL: {
    box: "border-crit/50 bg-crit/[0.06]",
    name: "text-ink",
    dot: "bg-crit",
    rule: "bg-crit",
  },
};

const statusLabel: Record<NodeStatus, string> = {
  EXTERNAL: "text-dim",
  NOMINAL: "text-muted",
  FLAGGED: "text-warn",
  AFFECTED: "text-warn",
  CRITICAL: "text-crit",
};

function path(a: GraphNode, b: GraphNode, w: number, h: number): string {
  const ax = a.x * w;
  const ay = a.y * h;
  const bx = b.x * w;
  const by = b.y * h;
  const dx = bx - ax;
  const dy = by - ay;

  if (Math.abs(dx) > Math.abs(dy)) {
    const s = Math.sign(dx);
    const x1 = ax + s * HW;
    const x2 = bx - s * HW;
    if (Math.abs(dy) < 3) return `M ${x1} ${ay} L ${x2} ${by}`;
    const mx = (x1 + x2) / 2;
    const d = Math.sign(dy);
    const r = Math.min(12, Math.abs(dy) / 2, Math.abs(x2 - x1) / 2);
    return `M ${x1} ${ay} H ${mx - r * s} Q ${mx} ${ay} ${mx} ${ay + r * d} V ${
      by - r * d
    } Q ${mx} ${by} ${mx + r * s} ${by} H ${x2}`;
  }

  const d = Math.sign(dy) || 1;
  const y1 = ay + d * HH;
  const y2 = by - d * HH;
  if (Math.abs(dx) < 3) return `M ${ax} ${y1} L ${bx} ${y2}`;
  const my = (y1 + y2) / 2;
  const s = Math.sign(dx);
  const r = Math.min(12, Math.abs(dx) / 2, Math.abs(y2 - y1) / 2);
  return `M ${ax} ${y1} V ${my - r * d} Q ${ax} ${my} ${ax + r * s} ${my} H ${
    bx - r * s
  } Q ${bx} ${my} ${bx} ${my + r * d} V ${y2}`;
}

const edgeStroke: Record<GraphEdge["kind"], string> = {
  trust: "#232b2f",
  attack: "#8a6a30",
  target: "#8f3f39",
};

function NodeCard({ node, index }: { node: GraphNode; index: number }) {
  const c = statusChrome[node.status];
  const flipped = node.x > 0.62;
  return (
    <div
      className="group absolute z-10"
      style={{ left: `${node.x * 100}%`, top: `${node.y * 100}%` }}
    >
      <div
        className={`relative -translate-x-1/2 -translate-y-1/2 border ${c.box} w-[168px] transition-colors duration-200 group-hover:border-line-3`}
      >
        <span className={`absolute top-0 bottom-0 left-0 w-[2px] ${c.rule}`} />
        <div className="flex items-baseline justify-between px-2.5 pt-[7px]">
          <span className={`text-[13.5px] leading-none font-medium ${c.name}`}>
            {node.name}
          </span>
          <span className="tnum text-[10.5px] text-dim">
            ast-{String(index + 1).padStart(2, "0")}
          </span>
        </div>
        <div className="px-2.5 pt-[5px] pb-[6px]">
          <span className="label">{node.kind}</span>
        </div>
        <div className="flex items-center justify-between border-t border-line/80 px-2.5 py-[5px]">
          <span className="flex items-center gap-1.5">
            <span
              className={`inline-block h-[5px] w-[5px] ${c.dot} ${
                node.status === "CRITICAL" ? "blink" : ""
              }`}
            />
            <span
              className={`font-mono text-[10.5px] tracking-[0.16em] ${statusLabel[node.status]}`}
            >
              {node.statusLabel ?? node.status}
            </span>
          </span>
          <span className="tnum text-[10.5px] text-dim">{node.chip}</span>
        </div>
      </div>

      {/* hover instrumentation */}
      <div
        className={`pointer-events-none absolute top-[22px] z-30 w-[214px] border border-line-2 bg-raised px-2.5 py-2 opacity-0 shadow-[0_8px_24px_rgba(0,0,0,0.45)] transition-opacity duration-150 group-hover:opacity-100 ${
          flipped ? "right-[84px]" : "left-[84px]"
        }`}
      >
        {node.meta.map(([k, v]) => (
          <div key={k} className="flex items-baseline justify-between gap-3 py-[3px]">
            <span className="label">{k}</span>
            <span className="tnum text-[11.5px] text-ink-2">{v}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function InfrastructureGraph({
  dashboard,
  fog = false,
}: {
  dashboard: Dashboard;
  fog?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ w: 0, h: 0 });

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      const r = entries[0].contentRect;
      setSize({ w: Math.round(r.width), h: Math.round(r.height) });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const { nodes: graphNodes, edges: graphEdges } = fog
    ? buildTrainingGraph(dashboard)
    : buildGraph(dashboard);
  const byId = new Map(graphNodes.map((n) => [n.id, n]));
  const ready = size.w > 0 && size.h > 0;

  const affected = graphNodes.filter(
    (n) => n.status === "AFFECTED" || n.status === "CRITICAL",
  ).length;
  const graphStats = [
    { k: "ASSETS", v: String(graphNodes.length).padStart(2, "0") },
    { k: fog ? "WITH EVIDENCE" : "AFFECTED", v: String(affected).padStart(2, "0") },
    { k: "ISOLATED", v: String(dashboard.endpoints.filter((e) => e.isolated).length).padStart(2, "0") },
  ];
  const graphFooter = [
    { k: "SCENARIO", v: dashboard.environment.scenario },
    { k: "CLOCK", v: dashboard.environment.simulation_time.slice(11, 19) },
    { k: "ATTACK", v: dashboard.attack.status },
    { k: "GOVERNOR", v: dashboard.safety.simulation_status },
    { k: "TELEMETRY", v: `${dashboard.attack.telemetry_events} EV` },
  ];

  return (
    <section className="flex min-h-0 flex-col bg-base">
      <SectionHead
        title="Live Infrastructure"
        right={
          <>
            {graphStats.map((s) => (
              <span key={s.k} className="flex items-baseline gap-1.5">
                <span className="tnum text-[11.5px] text-ink-2">{s.v}</span>
                <span className="label">{s.k}</span>
              </span>
            ))}
          </>
        }
      />

      <div ref={ref} className="grid-field relative min-h-0 flex-1 overflow-hidden">
        {/* corner brackets */}
        <span className="pointer-events-none absolute top-2 left-2 h-3 w-3 border-t border-l border-line-2" />
        <span className="pointer-events-none absolute top-2 right-2 h-3 w-3 border-t border-r border-line-2" />
        <span className="pointer-events-none absolute bottom-2 left-2 h-3 w-3 border-b border-l border-line-2" />
        <span className="pointer-events-none absolute right-2 bottom-2 h-3 w-3 border-r border-b border-line-2" />

        {/* legend */}
        <div className="pointer-events-none absolute bottom-3 left-4 z-20 flex flex-col gap-[5px]">
          {(
            (fog
              ? ([
                  ["NOMINAL", "bg-good/70"],
                  ["ACTIVITY DETECTED", "bg-warn"],
                  ["SUSPICIOUS", "bg-warn"],
                ] as const)
              : ([
                  ["NOMINAL", "bg-good/70"],
                  ["AFFECTED", "bg-warn"],
                  ["CRITICAL", "bg-crit"],
                ] as const))
          ).map(([k, c]) => (
            <span key={k} className="flex items-center gap-1.5">
              <span className={`inline-block h-[5px] w-[5px] ${c}`} />
              <span className="label">{k}</span>
            </span>
          ))}
        </div>

        {/* zone annotations */}
        <span className="pointer-events-none absolute top-[7%] left-4 label">
          ENDPOINTS
        </span>
        <span className="pointer-events-none absolute top-[7%] left-[46%] label">
          CONTROL PLANE
        </span>
        <span className="pointer-events-none absolute top-[7%] right-[6%] label text-crit/55!">
          DATA PLANE
        </span>
        <span className="pointer-events-none absolute right-4 bottom-3 z-20 label">
          {fog ? "FOG OF WAR · EVIDENCE ONLY" : "OBSERVABLE EVIDENCE ONLY"}
        </span>

        {ready ? (
          <svg
            width={size.w}
            height={size.h}
            className="absolute inset-0"
            aria-hidden
          >
            <defs>
              <marker
                id="tn-arrow"
                markerWidth="7"
                markerHeight="7"
                refX="6"
                refY="3.5"
                orient="auto"
              >
                <path d="M0 0 L6 3.5 L0 7 z" fill="#9a4740" />
              </marker>
            </defs>

            {graphEdges.map((e, i) => {
              const a = byId.get(e.from);
              const b = byId.get(e.to);
              if (!a || !b) return null;
              const d = path(a, b, size.w, size.h);
              const hot = e.kind !== "trust";
              const mx = ((a.x + b.x) / 2) * size.w;
              const my = ((a.y + b.y) / 2) * size.h;

              return (
                <g key={`${e.from}-${e.to}`}>
                  <path
                    d={d}
                    fill="none"
                    stroke={edgeStroke[e.kind]}
                    strokeWidth={hot ? 1.15 : 1}
                    strokeDasharray={hot ? "3 5" : undefined}
                    markerEnd={e.kind === "target" ? "url(#tn-arrow)" : undefined}
                    style={
                      hot
                        ? { animation: `tn-dash ${e.kind === "target" ? 1.8 : 2.6}s linear infinite` }
                        : undefined
                    }
                  />
                  {hot ? (
                    <circle r="2.1" fill={e.kind === "target" ? "#cc5149" : "#cb9a45"}>
                      <animateMotion
                        dur={`${2.4 + i * 0.35}s`}
                        begin={`${i * 0.5}s`}
                        repeatCount="indefinite"
                        path={d}
                      />
                    </circle>
                  ) : null}
                  {e.label ? (
                    <text
                      x={mx}
                      y={my - 6}
                      textAnchor="middle"
                      fontSize="8"
                      letterSpacing="1.6"
                      fontFamily="var(--font-geist-mono), monospace"
                      fill="#5b666c"
                      stroke="#0a0c0d"
                      strokeWidth="3"
                      paintOrder="stroke"
                    >
                      {e.label}
                    </text>
                  ) : null}
                </g>
              );
            })}
          </svg>
        ) : null}

        {graphNodes.map((n, i) => (
          <NodeCard key={n.id} node={n} index={i} />
        ))}
      </div>

      <div className="flex h-9 shrink-0 items-stretch border-t border-line bg-panel">
        {graphFooter.map((f) => (
          <span
            key={f.k}
            className="flex items-center gap-2 border-r border-line px-3 last:border-r-0"
          >
            <span className="label">{f.k}</span>
            <span className="tnum text-[11.5px] text-ink-2">{f.v}</span>
          </span>
        ))}
        <span className="ml-auto flex items-center gap-2 px-3">
          <span className="label">SYNC</span>
          <span
            className={`tnum text-[11.5px] ${
              dashboard.safety.emergency_stopped ? "text-crit" : "text-good"
            }`}
          >
            {dashboard.safety.emergency_stopped ? "HALTED" : "STREAMING"}
          </span>
        </span>
      </div>
    </section>
  );
}
