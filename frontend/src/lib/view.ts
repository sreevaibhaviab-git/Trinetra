/**
 * Derivations from live backend payloads into what the console draws.
 *
 * Everything here is a projection of observable state returned by the API. The
 * Red Engine's own view of its progress is never available to this layer, so
 * the graph and timeline can only reflect evidence the range has published.
 */

import type { AgentEvent, Dashboard, TelemetryEvent } from "@/src/lib/api";

export type Tone = "ice" | "good" | "warn" | "crit" | "idle";

export type NodeStatus = "NOMINAL" | "FLAGGED" | "AFFECTED" | "CRITICAL" | "EXTERNAL";

export interface GraphNode {
  id: string;
  name: string;
  kind: string;
  status: NodeStatus;
  /** Optional analyst-facing wording, used by Training's fog of war. */
  statusLabel?: string;
  chip: string;
  x: number;
  y: number;
  meta: [string, string][];
}

export interface GraphEdge {
  from: string;
  to: string;
  kind: "trust" | "attack" | "target";
  label?: string;
}

/* ── fixed topology: position and wiring are design, status is live ── */

const LAYOUT: Record<string, { x: number; y: number; kind: string; short: string }> = {
  "endpoint-arjun-01": { x: 0.15, y: 0.16, kind: "ENDPOINT", short: "Arjun · macOS" },
  "endpoint-maya-01": { x: 0.15, y: 0.5, kind: "ENDPOINT", short: "Maya · Windows" },
  "endpoint-ethan-01": { x: 0.15, y: 0.84, kind: "ENDPOINT", short: "Ethan · Linux" },
  "identity-provider": { x: 0.36, y: 0.33, kind: "IDENTITY", short: "Identity Provider" },
  "api-gateway": { x: 0.36, y: 0.78, kind: "NETWORK EDGE", short: "API Gateway" },
  github: { x: 0.58, y: 0.14, kind: "SOURCE CONTROL", short: "GitHub" },
  aws: { x: 0.58, y: 0.47, kind: "CLOUD ACCOUNT", short: "AWS" },
  "production-server": { x: 0.58, y: 0.82, kind: "COMPUTE", short: "Production Server" },
  "customer-database": { x: 0.83, y: 0.62, kind: "DATA STORE", short: "Customer Database" },
};

const TRUST: GraphEdge[] = [
  { from: "endpoint-arjun-01", to: "identity-provider", kind: "trust" },
  { from: "endpoint-maya-01", to: "identity-provider", kind: "trust" },
  { from: "endpoint-ethan-01", to: "api-gateway", kind: "trust" },
  { from: "identity-provider", to: "github", kind: "trust", label: "OAUTH" },
  { from: "identity-provider", to: "aws", kind: "trust", label: "SSO" },
  { from: "api-gateway", to: "production-server", kind: "trust" },
  { from: "aws", to: "production-server", kind: "trust" },
  { from: "production-server", to: "customer-database", kind: "trust" },
  { from: "aws", to: "customer-database", kind: "trust", label: "QUERY" },
];

const SEVERITY_RANK: Record<TelemetryEvent["severity"], number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export const severityTone: Record<TelemetryEvent["severity"], Tone> = {
  info: "good",
  low: "ice",
  medium: "warn",
  high: "warn",
  critical: "crit",
};

export function clock(timestamp: string | null | undefined): string {
  return timestamp ? timestamp.slice(11, 19) : "--:--:--";
}

/** Highest severity of evidence naming each asset or endpoint. */
function evidenceByEntity(telemetry: TelemetryEvent[]) {
  const worst = new Map<string, TelemetryEvent>();
  for (const event of telemetry) {
    const key = event.related_asset;
    if (!key) continue;
    const held = worst.get(key);
    if (!held || SEVERITY_RANK[event.severity] >= SEVERITY_RANK[held.severity]) {
      worst.set(key, event);
    }
  }
  return worst;
}

export function buildGraph(dashboard: Dashboard): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const evidence = evidenceByEntity(dashboard.telemetry);
  const nodes: GraphNode[] = [];

  for (const asset of dashboard.assets) {
    const layout = LAYOUT[asset.asset_id];
    if (!layout) continue;
    const hit = evidence.get(asset.asset_id);
    const rank = hit ? SEVERITY_RANK[hit.severity] : 0;
    const status: NodeStatus = asset.restricted
      ? "FLAGGED"
      : rank >= 4
        ? "CRITICAL"
        : rank >= 3
          ? "AFFECTED"
          : rank >= 2
            ? "FLAGGED"
            : "NOMINAL";
    nodes.push({
      id: asset.asset_id,
      name: layout.short,
      kind: layout.kind,
      status,
      chip: asset.restricted ? "PROTECTED" : asset.criticality.replace("_", " ").toUpperCase(),
      x: layout.x,
      y: layout.y,
      meta: [
        ["CRITICALITY", asset.criticality.toUpperCase()],
        ["STATUS", asset.status.toUpperCase()],
        ["EXPOSED", asset.exposed ? "YES" : "NO"],
        ["LAST EVIDENCE", hit ? `${hit.severity.toUpperCase()} ${clock(hit.timestamp)}` : "NONE"],
      ],
    });
  }

  for (const endpoint of dashboard.endpoints) {
    const layout = LAYOUT[endpoint.endpoint_id];
    if (!layout) continue;
    const hit = evidence.get(endpoint.endpoint_id);
    const rank = hit ? SEVERITY_RANK[hit.severity] : 0;
    const status: NodeStatus = endpoint.isolated
      ? "FLAGGED"
      : rank >= 4
        ? "CRITICAL"
        : rank >= 3
          ? "AFFECTED"
          : "NOMINAL";
    nodes.push({
      id: endpoint.endpoint_id,
      name: layout.short,
      kind: layout.kind,
      status,
      chip: endpoint.isolated ? "ISOLATED" : endpoint.status.toUpperCase(),
      x: layout.x,
      y: layout.y,
      meta: [
        ["HOST", endpoint.hostname],
        ["OWNER", endpoint.owner],
        ["ISOLATED", endpoint.isolated ? "YES" : "NO"],
        ["LAST EVIDENCE", hit ? `${hit.severity.toUpperCase()} ${clock(hit.timestamp)}` : "NONE"],
      ],
    });
  }

  const byId = new Map(nodes.map((n) => [n.id, n]));
  const edges = TRUST.filter((e) => byId.has(e.from) && byId.has(e.to)).map((edge) => {
    const a = byId.get(edge.from)!;
    const b = byId.get(edge.to)!;
    const hot = a.status === "CRITICAL" || b.status === "CRITICAL";
    const warm =
      a.status === "AFFECTED" || b.status === "AFFECTED" || (hot && b.status !== "CRITICAL");
    return {
      ...edge,
      kind: hot ? "target" : warm ? "attack" : "trust",
    } as GraphEdge;
  });

  return { nodes, edges };
}

/* ── right-hand intelligence panel ─────────────────────────────── */

export interface TimelineEntry {
  t: string;
  tag: string;
  text: string;
  tone: Tone;
  ref: string;
}

export function buildTimeline(telemetry: TelemetryEvent[], limit = 40): TimelineEntry[] {
  return telemetry.slice(-limit).map((event) => ({
    t: clock(event.timestamp),
    tag: event.source,
    text: event.message,
    tone: severityTone[event.severity],
    ref: event.related_asset ?? event.related_user ?? event.id,
  }));
}

export function riskBand(risk: number): { band: string; tone: Tone } {
  if (risk >= 70) return { band: "CRITICAL", tone: "crit" };
  if (risk >= 40) return { band: "ELEVATED", tone: "warn" };
  if (risk > 0) return { band: "GUARDED", tone: "ice" };
  return { band: "NOMINAL", tone: "good" };
}

/* ── agent lifecycle strip ─────────────────────────────────────── */

export type StageState = "COMPLETE" | "RUNNING" | "WAITING";

export const LIFECYCLE = ["OBSERVE", "DECIDE", "ACT", "EVALUATE", "ADAPT"] as const;

export function buildStages(
  events: AgentEvent[],
  currentPhase: string | null,
  running: boolean,
): { name: string; state: StageState }[] {
  const seen = new Set(events.map((e) => e.phase));
  const active = running ? currentPhase : null;
  return LIFECYCLE.map((name) => ({
    name,
    state: (name === active ? "RUNNING" : seen.has(name) ? "COMPLETE" : "WAITING") as StageState,
  }));
}

export const phaseTone: Record<string, Tone> = {
  OBSERVE: "ice",
  DECIDE: "idle",
  ACT: "warn",
  RESULT: "good",
  EVALUATE: "ice",
  ADAPT: "warn",
  FAILED: "crit",
  FINAL: "good",
  COMPLETE: "good",
};

export function environmentTone(status: string): Tone {
  if (status === "HEALTHY" || status === "CONTAINED") return "good";
  if (status === "ELEVATED") return "warn";
  if (status === "COMPROMISED") return "crit";
  return "idle";
}


/* ── fog of war: Training sees the estate, never the attack path ── */

/**
 * A node is described only by how much observable evidence names it — never by
 * what the Red Engine intends. Edges stay plain infrastructure trust links, so
 * no route is ever drawn for the trainee.
 */
export function buildTrainingGraph(dashboard: Dashboard): {
  nodes: GraphNode[];
  edges: GraphEdge[];
} {
  const counts = new Map<string, { hits: number; worst: number; at: string }>();
  for (const event of dashboard.telemetry) {
    const key = event.related_asset;
    if (!key) continue;
    const rank = SEVERITY_RANK[event.severity];
    const held = counts.get(key) ?? { hits: 0, worst: 0, at: "" };
    counts.set(key, {
      hits: held.hits + (rank >= 2 ? 1 : 0),
      worst: Math.max(held.worst, rank),
      at: rank >= held.worst ? event.timestamp : held.at,
    });
  }

  const { nodes, edges } = buildGraph(dashboard);
  const fogged = nodes.map((node) => {
    const seen = counts.get(node.id);
    const isolated =
      dashboard.endpoints.find((e) => e.endpoint_id === node.id)?.isolated ?? false;
    const restricted = dashboard.assets.find((a) => a.asset_id === node.id)?.restricted ?? false;

    let status: NodeStatus = "NOMINAL";
    let label = "NOMINAL";
    if (isolated) {
      status = "FLAGGED";
      label = "ISOLATED";
    } else if (restricted) {
      status = "FLAGGED";
      label = "DEGRADED";
    } else if (seen && seen.hits >= 2 && seen.worst >= 3) {
      status = "AFFECTED";
      label = "SUSPICIOUS";
    } else if (seen && seen.hits >= 1) {
      status = "FLAGGED";
      label = "ACTIVITY DETECTED";
    }

    return {
      ...node,
      status,
      statusLabel: label,
      chip: node.chip,
      meta: [
        node.meta[0],
        node.meta[1],
        ["EVIDENCE ITEMS", String(seen?.hits ?? 0)],
        ["LAST OBSERVED", seen?.at ? clock(seen.at) : "NONE"],
      ] as [string, string][],
    };
  });

  return { nodes: fogged, edges: edges.map((e) => ({ ...e, kind: "trust" as const })) };
}
