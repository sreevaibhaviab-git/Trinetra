/**
 * Typed client for the Trinetra FastAPI backend.
 *
 * The backend owns every decision: range state, mode enforcement, the Blue tool
 * allowlist and the safety governor. This file only moves JSON.
 */

const BASE =
  process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "") ?? "http://127.0.0.1:8000";

export type Mode = "AUTONOMOUS" | "COPILOT" | "TRAINING";

export type TelemetrySource =
  | "IDENTITY"
  | "ENDPOINT"
  | "SAAS"
  | "CLOUD"
  | "NETWORK"
  | "DATA";

export interface TelemetryEvent {
  id: string;
  timestamp: string;
  source: TelemetrySource;
  category: string;
  event_type: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  message: string;
  related_user: string | null;
  related_asset: string | null;
  metadata: Record<string, unknown>;
}

export interface AgentEvent {
  step: number;
  phase: "OBSERVE" | "DECIDE" | "ACT" | "EVALUATE" | "ADAPT" | "RESULT" | "FAILED" | "FINAL" | "COMPLETE";
  message: string;
  tool?: string;
  target?: string;
  success?: boolean;
}

export interface Threat {
  type: string;
  target: string;
  detail: string;
}

export interface Recommendation {
  id: string;
  tool_name: string;
  arguments: Record<string, unknown>;
  impact: "LOW" | "MEDIUM" | "HIGH";
  reason: string;
  proposed_at: string;
  status: "PENDING" | "APPROVED" | "REJECTED" | "EXECUTED" | "EXPIRED";
  result: Record<string, unknown> | null;
}

export interface TrainingDebrief {
  score: number;
  grade: string;
  contained: boolean;
  final_risk: number;
  final_resilience: number;
  actions_taken: number;
  high_impact_actions: number;
  failed_actions: number;
  tools_used: number;
  feedback: string[];
}

export interface TrainingView {
  active: boolean;
  started_at: string;
  starting_risk: number;
  starting_resilience: number;
  elapsed_simulation_time: string;
  actions_taken: number;
  tools_used: number;
  actions?: TrainingAction[];
  debrief: TrainingDebrief | null;
}

export interface TrainingAction {
  timestamp: string;
  tool: string;
  arguments: Record<string, unknown>;
  read_only: boolean;
  impact: string;
  success: boolean;
}

export interface Dashboard {
  mode: Mode;
  copilot: { pending_recommendation: Recommendation | null; history: number };
  training: TrainingView | null;
  environment: {
    scenario: string;
    status: string;
    simulation_time: string;
    resilience_score: number;
    risk_score: number;
  };
  attack: {
    status: string;
    scenario: string | null;
    simulation_status: string;
    resilience_score: number;
    telemetry_events: number;
    pending_events: number;
  };
  incident: {
    contained: boolean;
    remaining_threats: Threat[];
    identity_risk: number;
    endpoint_risk: number;
    saas_risk: number;
    cloud_risk: number;
    data_risk: number;
  };
  assets: {
    asset_id: string;
    name: string;
    criticality: string;
    status: string;
    restricted: boolean;
    exposed: boolean;
  }[];
  endpoints: {
    endpoint_id: string;
    hostname: string;
    owner: string;
    status: string;
    isolated: boolean;
  }[];
  telemetry: TelemetryEvent[];
  agent: {
    status: string;
    running: boolean;
    current_phase: string | null;
    current_action: string | null;
    steps: number;
    adaptations: number;
    events: AgentEvent[];
  };
  safety: {
    simulation_status: string;
    emergency_stopped: boolean;
    emergency_stop_reason: string | null;
    critical_failure_threshold: number;
  };
}

export interface AgentRunResult {
  status: string;
  contained: boolean;
  risk_score: number;
  resilience_score: number;
  steps: number;
  actions: { tool: string; target: string; step: number }[];
  failed_actions: { tool: string; target: string; error: string }[];
  adaptations: number;
  adaptation_notes: string[];
  events: AgentEvent[];
  outcome: string;
}

export interface BlueTool {
  name: string;
  description: string;
  category: string;
  read_only: boolean;
  impact: "NONE" | "LOW" | "MEDIUM" | "HIGH";
}

/** A backend refusal, carrying the status so the UI can name the condition. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }

  /** True when the backend is unreachable rather than refusing. */
  get offline() {
    return this.status === 0;
  }
}

async function request<T>(
  path: string,
  init?: { method?: string; body?: unknown; signal?: AbortSignal },
): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${BASE}${path}`, {
      method: init?.method ?? "GET",
      headers: init?.body ? { "content-type": "application/json" } : undefined,
      body: init?.body ? JSON.stringify(init.body) : undefined,
      signal: init?.signal,
      cache: "no-store",
    });
  } catch {
    throw new ApiError(0, "BACKEND OFFLINE — cannot reach the range API.");
  }

  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = (await response.json()) as { detail?: unknown };
      if (typeof body.detail === "string") detail = body.detail;
      else if (Array.isArray(body.detail)) detail = "INVALID TOOL ARGUMENTS";
    } catch {
      /* non-JSON error body — keep the status line */
    }
    throw new ApiError(response.status, detail);
  }

  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export const api = {
  health: () => request<{ status: string; simulation_time: string }>("/health"),
  dashboard: (signal?: AbortSignal) => request<Dashboard>("/dashboard", { signal }),
  rangeState: () => request<Record<string, unknown>>("/range/state"),

  initialize: () => request<{ initialized: boolean }>("/range/initialize", { method: "POST" }),
  advance: (seconds: number) =>
    request<{ simulation_time: string; events_processed: number }>("/range/advance", {
      method: "POST",
      body: { seconds },
    }),
  telemetry: (params: { category?: string; severity?: string; limit?: number } = {}) => {
    const query = new URLSearchParams();
    if (params.category) query.set("category", params.category);
    if (params.severity) query.set("severity", params.severity);
    if (params.limit) query.set("limit", String(params.limit));
    const suffix = query.toString();
    return request<TelemetryEvent[]>(`/range/telemetry${suffix ? `?${suffix}` : ""}`);
  },

  getMode: () => request<{ mode: Mode; available: Mode[] }>("/mode"),
  setMode: (mode: Mode) => request<{ mode: Mode }>("/mode", { method: "POST", body: { mode } }),

  launchAttack: (scenario = "operation_maya") =>
    request<{ launched: string }>("/attack/launch", { method: "POST", body: { scenario } }),
  attackStatus: () => request<Dashboard["attack"]>("/attack/status"),
  stopAttack: () => request<{ stopped: boolean }>("/attack/stop", { method: "POST" }),

  pause: () => request<{ simulation_status: string }>("/simulation/pause", { method: "POST" }),
  resume: () => request<{ simulation_status: string }>("/simulation/resume", { method: "POST" }),
  emergencyStop: (reason: string) =>
    request<{ status: string; cancelled_events: string[]; telemetry_preserved: number }>(
      "/simulation/emergency-stop",
      { method: "POST", body: { reason } },
    ),
  restoreBaseline: () =>
    request<{ simulation_status: string }>("/simulation/restore-baseline", { method: "POST" }),

  runAgent: (goal: string) =>
    request<AgentRunResult>("/agent/run", { method: "POST", body: { goal } }),

  runCopilot: (goal: string) =>
    request<{ status: string; recommendation: Recommendation | null; rationale: string }>(
      "/copilot/run",
      { method: "POST", body: { goal } },
    ),
  approve: (id: string) =>
    request<{ executed: boolean; recommendation: Recommendation }>(
      `/copilot/recommendation/${id}/approve`,
      { method: "POST" },
    ),
  reject: (id: string) =>
    request<{ executed: boolean; recommendation: Recommendation }>(
      `/copilot/recommendation/${id}/reject`,
      { method: "POST" },
    ),

  blueTools: () => request<BlueTool[]>("/blue/tools"),
  callBlueTool: (name: string, args: Record<string, unknown>) =>
    request<{ tool: string; impact: string; result: unknown }>(`/blue/tools/${name}`, {
      method: "POST",
      body: { arguments: args },
    }),

  trainingStart: () => request<TrainingView>("/training/start", { method: "POST" }),
  trainingStatus: () => request<TrainingView>("/training/status"),
  trainingFinish: () => request<TrainingView>("/training/finish", { method: "POST" }),
};

export const DEFAULT_GOAL =
  "Keep Nexora operational. Investigate the active incident, contain confirmed threats, " +
  "protect critical assets, and minimize unnecessary disruption.";
