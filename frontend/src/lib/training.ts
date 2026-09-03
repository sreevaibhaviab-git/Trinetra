/**
 * The analyst-facing vocabulary for Training mode.
 *
 * The trainee never sees a backend function name, an argument object or a
 * scenario fact. This file maps human labels onto the existing Blue tools,
 * decides which columns each kind of evidence shows, and pulls selectable
 * entities out of whatever the tools return — so containment targets can only
 * come from evidence the trainee actually looked at.
 */

import type { Dashboard } from "@/src/lib/api";

/* ── human labels for the allowlisted tools ───────────────────── */

export const TOOL_LABELS: Record<string, string> = {
  get_recent_logins: "Recent Logins",
  get_active_sessions: "Active Sessions",
  get_registered_devices: "Registered Devices",
  get_oauth_activity: "OAuth Activity",
  get_mailbox_activity: "Mailbox Activity",
  get_mailbox_rules: "Mailbox Rules",
  get_cloud_drive_activity: "Cloud Drive Activity",
  get_endpoint_status: "Endpoint Status",
  get_process_activity: "Process Activity",
  get_file_activity: "File Activity",
  get_persistence_entries: "Persistence",
  get_network_activity: "Network Connections",
  get_dns_activity: "DNS Activity",
  get_github_activity: "GitHub Activity",
  get_cloud_activity: "Cloud Activity",
  get_asset_status: "Asset Status",
  get_data_access_activity: "Data Access",
  revoke_token: "Revoke OAuth Token",
  terminate_session: "Terminate Session",
  disable_user: "Disable User",
  remove_registered_device: "Remove Registered Device",
  remove_mailbox_rule: "Remove Mailbox Rule",
  isolate_endpoint: "Isolate Endpoint",
  terminate_synthetic_process: "Terminate Process",
  remove_persistence_entry: "Remove Persistence",
  block_simulated_connection: "Block Connection",
  block_ip: "Block IP",
  restrict_asset: "Restrict Asset",
  protect_data_asset: "Protect Data Asset",
};

/** What a tool needs before it can be run, if anything. */
export type Scope = "none" | "user" | "endpoint" | "asset";

export interface InvestigationItem {
  label: string;
  tool: string;
  scope: Scope;
}

export const INVESTIGATION_GROUPS: { group: string; items: InvestigationItem[] }[] = [
  {
    group: "IDENTITY",
    items: [
      { label: "Recent Logins", tool: "get_recent_logins", scope: "user" },
      { label: "Active Sessions", tool: "get_active_sessions", scope: "user" },
      { label: "Registered Devices", tool: "get_registered_devices", scope: "user" },
      { label: "OAuth Activity", tool: "get_oauth_activity", scope: "user" },
    ],
  },
  {
    group: "SAAS",
    items: [
      { label: "Mailbox Activity", tool: "get_mailbox_activity", scope: "user" },
      { label: "Mailbox Rules", tool: "get_mailbox_rules", scope: "user" },
      { label: "Cloud Drive Activity", tool: "get_cloud_drive_activity", scope: "user" },
    ],
  },
  {
    group: "ENDPOINT",
    items: [
      { label: "Endpoint Status", tool: "get_endpoint_status", scope: "endpoint" },
      { label: "Process Activity", tool: "get_process_activity", scope: "endpoint" },
      { label: "File Activity", tool: "get_file_activity", scope: "endpoint" },
      { label: "Persistence", tool: "get_persistence_entries", scope: "endpoint" },
      { label: "Network Connections", tool: "get_network_activity", scope: "endpoint" },
      { label: "DNS Activity", tool: "get_dns_activity", scope: "endpoint" },
    ],
  },
  {
    group: "CLOUD & DATA",
    items: [
      { label: "GitHub Activity", tool: "get_github_activity", scope: "user" },
      { label: "Cloud Activity", tool: "get_cloud_activity", scope: "user" },
      { label: "Asset Status", tool: "get_asset_status", scope: "asset" },
      { label: "Data Access", tool: "get_data_access_activity", scope: "asset" },
    ],
  },
];

/* ── containment, grouped by the domain it acts on ────────────── */

export type TargetKind =
  | "token"
  | "session"
  | "user"
  | "device"
  | "rule"
  | "endpoint"
  | "process"
  | "persistence"
  | "connection"
  | "ip"
  | "asset";

export interface ResponseAction {
  label: string;
  tool: string;
  kind: TargetKind;
  note: string;
}

export const RESPONSE_GROUPS: { group: string; items: ResponseAction[] }[] = [
  {
    group: "IDENTITY RESPONSE",
    items: [
      { label: "Revoke OAuth Token", tool: "revoke_token", kind: "token",
        note: "The application holding this token loses access immediately." },
      { label: "Terminate Session", tool: "terminate_session", kind: "session",
        note: "This action may interrupt an active user session." },
      { label: "Disable User", tool: "disable_user", kind: "user",
        note: "The account loses all access until it is re-enabled." },
      { label: "Remove Registered Device", tool: "remove_registered_device", kind: "device",
        note: "Unenrols the device and drops sessions bound to it." },
    ],
  },
  {
    group: "SAAS RESPONSE",
    items: [
      { label: "Remove Mailbox Rule", tool: "remove_mailbox_rule", kind: "rule",
        note: "Restores normal delivery for messages the rule matched." },
    ],
  },
  {
    group: "ENDPOINT RESPONSE",
    items: [
      { label: "Isolate Endpoint", tool: "isolate_endpoint", kind: "endpoint",
        note: "The workstation is cut off the network; its user cannot work." },
      { label: "Terminate Process", tool: "terminate_synthetic_process", kind: "process",
        note: "Stops the process on the endpoint." },
      { label: "Remove Persistence", tool: "remove_persistence_entry", kind: "persistence",
        note: "Removes the startup item from the endpoint." },
    ],
  },
  {
    group: "NETWORK RESPONSE",
    items: [
      { label: "Block Connection", tool: "block_simulated_connection", kind: "connection",
        note: "Blocks one socket at the host firewall." },
      { label: "Block IP", tool: "block_ip", kind: "ip",
        note: "Blocks the source address at the network edge." },
    ],
  },
  {
    group: "ASSET RESPONSE",
    items: [
      { label: "Restrict Asset", tool: "restrict_asset", kind: "asset",
        note: "Production access is restricted; dependent services may degrade." },
      { label: "Protect Data Asset", tool: "protect_data_asset", kind: "asset",
        note: "An emergency policy refuses further access to the data store." },
    ],
  },
];

/* ── evidence columns ─────────────────────────────────────────── */

export interface Column {
  path: string;
  label: string;
}

export const COLUMNS: Record<string, Column[]> = {
  get_recent_logins: [
    { path: "timestamp", label: "TIME" },
    { path: "user_id", label: "USER" },
    { path: "geo.city", label: "LOCATION" },
    { path: "source_ip", label: "SOURCE" },
    { path: "device_id", label: "DEVICE" },
    { path: "auth_method", label: "AUTH" },
    { path: "mfa_satisfied", label: "MFA" },
    { path: "outcome", label: "RESULT" },
  ],
  get_active_sessions: [
    { path: "session_id", label: "SESSION" },
    { path: "user_id", label: "USER" },
    { path: "source_ip", label: "SOURCE" },
    { path: "geo.city", label: "LOCATION" },
    { path: "device_id", label: "DEVICE" },
    { path: "device_managed", label: "MANAGED" },
    { path: "network_type", label: "NETWORK" },
    { path: "status", label: "STATUS" },
  ],
  get_registered_devices: [
    { path: "device_id", label: "DEVICE" },
    { path: "owner", label: "OWNER" },
    { path: "platform", label: "PLATFORM" },
    { path: "managed", label: "MANAGED" },
    { path: "compliant", label: "COMPLIANT" },
    { path: "enrolled_at", label: "ENROLLED" },
  ],
  oauth_grants: [
    { path: "grant_id", label: "GRANT" },
    { path: "user_id", label: "USER" },
    { path: "client_name", label: "APPLICATION" },
    { path: "scopes", label: "SCOPES" },
    { path: "first_party", label: "FIRST PARTY" },
    { path: "granted_at", label: "GRANTED" },
  ],
  oauth_tokens: [
    { path: "token_id", label: "TOKEN" },
    { path: "owner", label: "OWNER" },
    { path: "client_name", label: "APPLICATION" },
    { path: "permissions", label: "SCOPES" },
    { path: "consent_prompt_shown", label: "CONSENT" },
    { path: "issued_from_ip", label: "ISSUED FROM" },
    { path: "status", label: "STATUS" },
  ],
  oauth_events: [
    { path: "timestamp", label: "TIME" },
    { path: "user_id", label: "USER" },
    { path: "event_type", label: "EVENT" },
    { path: "source_ip", label: "SOURCE" },
    { path: "mfa_satisfied", label: "MFA" },
    { path: "outcome", label: "RESULT" },
  ],
  get_mailbox_activity: [
    { path: "timestamp", label: "TIME" },
    { path: "mailbox", label: "MAILBOX" },
    { path: "event_type", label: "EVENT" },
    { path: "subject", label: "SUBJECT" },
    { path: "sender", label: "SENDER" },
    { path: "outcome", label: "RESULT" },
  ],
  get_mailbox_rules: [
    { path: "rule_id", label: "RULE" },
    { path: "mailbox", label: "MAILBOX" },
    { path: "name", label: "NAME" },
    { path: "actions", label: "ACTIONS" },
    { path: "created_by", label: "CREATED BY" },
    { path: "created_at", label: "CREATED" },
  ],
  get_cloud_drive_activity: [
    { path: "timestamp", label: "TIME" },
    { path: "actor", label: "ACTOR" },
    { path: "file_name", label: "FILE" },
    { path: "action", label: "ACTION" },
    { path: "sensitivity", label: "CLASS" },
    { path: "source_ip", label: "SOURCE" },
  ],
  get_process_activity: [
    { path: "pid", label: "PID" },
    { path: "name", label: "PROCESS" },
    { path: "user", label: "USER" },
    { path: "signed", label: "SIGNED" },
    { path: "started_at", label: "STARTED" },
    { path: "status", label: "STATUS" },
  ],
  files: [
    { path: "name", label: "FILE" },
    { path: "path", label: "PATH" },
    { path: "sensitivity", label: "CLASS" },
    { path: "size", label: "SIZE" },
    { path: "modified_at", label: "MODIFIED" },
    { path: "quarantined", label: "QUARANTINED" },
  ],
  downloads: [
    { path: "file_name", label: "FILE" },
    { path: "source_domain", label: "SOURCE" },
    { path: "downloaded_at", label: "DOWNLOADED" },
    { path: "size", label: "SIZE" },
  ],
  get_persistence_entries: [
    { path: "entry_id", label: "ENTRY" },
    { path: "mechanism", label: "MECHANISM" },
    { path: "name", label: "NAME" },
    { path: "target", label: "TARGET" },
    { path: "enabled", label: "ENABLED" },
    { path: "created_at", label: "CREATED" },
  ],
  connections: [
    { path: "connection_id", label: "CONNECTION" },
    { path: "process", label: "PROCESS" },
    { path: "remote_address", label: "REMOTE" },
    { path: "remote_port", label: "PORT" },
    { path: "state", label: "STATE" },
    { path: "bytes_out", label: "BYTES OUT" },
  ],
  transfers: [
    { path: "timestamp", label: "TIME" },
    { path: "source_endpoint", label: "ENDPOINT" },
    { path: "destination_domain", label: "DESTINATION" },
    { path: "bytes_out", label: "BYTES OUT" },
    { path: "classification", label: "CLASS" },
  ],
  get_dns_activity: [
    { path: "timestamp", label: "TIME" },
    { path: "source_endpoint", label: "ENDPOINT" },
    { path: "query", label: "QUERY" },
    { path: "resolved_ip", label: "RESOLVED" },
    { path: "category", label: "CATEGORY" },
    { path: "action", label: "ACTION" },
  ],
  cloud_events: [
    { path: "timestamp", label: "TIME" },
    { path: "actor", label: "ACTOR" },
    { path: "asset_id", label: "ASSET" },
    { path: "action", label: "ACTION" },
    { path: "resource", label: "RESOURCE" },
    { path: "source_ip", label: "SOURCE" },
    { path: "outcome", label: "RESULT" },
  ],
};

COLUMNS.get_github_activity = COLUMNS.cloud_events;
COLUMNS.get_cloud_activity = COLUMNS.cloud_events;

export function valueAt(row: unknown, path: string): unknown {
  return path.split(".").reduce<unknown>((acc, key) => {
    if (acc && typeof acc === "object") return (acc as Record<string, unknown>)[key];
    return undefined;
  }, row);
}

export function display(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "boolean") return value ? "YES" : "NO";
  if (Array.isArray(value)) return value.join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  const text = String(value);
  // ISO timestamps read better as range clock time
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(text)) return text.slice(11, 19);
  return text;
}

/** Values a SOC analyst would look twice at — never a verdict, just unusual. */
export function isNotable(path: string, value: unknown): boolean {
  if (typeof value === "boolean") {
    if (["managed", "compliant", "device_managed", "consent_prompt_shown", "first_party",
         "mfa_satisfied", "signed"].includes(path.split(".").pop() ?? "")) {
      return value === false;
    }
    return false;
  }
  const text = String(value ?? "").toLowerCase();
  return (
    text === "denied" ||
    text === "hosting_provider" ||
    text === "uncategorised" ||
    text === "restricted-pii" ||
    text === "restricted" ||
    text.includes("unmanaged") ||
    text === "critical" ||
    text === "high"
  );
}

/* ── entities the trainee has actually seen ───────────────────── */

export interface Entity {
  kind: TargetKind;
  id: string;
  label: string;
  detail: string;
  extra?: Record<string, unknown>;
}

const EMPTY = new Set(["", "null", "undefined", "none", "-"]);

function push(map: Map<string, Entity>, entity: Entity) {
  if (!entity.id || EMPTY.has(entity.id.toLowerCase())) return;
  map.set(`${entity.kind}:${entity.id}`, entity);
}

/** Pull selectable entities out of one tool result. Nothing is judged here. */
export function extractEntities(tool: string, payload: unknown): Entity[] {
  const found = new Map<string, Entity>();
  const rows: Record<string, unknown>[] = [];

  const collect = (value: unknown) => {
    if (Array.isArray(value)) rows.push(...(value as Record<string, unknown>[]));
    else if (value && typeof value === "object") {
      const obj = value as Record<string, unknown>;
      let nested = false;
      for (const inner of Object.values(obj)) {
        if (Array.isArray(inner)) {
          rows.push(...(inner as Record<string, unknown>[]));
          nested = true;
        }
      }
      if (!nested) rows.push(obj);
    }
  };
  collect(payload);

  for (const row of rows) {
    if (!row || typeof row !== "object") continue;
    const get = (k: string) => (row[k] === undefined ? undefined : String(row[k]));

    const user = get("user_id") ?? get("owner") ?? get("actor");
    if (user && !user.includes("@") && !user.includes("-")) {
      push(found, { kind: "user", id: user, label: user, detail: "Identity" });
    }
    const session = get("session_id");
    if (session) {
      push(found, {
        kind: "session",
        id: session,
        label: session,
        detail: [row.user_id, row.device_managed === false ? "unmanaged device" : null, row.status]
          .filter(Boolean)
          .join(" · "),
      });
    }
    const device = get("device_id");
    if (device && device !== "null") {
      push(found, {
        kind: "device",
        id: device,
        label: device,
        detail: [row.owner ?? row.user_id, row.managed === false ? "unmanaged" : null]
          .filter(Boolean)
          .join(" · "),
      });
    }
    const token = get("token_id");
    if (token) {
      push(found, {
        kind: "token",
        id: token,
        label: token,
        detail: [row.owner, row.client_name, row.status].filter(Boolean).join(" · "),
      });
    }
    const rule = get("rule_id");
    if (rule) {
      push(found, {
        kind: "rule",
        id: rule,
        label: rule,
        detail: [row.mailbox, Array.isArray(row.actions) ? row.actions.join(", ") : null]
          .filter(Boolean)
          .join(" · "),
      });
    }
    const ip = get("source_ip") ?? get("issued_from_ip");
    if (ip) {
      push(found, {
        kind: "ip",
        id: ip,
        label: ip,
        detail: String(valueAt(row, "geo.city") ?? row.network_type ?? "network source"),
      });
    }
    const connection = get("connection_id");
    if (connection) {
      push(found, {
        kind: "connection",
        id: connection,
        label: connection,
        detail: [row.process, row.remote_address].filter(Boolean).join(" · "),
      });
    }
    const entry = get("entry_id");
    if (entry) {
      push(found, {
        kind: "persistence",
        id: entry,
        label: entry,
        detail: [row.mechanism, row.name].filter(Boolean).join(" · "),
      });
    }
    if (row.pid !== undefined) {
      push(found, {
        kind: "process",
        id: String(row.pid),
        label: `${row.name ?? "process"} (${row.pid})`,
        detail: String(row.user ?? ""),
        extra: { pid: row.pid },
      });
    }
    const endpoint = get("endpoint_id") ?? get("source_endpoint");
    if (endpoint) {
      push(found, {
        kind: "endpoint",
        id: endpoint,
        label: endpoint,
        detail: String(row.hostname ?? row.owner ?? "endpoint"),
      });
    }
    const asset = get("asset_id");
    if (asset) {
      push(found, { kind: "asset", id: asset, label: asset, detail: "Cloud asset" });
    }
  }

  // Processes belong to the endpoint the console was scoped to.
  if (tool !== "get_process_activity") {
    for (const key of [...found.keys()]) if (key.startsWith("process:")) found.delete(key);
  }
  return [...found.values()];
}

/* ── analyst-facing posture, never the raw score ──────────────── */

export function posture(risk: number): { band: string; tone: "good" | "warn" | "crit" | "ice" } {
  if (risk >= 70) return { band: "CRITICAL", tone: "crit" };
  if (risk >= 40) return { band: "HIGH", tone: "crit" };
  if (risk >= 15) return { band: "ELEVATED", tone: "warn" };
  return { band: "NORMAL", tone: "good" };
}

export function incidentState(
  dashboard: Dashboard,
  declared: boolean,
  actionsTaken: number,
): string {
  if (declared && dashboard.incident.contained) return "CONTAINMENT DECLARED";
  if (dashboard.incident.contained && actionsTaken > 0) return "STABILIZING";
  if (actionsTaken > 0) return "UNDER INVESTIGATION";
  return "UNRESOLVED";
}
