/**
 * Synthetic operational data for the TRINETRA console shell.
 * Nothing here talks to a backend — it is a fixed, deterministic snapshot of
 * incident INC-2026-0902-001 at 17:38:42 IST.
 */

export type Tone = "ice" | "good" | "warn" | "crit" | "idle";

export const incident = {
  id: "INC-2026-0902-001",
  environment: "NEXORA SYSTEMS",
  posture: "LIVE INCIDENT",
  clock: "17:38:42",
  zone: "IST",
  threatState: "CRITICAL",
  agentState: "AGENT ONLINE",
  region: "ap-south-1",
  scenario: "credential_compromise",
} as const;

/* ── left panel ─────────────────────────────────────────────── */

export const objective =
  "Investigate the current anomaly, protect production systems and avoid customer-facing downtime.";

export const commanderMeta = [
  { k: "MODE", v: "AUTONOMOUS" },
  { k: "LOOP", v: "04" },
  { k: "LATENCY", v: "312MS" },
] as const;

export type JournalPhase = "OBSERVE" | "DECIDE" | "ACTION" | "RESULT";

export interface JournalEntry {
  t: string;
  phase: JournalPhase;
  message: string;
  tone: Tone;
  ref?: string;
}

export const journal: JournalEntry[] = [
  {
    t: "17:33:11",
    phase: "OBSERVE",
    message: "Authentication anomaly detected.",
    tone: "ice",
    ref: "idp/sig-014",
  },
  {
    t: "17:33:19",
    phase: "DECIDE",
    message: "Identity activity requires correlation before containment.",
    tone: "idle",
  },
  {
    t: "17:33:24",
    phase: "ACTION",
    message: "Query authentication history.",
    tone: "warn",
    ref: "q-0231",
  },
  {
    t: "17:33:58",
    phase: "RESULT",
    message: "Impossible-travel event associated with Arjun Rao.",
    tone: "crit",
    ref: "auth-0004",
  },
  {
    t: "17:34:40",
    phase: "OBSERVE",
    message: "OAuth grant issued 19s after client registration.",
    tone: "ice",
    ref: "oauth-8492",
  },
  {
    t: "17:35:26",
    phase: "DECIDE",
    message: "Source-control read is in scope; defer revocation pending blast radius.",
    tone: "idle",
  },
  {
    t: "17:36:02",
    phase: "ACTION",
    message: "Enumerate token permissions and downstream trust.",
    tone: "warn",
    ref: "q-0234",
  },
  {
    t: "17:37:12",
    phase: "RESULT",
    message: "Token carries aws.assume_role — privilege path to production confirmed.",
    tone: "crit",
    ref: "cloud-0004",
  },
  {
    t: "17:38:44",
    phase: "OBSERVE",
    message: "Bulk read against customer store refused by endpoint policy.",
    tone: "ice",
    ref: "cloud-0005",
  },
];

/* ── centre graph ───────────────────────────────────────────── */

export type NodeStatus = "NOMINAL" | "FLAGGED" | "AFFECTED" | "CRITICAL" | "EXTERNAL";

export interface GraphNode {
  id: string;
  name: string;
  kind: string;
  status: NodeStatus;
  chip: string;
  x: number; // 0-1 of canvas width
  y: number; // 0-1 of canvas height
  meta: [string, string][];
}

export const graphNodes: GraphNode[] = [
  {
    id: "net-ext",
    name: "Internet",
    kind: "EXTERNAL EDGE",
    status: "EXTERNAL",
    chip: "185.220.101.47",
    x: 0.14,
    y: 0.15,
    meta: [
      ["ASN", "AS49505"],
      ["INGRESS", "185.220.101.47"],
      ["REPUTATION", "HOSTING / LOW"],
    ],
  },
  {
    id: "prn-arjun",
    name: "Arjun Rao",
    kind: "PRINCIPAL",
    status: "FLAGGED",
    chip: "2 GEOS",
    x: 0.14,
    y: 0.56,
    meta: [
      ["ROLE", "DEVOPS ENGINEER"],
      ["SESSIONS", "02 ACTIVE"],
      ["ENTITLEMENT", "PRIVILEGED"],
    ],
  },
  {
    id: "idp",
    name: "Identity Provider",
    kind: "IDENTITY",
    status: "AFFECTED",
    chip: "RISK 91",
    x: 0.35,
    y: 0.34,
    meta: [
      ["TENANT", "nexora.idp"],
      ["MFA", "COOKIE-SKIPPED"],
      ["RISK", "91 / 100"],
    ],
  },
  {
    id: "github",
    name: "GitHub",
    kind: "SOURCE CONTROL",
    status: "AFFECTED",
    chip: "412 MB",
    x: 0.61,
    y: 0.13,
    meta: [
      ["ORG", "nexora"],
      ["CLONES", "3 PRIVATE REPOS"],
      ["EGRESS", "412 MB"],
    ],
  },
  {
    id: "aws",
    name: "AWS",
    kind: "CLOUD ACCOUNT",
    status: "AFFECTED",
    chip: "ADMIN ROLE",
    x: 0.61,
    y: 0.46,
    meta: [
      ["ACCOUNT", "418322947610"],
      ["ROLE", "NexoraProdAdmin"],
      ["PRIOR USE", "0 / 180D"],
    ],
  },
  {
    id: "api-gw",
    name: "API Gateway",
    kind: "NETWORK EDGE",
    status: "NOMINAL",
    chip: "1.24K RPS",
    x: 0.35,
    y: 0.79,
    meta: [
      ["RPS", "1.24K"],
      ["POLICY", "ENFORCED"],
      ["P99", "84 MS"],
    ],
  },
  {
    id: "prod",
    name: "Production Server",
    kind: "COMPUTE",
    status: "NOMINAL",
    chip: "3 DENIED",
    x: 0.61,
    y: 0.79,
    meta: [
      ["HOST", "prod-app-01"],
      ["SSH", "3 DENIED"],
      ["LOAD", "0.42"],
    ],
  },
  {
    id: "cust-db",
    name: "Customer Database",
    kind: "DATA STORE",
    status: "CRITICAL",
    chip: "PII · DENIED",
    x: 0.87,
    y: 0.63,
    meta: [
      ["CLUSTER", "nexora-customers"],
      ["CLASS", "RESTRICTED-PII"],
      ["LAST ATTEMPT", "DENIED 17:38:42"],
    ],
  },
];

export interface GraphEdge {
  from: string;
  to: string;
  kind: "trust" | "attack" | "target";
  label?: string;
}

export const graphEdges: GraphEdge[] = [
  { from: "net-ext", to: "prn-arjun", kind: "attack", label: "SESSION" },
  { from: "prn-arjun", to: "idp", kind: "attack", label: "AUTH" },
  { from: "idp", to: "github", kind: "attack", label: "OAUTH" },
  { from: "idp", to: "aws", kind: "attack", label: "ASSUME" },
  { from: "aws", to: "cust-db", kind: "target", label: "QUERY" },
  { from: "net-ext", to: "api-gw", kind: "trust" },
  { from: "api-gw", to: "prod", kind: "trust" },
  { from: "aws", to: "prod", kind: "trust" },
  { from: "prod", to: "cust-db", kind: "trust" },
];

export const graphStats = [
  { k: "ASSETS", v: "08" },
  { k: "AFFECTED", v: "03" },
  { k: "CRITICAL PATH", v: "01" },
] as const;

export const graphFooter = [
  { k: "REGION", v: "ap-south-1" },
  { k: "IDENTITIES", v: "03" },
  { k: "ACTIVE CONNECTIONS", v: "12" },
  { k: "EDGE POLICY", v: "ENFORCED" },
  { k: "TELEMETRY", v: "1.2K EV/S" },
] as const;

/* ── right panel ────────────────────────────────────────────── */

export const threat = {
  score: 92,
  band: "CRITICAL",
  facets: [
    { k: "BLAST RADIUS", v: "4 ASSETS" },
    { k: "DWELL", v: "07M 28S" },
    { k: "EXPOSURE", v: "PII" },
  ],
} as const;

export interface TimelineEntry {
  t: string;
  tag: string;
  text: string;
  tone: Tone;
  ref: string;
}

export const timeline: TimelineEntry[] = [
  {
    t: "17:31:14",
    tag: "AUTH",
    text: "Legitimate Bangalore login",
    tone: "good",
    ref: "auth-0003",
  },
  {
    t: "17:33:02",
    tag: "IDENTITY",
    text: "Suspicious Moscow authentication",
    tone: "crit",
    ref: "auth-0004",
  },
  {
    t: "17:34:21",
    tag: "TOKEN",
    text: "Privileged OAuth token created",
    tone: "warn",
    ref: "oauth-8492",
  },
  {
    t: "17:35:11",
    tag: "SOURCE",
    text: "GitHub repository accessed",
    tone: "warn",
    ref: "cloud-0003",
  },
  {
    t: "17:37:04",
    tag: "CLOUD",
    text: "AWS privileged role assumed",
    tone: "crit",
    ref: "cloud-0004",
  },
  {
    t: "17:38:42",
    tag: "DATA",
    text: "Customer database access attempted",
    tone: "crit",
    ref: "cloud-0005",
  },
];

export const hypothesis = {
  primary: "Credential compromise with possible cloud lateral movement.",
  confidence: 86,
  alternatives: [
    { text: "Insider misuse of standing privilege", pct: 9 },
    { text: "Automation misconfiguration", pct: 5 },
  ],
} as const;

/* ── bottom strip ───────────────────────────────────────────── */

export type StageState = "COMPLETE" | "RUNNING" | "WAITING";

export const stages: { name: string; state: StageState }[] = [
  { name: "OBSERVE", state: "COMPLETE" },
  { name: "DECIDE", state: "COMPLETE" },
  { name: "ACT", state: "RUNNING" },
  { name: "EVALUATE", state: "WAITING" },
  { name: "ADAPT", state: "WAITING" },
];

export const currentOperation = "INSPECTING OAUTH TOKEN PERMISSIONS";

export const executionMetrics = [
  { k: "INCIDENTS", v: "01" },
  { k: "ASSETS", v: "08" },
  { k: "ACTIONS", v: "04" },
  { k: "CONTAINMENT", v: "37%" },
] as const;
