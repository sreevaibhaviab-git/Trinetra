"use client";

import { useMemo, useState } from "react";
import { api, type BlueTool, type Dashboard } from "@/src/lib/api";
import { RESPONSE_GROUPS, type Entity, type ResponseAction } from "@/src/lib/training";
import { useSession } from "@/src/state/session";

interface Result {
  label: string;
  target: string;
  impact: string;
  ok: boolean;
  message: string;
}

const IMPACT: Record<string, string> = {
  revoke_token: "LOW",
  terminate_session: "LOW",
  remove_mailbox_rule: "LOW",
  terminate_synthetic_process: "LOW",
  remove_persistence_entry: "LOW",
  block_simulated_connection: "LOW",
  block_ip: "LOW",
  remove_registered_device: "MEDIUM",
  disable_user: "MEDIUM",
  isolate_endpoint: "MEDIUM",
  restrict_asset: "HIGH",
  protect_data_asset: "HIGH",
};

function impactTone(impact: string) {
  return impact === "HIGH" ? "text-crit" : impact === "MEDIUM" ? "text-warn" : "text-good";
}

export default function ContainmentPanel({
  dashboard,
  discovered,
}: {
  dashboard: Dashboard;
  discovered: Entity[];
}) {
  const { refresh, report } = useSession();
  const [action, setAction] = useState<ResponseAction | null>(null);
  const [target, setTarget] = useState<Entity | null>(null);
  const [second, setSecond] = useState<Entity | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<Result | null>(null);

  // Endpoints and assets are part of the visible estate; everything else must
  // have turned up in evidence the trainee actually pulled.
  const pool = useMemo<Entity[]>(() => {
    const estate: Entity[] = [
      ...dashboard.endpoints.map((e) => ({
        kind: "endpoint" as const,
        id: e.endpoint_id,
        label: e.hostname,
        detail: `${e.owner}${e.isolated ? " · isolated" : ""}`,
      })),
      ...dashboard.assets.map((a) => ({
        kind: "asset" as const,
        id: a.asset_id,
        label: a.name,
        detail: `${a.criticality.replace("_", " ")}${a.restricted ? " · protected" : ""}`,
      })),
    ];
    const merged = new Map<string, Entity>();
    for (const e of [...estate, ...discovered]) merged.set(`${e.kind}:${e.id}`, e);
    return [...merged.values()];
  }, [dashboard.endpoints, dashboard.assets, discovered]);

  const targets = action ? pool.filter((e) => e.kind === action.kind) : [];
  const needsEndpoint = action?.kind === "process" || action?.kind === "persistence";
  const endpoints = pool.filter((e) => e.kind === "endpoint");

  async function execute() {
    if (!action || !target) return;
    setBusy(true);
    const args: Record<string, unknown> = {};
    switch (action.kind) {
      case "token": args.token_id = target.id; break;
      case "session": args.session_id = target.id; break;
      case "user": args.user_id = target.id; break;
      case "device": args.device_id = target.id; break;
      case "rule": args.rule_id = target.id; break;
      case "endpoint": args.endpoint_id = target.id; break;
      case "connection": args.connection_id = target.id; break;
      case "ip": args.ip_address = target.id; break;
      case "asset": args.asset_id = target.id; break;
      case "process":
        args.endpoint_id = second?.id ?? "";
        args.process_id = Number(target.id);
        break;
      case "persistence":
        args.endpoint_id = second?.id ?? "";
        args.entry_id = target.id;
        break;
    }
    try {
      const outcome = await api.callBlueTool(action.tool, args);
      const payload = outcome.result as { message?: string } | undefined;
      setResult({
        label: action.label,
        target: target.label,
        impact: outcome.impact,
        ok: true,
        message: payload?.message ?? "Action applied.",
      });
    } catch (err) {
      report(err);
      setResult({
        label: action.label,
        target: target.label,
        impact: IMPACT[action.tool] ?? "MEDIUM",
        ok: false,
        message: "The environment refused this action.",
      });
    } finally {
      setBusy(false);
      setConfirming(false);
      setAction(null);
      setTarget(null);
      setSecond(null);
      await refresh();
    }
  }

  if (result) {
    return (
      <div className="flex min-h-0 flex-1 flex-col justify-between px-3 py-3">
        <div>
          <div className={`font-mono text-[13px] tracking-[0.2em] ${result.ok ? "text-ice" : "text-crit"}`}>
            {result.ok ? "ACTION EXECUTED" : "ACTION REFUSED"}
          </div>
          <div className="mt-4 grid grid-cols-[110px_1fr] gap-y-2">
            <span className="label">Action</span>
            <span className="text-[13px] text-ink">{result.label}</span>
            <span className="label">Target</span>
            <span className="font-mono text-[13px] text-ink-2">{result.target}</span>
            <span className="label">Result</span>
            <span className={`font-mono text-[13px] ${result.ok ? "text-good" : "text-crit"}`}>
              {result.ok ? "SUCCESS" : "REFUSED"}
            </span>
            <span className="label">Impact</span>
            <span className={`font-mono text-[13px] ${impactTone(result.impact)}`}>
              {result.impact}
            </span>
          </div>
          <p className="mt-4 border-l border-line-2 pl-3 text-[13px] leading-[1.55] text-muted">
            ENVIRONMENT UPDATED. Continue investigation to determine whether the incident remains
            active.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setResult(null)}
          className="border border-line-2 py-2 font-mono text-[11.5px] tracking-[0.2em] text-ink-2 uppercase hover:border-ice/50 hover:text-ice"
        >
          Back to Containment
        </button>
      </div>
    );
  }

  if (confirming && action && target) {
    const impact = IMPACT[action.tool] ?? "MEDIUM";
    const high = impact === "HIGH";
    return (
      <div className="flex min-h-0 flex-1 flex-col justify-between px-3 py-3">
        <div>
          <div className={`font-mono text-[13px] tracking-[0.2em] ${high ? "text-crit" : "text-warn"}`}>
            CONFIRM CONTAINMENT ACTION
          </div>
          <div className="mt-4 grid grid-cols-[110px_1fr] gap-y-2">
            <span className="label">Action</span>
            <span className="text-[13px] text-ink">{action.label}</span>
            <span className="label">Target</span>
            <span className="font-mono text-[13px] text-ink-2">{target.label}</span>
            {second ? (
              <>
                <span className="label">Endpoint</span>
                <span className="font-mono text-[13px] text-ink-2">{second.label}</span>
              </>
            ) : null}
            <span className="label">Impact</span>
            <span className={`font-mono text-[13px] ${impactTone(impact)}`}>{impact}</span>
          </div>
          <p
            className={`mt-4 border-l-2 pl-3 text-[13px] leading-[1.55] ${
              high ? "border-crit bg-crit/[0.05] py-2 text-crit/90" : "border-line-2 text-muted"
            }`}
          >
            {action.note}
          </p>
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => setConfirming(false)}
            className="flex-1 border border-line-2 py-2 font-mono text-[11.5px] tracking-[0.2em] text-muted uppercase hover:text-ink-2"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => void execute()}
            className={`flex-1 border py-2 font-mono text-[11.5px] tracking-[0.2em] uppercase disabled:opacity-50 ${
              high
                ? "border-crit/50 bg-crit/[0.1] text-crit hover:bg-crit/[0.18]"
                : "border-ice/45 bg-ice/[0.07] text-ice hover:bg-ice/[0.14]"
            }`}
          >
            {busy ? "Executing…" : "Execute"}
          </button>
        </div>
      </div>
    );
  }

  if (action) {
    return (
      <div className="flex min-h-0 flex-1 flex-col">
        <div className="flex shrink-0 items-center justify-between border-b border-line px-3 py-2">
          <span className="font-mono text-[13px] tracking-[0.18em] text-ink uppercase">
            {action.label}
          </span>
          <button
            type="button"
            onClick={() => {
              setAction(null);
              setTarget(null);
              setSecond(null);
            }}
            className="border border-line-2 px-2.5 py-1 font-mono text-[10.5px] tracking-[0.16em] text-muted uppercase hover:border-ice/50 hover:text-ice"
          >
            Back
          </button>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto scroll-thin px-3 py-2">
          {needsEndpoint ? (
            <>
              <div className="label mb-1.5">Endpoint</div>
              <div className="mb-3 flex flex-wrap gap-1.5">
                {endpoints.map((e) => (
                  <button
                    key={e.id}
                    type="button"
                    onClick={() => setSecond(e)}
                    className={`border px-2.5 py-1 font-mono text-[11px] ${
                      second?.id === e.id
                        ? "border-ice/45 bg-ice/[0.07] text-ice"
                        : "border-line-2 text-muted hover:text-ink-2"
                    }`}
                  >
                    {e.label}
                  </button>
                ))}
              </div>
            </>
          ) : null}

          <div className="label mb-1.5">Target</div>
          {targets.length === 0 ? (
            <p className="text-[13px] leading-[1.55] text-dim">
              No candidates of this type have appeared in the evidence you have reviewed.
              Investigate further, then return here.
            </p>
          ) : (
            <div className="border-t border-line">
              {targets.map((t) => (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => setTarget(t)}
                  className="flex w-full items-start gap-2.5 border-b border-line/70 px-1 py-2 text-left hover:bg-raised"
                >
                  <span
                    className={`mt-[5px] inline-block h-[9px] w-[9px] shrink-0 border ${
                      target?.id === t.id ? "border-ice bg-ice/60" : "border-line-3"
                    }`}
                  />
                  <span className="min-w-0">
                    <span className="block font-mono text-[12.5px] text-ink">{t.label}</span>
                    <span className="block truncate text-[12px] text-muted">{t.detail}</span>
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>

        <div className="shrink-0 border-t border-line px-3 py-2">
          <div className="mb-2 flex items-center justify-between">
            <span className="label">Impact</span>
            <span className={`font-mono text-[11.5px] ${impactTone(IMPACT[action.tool] ?? "MEDIUM")}`}>
              {IMPACT[action.tool] ?? "MEDIUM"}
            </span>
          </div>
          <button
            type="button"
            disabled={!target || (needsEndpoint && !second)}
            onClick={() => setConfirming(true)}
            className="w-full border border-ice/40 bg-ice/[0.06] py-2 font-mono text-[11.5px] tracking-[0.22em] text-ice uppercase hover:bg-ice/[0.12] disabled:cursor-not-allowed disabled:border-line-2 disabled:bg-transparent disabled:text-dim"
          >
            Execute Action
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-0 flex-1 overflow-y-auto scroll-thin px-3 py-2">
      {RESPONSE_GROUPS.map(({ group, items }) => (
        <div key={group} className="mb-3">
          <div className="label mb-1.5">{group}</div>
          <div className="border-t border-line">
            {items.map((item) => (
              <button
                key={item.tool}
                type="button"
                onClick={() => setAction(item)}
                className="flex w-full items-center justify-between border-b border-line/70 px-1 py-2 text-left hover:bg-raised"
              >
                <span className="text-[13px] text-ink-2">{item.label}</span>
                <span className={`font-mono text-[10.5px] ${impactTone(IMPACT[item.tool] ?? "MEDIUM")}`}>
                  {IMPACT[item.tool] ?? "MEDIUM"}
                </span>
              </button>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

export type { BlueTool };
