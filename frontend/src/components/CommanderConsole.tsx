"use client";

import { useState } from "react";
import { DEFAULT_GOAL, api, type Dashboard } from "@/src/lib/api";
import { SectionHead, StatusDot } from "@/src/components/StatusIndicator";
import { clock, phaseTone } from "@/src/lib/view";
import { useSession } from "@/src/state/session";

const phaseStyle: Record<string, string> = {
  OBSERVE: "text-ice/85",
  DECIDE: "text-ink-2",
  ACT: "text-warn/90",
  RESULT: "text-good/90",
  EVALUATE: "text-ice/85",
  ADAPT: "text-warn",
  FAILED: "text-crit/90",
  FINAL: "text-good/90",
  COMPLETE: "text-good/90",
};

/* ── shared journal of agent lifecycle events ─────────────────── */

function Journal({ dashboard }: { dashboard: Dashboard }) {
  const events = dashboard.agent.events;
  return (
    <>
      <div className="flex h-7 shrink-0 items-center justify-between border-b border-line px-3">
        <span className="label">Execution Journal</span>
        <span className="label">{events.length} ENTRIES</span>
      </div>
      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
        {events.length === 0 ? (
          <p className="px-3 py-3 text-[13.5px] leading-[1.5] text-dim">
            No agent activity yet.
          </p>
        ) : null}
        {events.map((e, i) => (
          <article
            key={`${e.step}-${i}`}
            className="group grid grid-cols-[34px_1fr] gap-x-2 border-b border-line/60 px-3 py-2 transition-colors hover:bg-raised"
          >
            <div className="tnum pt-[1px] text-[11.5px] text-dim">
              {String(e.step).padStart(2, "0")}
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <StatusDot tone={phaseTone[e.phase] ?? "idle"} size={4} />
                <span
                  className={`font-mono text-[11px] tracking-[0.18em] ${
                    phaseStyle[e.phase] ?? "text-ink-2"
                  }`}
                >
                  {e.phase}
                </span>
                {e.tool ? (
                  <span className="tnum ml-auto text-[11px] text-dim opacity-0 transition-opacity group-hover:opacity-100">
                    {e.tool}
                    {e.target ? `:${e.target}` : ""}
                  </span>
                ) : null}
              </div>
              <p className="mt-1 pl-3 text-[13.5px] leading-[1.5] text-ink-2">{e.message}</p>
            </div>
          </article>
        ))}
      </div>
    </>
  );
}

/* ── autonomous ───────────────────────────────────────────────── */

function AutonomousFoot({ dashboard }: { dashboard: Dashboard }) {
  const { refresh, report, go } = useSession();
  const [busy, setBusy] = useState(false);
  const running = busy || dashboard.agent.running;

  async function run() {
    setBusy(true);
    try {
      await api.runAgent(DEFAULT_GOAL);
      await refresh();
      go("DEBRIEF");
    } catch (err) {
      report(err);
    } finally {
      setBusy(false);
      void refresh();
    }
  }

  return (
    <div className="shrink-0 border-t border-line bg-raised px-3 py-3">
      <button
        type="button"
        disabled={running}
        onClick={() => void run()}
        className="w-full border border-ice/40 bg-ice/[0.06] py-2.5 font-mono text-[12px] tracking-[0.24em] text-ice uppercase transition-colors hover:border-ice hover:bg-ice/[0.12] disabled:cursor-not-allowed disabled:border-line-2 disabled:bg-transparent disabled:text-dim"
      >
        {running ? "Trinetra Responding…" : "Start Autonomous Response"}
      </button>
      <p className="mt-2 text-[12.5px] leading-[1.5] text-dim">
        Trinetra selects its own tools, acts, verifies and adapts. You retain emergency stop.
      </p>
    </div>
  );
}

/* ── copilot ──────────────────────────────────────────────────── */

function CopilotFoot({ dashboard }: { dashboard: Dashboard }) {
  const { refresh, report } = useSession();
  const [busy, setBusy] = useState(false);
  const pending = dashboard.copilot.pending_recommendation;

  async function analyse() {
    setBusy(true);
    try {
      await api.runCopilot("Investigate and recommend the safest next containment action.");
      await refresh();
    } catch (err) {
      report(err);
    } finally {
      setBusy(false);
    }
  }

  async function decide(approve: boolean) {
    if (!pending) return;
    setBusy(true);
    try {
      if (approve) await api.approve(pending.id);
      else await api.reject(pending.id);
      await refresh();
    } catch (err) {
      report(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="shrink-0 border-t border-line bg-raised">
      {pending ? (
        <div className="border-b border-line px-3 py-3">
          <div className="flex items-center justify-between">
            <span className="label text-ice!">Recommended Action</span>
            <span
              className={`font-mono text-[11px] tracking-[0.18em] ${
                pending.impact === "HIGH"
                  ? "text-crit"
                  : pending.impact === "MEDIUM"
                    ? "text-warn"
                    : "text-good"
              }`}
            >
              IMPACT {pending.impact}
            </span>
          </div>
          <div className="mt-2 grid grid-cols-[64px_1fr] gap-y-1">
            <span className="label">Tool</span>
            <span className="font-mono text-[13px] text-ink">{pending.tool_name}</span>
            <span className="label">Target</span>
            <span className="font-mono text-[13px] text-ink-2">
              {Object.values(pending.arguments).join(", ") || "—"}
            </span>
          </div>
          <p className="mt-2 border-l border-ice/45 pl-2.5 text-[13.5px] leading-[1.5] text-ink-2">
            {pending.reason}
          </p>
          <div className="mt-3 flex gap-2">
            <button
              type="button"
              disabled={busy}
              onClick={() => void decide(true)}
              className="flex-1 border border-good/45 bg-good/[0.07] py-2 font-mono text-[11.5px] tracking-[0.22em] text-good uppercase hover:bg-good/[0.14] disabled:opacity-50"
            >
              Approve
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={() => void decide(false)}
              className="flex-1 border border-line-2 py-2 font-mono text-[11.5px] tracking-[0.22em] text-muted uppercase hover:border-crit/45 hover:text-crit disabled:opacity-50"
            >
              Reject
            </button>
          </div>
        </div>
      ) : null}

      <div className="px-3 py-3">
        <button
          type="button"
          disabled={busy}
          onClick={() => void analyse()}
          className="w-full border border-ice/40 bg-ice/[0.06] py-2.5 font-mono text-[12px] tracking-[0.24em] text-ice uppercase hover:border-ice hover:bg-ice/[0.12] disabled:cursor-not-allowed disabled:border-line-2 disabled:bg-transparent disabled:text-dim"
        >
          {busy ? "Analyzing…" : "Start Copilot Analysis"}
        </button>
      </div>
    </div>
  );
}

/* ── panel ────────────────────────────────────────────────────── */

export default function CommanderConsole({ dashboard }: { dashboard: Dashboard }) {
  const mode = dashboard.mode;
  const meta = [
    ["MODE", mode],
    ["STEPS", String(dashboard.agent.steps).padStart(2, "0")],
    ["ADAPT", String(dashboard.agent.adaptations).padStart(2, "0")],
  ];

  return (
    <section className="flex min-h-0 flex-col bg-panel">
      <SectionHead
        title="Trinetra Command"
        right={
          <>
            {meta.map(([k, v]) => (
              <span key={k} className="hidden items-baseline gap-1.5 whitespace-nowrap 2xl:flex">
                <span className="label">{k}</span>
                <span className="tnum text-[11.5px] text-ink-2">{v}</span>
              </span>
            ))}
          </>
        }
      />

      <div className="shrink-0 border-b border-line px-3 py-3">
        <div className="label mb-2">Objective</div>
        <p className="border-l border-ice/45 pl-2.5 text-[14px] leading-[1.55] text-ink-2">
          {DEFAULT_GOAL}
        </p>
        {dashboard.agent.current_action ? (
          <div className="mt-2 flex items-center gap-2">
            <span className="label">LAST ACTION</span>
            <span className="tnum text-[12px] text-ink-2">{dashboard.agent.current_action}</span>
            <span className="tnum ml-auto text-[11.5px] text-dim">
              {clock(dashboard.environment.simulation_time)}
            </span>
          </div>
        ) : null}
      </div>

      <Journal dashboard={dashboard} />
      {mode === "COPILOT" ? (
        <CopilotFoot dashboard={dashboard} />
      ) : (
        <AutonomousFoot dashboard={dashboard} />
      )}
    </section>
  );
}
