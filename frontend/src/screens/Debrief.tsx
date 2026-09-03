"use client";

import { useEffect, useState } from "react";
import { api } from "@/src/lib/api";
import { useSession } from "@/src/state/session";
import { TOOL_LABELS } from "@/src/lib/training";
import { buildTimeline, clock } from "@/src/lib/view";

/** Colour a critical asset row by whether it is protected or still exposed. */
function toneRow(restricted: boolean, status: string): string {
  if (restricted) return "text-good";
  return status === "online" ? "text-ink-2" : "text-warn";
}

function Stat({ label, value, tone = "" }: { label: string; value: string; tone?: string }) {
  return (
    <div className="border-l border-line-2 px-4 py-3">
      <div className="label">{label}</div>
      <div className={`tnum mt-1.5 text-[22px] leading-none font-light ${tone || "text-ink"}`}>
        {value}
      </div>
    </div>
  );
}

export default function Debrief() {
  const { dashboard, refresh, report, go, caseboard } = useSession();
  const [busy, setBusy] = useState(false);
  const [showTimeline, setShowTimeline] = useState(false);

  useEffect(() => {
    const id = setTimeout(() => void refresh(), 0);
    return () => clearTimeout(id);
  }, [refresh]);

  if (!dashboard) {
    return (
      <main className="flex h-screen items-center justify-center bg-base">
        <span className="label">LOADING DEBRIEF</span>
      </main>
    );
  }

  const { environment, incident, attack, safety, agent, training } = dashboard;
  const debrief = training?.debrief ?? null;
  const aborted = safety.emergency_stopped;
  const verdict = aborted
    ? "SIMULATION ABORTED"
    : incident.contained && environment.resilience_score >= 50
      ? "NEXORA SURVIVED"
      : "NEXORA DEGRADED";
  const verdictTone = aborted
    ? "text-warn"
    : verdict === "NEXORA SURVIVED"
      ? "text-good"
      : "text-crit";

  async function restore() {
    setBusy(true);
    try {
      await api.restoreBaseline();
      await refresh();
      go("ATTACK_LAB");
    } catch (err) {
      report(err);
    } finally {
      setBusy(false);
    }
  }

  const timeline = buildTimeline(dashboard.telemetry, 60);

  // Reconstruction is drawn from the exercise record and the telemetry the
  // range published — the trainee only sees it once the exercise is over.
  const actions = training?.actions ?? [];
  const mutations = actions.filter((a) => !a.read_only);
  const notable = dashboard.telemetry.filter(
    (e) => e.severity === "high" || e.severity === "critical",
  );
  const named = [
    ...new Set(
      notable.flatMap((e) => [e.related_user, e.related_asset].filter(Boolean) as string[]),
    ),
  ];
  const savedIds = new Set(caseboard.map((c) => c.id));
  const reconstruction = {
    happened: notable.slice(0, 6).map((e) => `${clock(e.timestamp)} ${e.source} — ${e.message}`),
    discovered: caseboard.map((c) => `${c.label} (${c.kind})`),
    missed: named.filter((n) => !savedIds.has(n)),
    contained: mutations
      .filter((a) => a.success)
      .map((a) => `${TOOL_LABELS[a.tool] ?? a.tool} · ${Object.values(a.arguments)[0] ?? ""}`),
    unnecessary: [
      ...mutations
        .filter((a) => !a.success)
        .map((a) => `${TOOL_LABELS[a.tool] ?? a.tool} — refused`),
      ...mutations
        .filter((a) => a.success && a.impact === "HIGH")
        .map((a) => `${TOOL_LABELS[a.tool] ?? a.tool} — high operational impact`),
    ],
  };
  const criticalAssets = dashboard.assets.filter(
    (a) => a.criticality === "crown_jewel" || a.criticality === "high",
  );

  return (
    <main className="flex h-screen flex-col overflow-hidden bg-base">
      <header className="flex h-11 shrink-0 items-center justify-between border-b border-line bg-panel px-4">
        <span className="font-mono text-[12px] tracking-[0.24em] text-ink uppercase">Debrief</span>
        <span className="label">
          {dashboard.mode} · {clock(environment.simulation_time)}
        </span>
      </header>

      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
        <section className="border-b border-line px-8 py-7">
          <div className={`font-mono text-[30px] tracking-[0.24em] ${verdictTone}`}>{verdict}</div>
          <p className="mt-2 max-w-[70ch] text-[12.5px] leading-[1.6] text-muted">
            {aborted
              ? "The safety governor halted the range. Forensic telemetry is preserved; restore the baseline to run again."
              : incident.contained
                ? "Verification reports no remaining containment-relevant threats on the estate."
                : "Active threats remain on the estate. Containment is incomplete."}
          </p>
        </section>

        <section className="grid grid-cols-4 border-b border-line">
          <Stat label="INCIDENT" value={incident.contained ? "CONTAINED" : "ACTIVE"} tone={incident.contained ? "text-good" : "text-crit"} />
          <Stat label="FINAL RISK" value={String(environment.risk_score)} />
          <Stat label="FINAL RESILIENCE" value={String(environment.resilience_score)} />
          <Stat label="ATTACK STATUS" value={attack.status} />
          <Stat label="ACTIONS TAKEN" value={String(debrief?.actions_taken ?? agent.events.filter((e) => e.phase === "ACT").length)} />
          <Stat label="ADAPTATIONS" value={String(agent.adaptations)} />
          <Stat label="SIMULATION TIME" value={clock(environment.simulation_time)} />
          <Stat label="ENVIRONMENT" value={environment.status} />
        </section>

        {debrief ? (
          <section className="border-b border-line px-8 py-7">
            <div className="flex items-end gap-8">
              <div>
                <div className="label">Response Score</div>
                <div className="mt-2 flex items-baseline gap-2">
                  <span className="tnum text-[54px] leading-none font-light text-ink">
                    {debrief.score}
                  </span>
                  <span className="tnum text-[14px] text-dim">/100</span>
                </div>
                <div className="mt-3 font-mono text-[12px] tracking-[0.22em] text-ice">
                  {debrief.grade}
                </div>
              </div>
              <div className="grid flex-1 grid-cols-4 border-l border-line-2">
                <Stat label="CONTAINED" value={debrief.contained ? "YES" : "NO"} />
                <Stat label="HIGH-IMPACT" value={String(debrief.high_impact_actions)} />
                <Stat label="FAILED ACTIONS" value={String(debrief.failed_actions)} />
                <Stat label="TOOLS USED" value={String(debrief.tools_used)} />
              </div>
            </div>
            <div className="mt-6 border-t border-line pt-4">
              <div className="label mb-2">Feedback</div>
              {debrief.feedback.map((line) => (
                <p key={line} className="border-l border-line-2 py-[3px] pl-3 text-[12.5px] text-ink-2">
                  {line}
                </p>
              ))}
            </div>
          </section>
        ) : null}

        <section className="grid grid-cols-2 divide-x divide-line border-b border-line">
          <div className="px-8 py-6">
            <div className="label mb-3">Critical Asset State</div>
            {criticalAssets.map((a) => (
              <div key={a.asset_id} className="flex items-baseline justify-between border-b border-line/60 py-2">
                <span className="text-[12.5px] text-ink-2">{a.name}</span>
                <span className={`font-mono text-[10px] tracking-[0.16em] ${toneRow(a.restricted, a.status)}`}>
                  {a.restricted ? "PROTECTED" : a.status.toUpperCase()}
                </span>
              </div>
            ))}
          </div>
          <div className="px-8 py-6">
            <div className="label mb-3">Agent Outcome</div>
            <p className="max-w-[60ch] text-[12.5px] leading-[1.6] text-ink-2">
              {agent.events.length === 0
                ? "No autonomous run was executed in this session."
                : (agent.events[agent.events.length - 1]?.message ?? "—")}
            </p>
            {incident.remaining_threats.length > 0 ? (
              <div className="mt-4 border-t border-line pt-3">
                <div className="label mb-2 text-crit!">Remaining</div>
                {incident.remaining_threats.slice(0, 5).map((t, i) => (
                  <div key={`${t.type}-${i}`} className="flex items-baseline justify-between py-[3px]">
                    <span className="font-mono text-[10px] tracking-[0.14em] text-crit/85">
                      {t.type}
                    </span>
                    <span className="tnum text-[10px] text-dim">{t.target}</span>
                  </div>
                ))}
              </div>
            ) : null}
          </div>
        </section>

        {debrief ? (
          <section className="border-b border-line px-8 py-7">
            <div className="label mb-3">Incident Reconstruction</div>
            <div className="grid grid-cols-4 gap-6">
              <div>
                <div className="label mb-2 text-ice!">What happened</div>
                {reconstruction.happened.map((line) => (
                  <p key={line} className="py-[3px] text-[12.5px] leading-[1.5] text-ink-2">
                    {line}
                  </p>
                ))}
              </div>
              <div>
                <div className="label mb-2">What you discovered</div>
                {reconstruction.discovered.length === 0 ? (
                  <p className="text-[12.5px] text-dim">Nothing was saved to the caseboard.</p>
                ) : (
                  reconstruction.discovered.map((line) => (
                    <p key={line} className="py-[3px] font-mono text-[12px] text-ink-2">
                      {line}
                    </p>
                  ))
                )}
              </div>
              <div>
                <div className="label mb-2 text-warn!">What you missed</div>
                {reconstruction.missed.length === 0 ? (
                  <p className="text-[12.5px] text-good">
                    Every entity named by high-severity evidence was in your case.
                  </p>
                ) : (
                  reconstruction.missed.map((line) => (
                    <p key={line} className="py-[3px] font-mono text-[12px] text-warn/90">
                      {line}
                    </p>
                  ))
                )}
              </div>
              <div>
                <div className="label mb-2 text-good!">What you contained</div>
                {reconstruction.contained.length === 0 ? (
                  <p className="text-[12.5px] text-dim">No containment action was executed.</p>
                ) : (
                  reconstruction.contained.map((line) => (
                    <p key={line} className="py-[3px] text-[12.5px] text-ink-2">
                      {line}
                    </p>
                  ))
                )}
                {reconstruction.unnecessary.length > 0 ? (
                  <>
                    <div className="label mt-4 mb-2 text-crit!">Unnecessary actions</div>
                    {reconstruction.unnecessary.map((line) => (
                      <p key={line} className="py-[3px] text-[12.5px] text-crit/85">
                        {line}
                      </p>
                    ))}
                  </>
                ) : null}
              </div>
            </div>
          </section>
        ) : null}

        {showTimeline ? (
          <section className="px-8 py-6">
            <div className="label mb-3">Telemetry Timeline</div>
            {timeline.map((e, i) => (
              <div key={`${e.ref}-${i}`} className="grid grid-cols-[70px_88px_1fr] border-b border-line/60 py-[5px]">
                <span className="tnum text-[10px] text-dim">{e.t}</span>
                <span className="font-mono text-[9.5px] tracking-[0.16em] text-muted">{e.tag}</span>
                <span className="text-[12px] text-ink-2">{e.text}</span>
              </div>
            ))}
          </section>
        ) : null}
      </div>

      <footer className="flex h-14 shrink-0 items-center justify-between border-t border-line bg-panel px-6">
        <span className="label">BACKEND VERIFICATION IS THE SOURCE OF EVERY NUMBER ABOVE</span>
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => setShowTimeline((v) => !v)}
            className="border border-line-2 px-4 py-2 font-mono text-[10px] tracking-[0.2em] text-ink-2 uppercase hover:border-ice/50 hover:text-ice"
          >
            {showTimeline ? "Hide Timeline" : "View Timeline"}
          </button>
          <button
            type="button"
            onClick={() => go("COMMAND_CENTER")}
            className="border border-line-2 px-4 py-2 font-mono text-[10px] tracking-[0.2em] text-ink-2 uppercase hover:border-ice/50 hover:text-ice"
          >
            Back to Console
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => void restore()}
            className="border border-ice/40 bg-ice/[0.06] px-5 py-2 font-mono text-[10px] tracking-[0.22em] text-ice uppercase hover:bg-ice/[0.12] disabled:opacity-50"
          >
            {busy ? "Restoring…" : "Restore Baseline · Run Again"}
          </button>
        </div>
      </footer>
    </main>
  );
}
