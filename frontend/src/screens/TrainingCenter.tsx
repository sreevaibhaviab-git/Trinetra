"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api, type Dashboard } from "@/src/lib/api";
import CommandBar from "@/src/components/CommandBar";
import EmergencyStop from "@/src/components/EmergencyStop";
import InfrastructureGraph from "@/src/components/InfrastructureGraph";
import ContainmentPanel from "@/src/components/training/ContainmentPanel";
import InvestigationConsole from "@/src/components/training/InvestigationConsole";
import TrainingIntel from "@/src/components/training/TrainingIntel";
import { incidentState, posture, type Entity } from "@/src/lib/training";
import { useSession } from "@/src/state/session";

/* The exercise moves on its own: the range advances on a fixed interval while
   the trainee investigates, unless the governor has paused or stopped it. */
const TICK_MS = 6000;
const TICK_SECONDS = 20;

function Briefing({ onBegin }: { onBegin: () => void }) {
  return (
    <main className="flex h-screen items-center justify-center bg-base">
      <div className="grid-field pointer-events-none absolute inset-0 opacity-30" />
      <div className="relative w-[720px] border border-line-2 bg-panel">
        <div className="flex items-center justify-between border-b border-line px-6 py-3">
          <span className="font-mono text-[13px] tracking-[0.24em] text-ice uppercase">
            Blue Team Exercise
          </span>
          <span className="label">NEXORA SYSTEMS</span>
        </div>

        <div className="px-6 py-5">
          <p className="text-[14px] leading-[1.6] text-ink-2">
            Anomalous activity has been detected within the enterprise.
          </p>

          <div className="mt-5 border-t border-line pt-4">
            <div className="label mb-2">Mission</div>
            {[
              "Identify the compromise.",
              "Contain active threats.",
              "Protect critical infrastructure.",
              "Minimize operational disruption.",
            ].map((line) => (
              <p key={line} className="py-[3px] text-[13.5px] text-ink-2">
                <span className="mr-2 text-dim">—</span>
                {line}
              </p>
            ))}
          </div>

          <div className="mt-5 border-t border-line pt-4">
            <div className="label mb-2">Rules</div>
            {[
              "The attack continues while you investigate.",
              "Evidence may be incomplete.",
              "High-impact actions can reduce your score.",
              "You decide when the incident is contained.",
            ].map((line) => (
              <p key={line} className="py-[3px] text-[13.5px] text-muted">
                <span className="mr-2 text-dim">•</span>
                {line}
              </p>
            ))}
          </div>
        </div>

        <div className="flex justify-end border-t border-line px-6 py-4">
          <button
            type="button"
            onClick={onBegin}
            className="border border-ice/40 bg-ice/[0.06] px-8 py-2.5 font-mono text-[12px] tracking-[0.26em] text-ice uppercase hover:border-ice hover:bg-ice/[0.14]"
          >
            Begin Investigation
          </button>
        </div>
      </div>
    </main>
  );
}

function Assessment({ dashboard, onClose }: { dashboard: Dashboard; onClose: () => void }) {
  const { incident, assets } = { incident: dashboard.incident, assets: dashboard.assets };
  const rows: [string, boolean][] = [
    ["Identity anomalies", incident.identity_risk > 0],
    ["Endpoint anomalies", incident.endpoint_risk > 0],
    ["SaaS anomalies", incident.saas_risk > 0],
    ["Cloud anomalies", incident.cloud_risk > 0],
  ];
  const critical = assets.filter((a) => a.criticality === "crown_jewel");
  const degraded = incident.data_risk > 0 || critical.some((a) => a.status !== "online");

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-base/85">
      <div className="w-[520px] border border-line-2 bg-panel">
        <div className="border-b border-line px-5 py-3">
          <span className="font-mono text-[13px] tracking-[0.22em] text-ink uppercase">
            Environment Assessment
          </span>
        </div>
        <div className="px-5 py-4">
          {rows.map(([label, active]) => (
            <div key={label} className="flex items-center justify-between border-b border-line/60 py-2">
              <span className="text-[13px] text-ink-2">{label}</span>
              <span
                className={`font-mono text-[12px] tracking-[0.18em] ${
                  active ? "text-warn" : "text-good"
                }`}
              >
                {active ? "ACTIVE" : "QUIET"}
              </span>
            </div>
          ))}
          <div className="flex items-center justify-between py-2">
            <span className="text-[13px] text-ink-2">Critical assets</span>
            <span
              className={`font-mono text-[12px] tracking-[0.18em] ${
                degraded ? "text-crit" : "text-good"
              }`}
            >
              {degraded ? "DEGRADED" : "STABLE"}
            </span>
          </div>
          <p className="mt-3 border-l border-line-2 pl-3 text-[12.5px] leading-[1.55] text-muted">
            These are observable posture checks only. They do not name entities you have not
            discovered.
          </p>
        </div>
        <div className="flex justify-end border-t border-line px-5 py-3">
          <button
            type="button"
            onClick={onClose}
            className="border border-line-2 px-5 py-2 font-mono text-[11.5px] tracking-[0.2em] text-ink-2 uppercase hover:border-ice/50 hover:text-ice"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

export default function TrainingCenter({ dashboard }: { dashboard: Dashboard }) {
  const { refresh, report, go } = useSession();
  const [begun, setBegun] = useState(dashboard.training?.active ?? false);
  const [discovered, setDiscovered] = useState<Entity[]>([]);
  const [assessing, setAssessing] = useState(false);
  const [declaration, setDeclaration] = useState<"NONE" | "FAILED" | "VERIFIED">("NONE");
  const [busy, setBusy] = useState(false);
  const ticking = useRef(false);

  const onDiscover = useCallback((entities: Entity[]) => {
    setDiscovered((current) => {
      const merged = new Map(current.map((e) => [`${e.kind}:${e.id}`, e]));
      for (const e of entities) merged.set(`${e.kind}:${e.id}`, e);
      return [...merged.values()];
    });
  }, []);

  // one advance in flight at a time; the governor still owns the clock
  useEffect(() => {
    if (!begun) return;
    const id = setInterval(() => {
      if (ticking.current) return;
      if (dashboard.safety.emergency_stopped) return;
      if (dashboard.safety.simulation_status === "PAUSED") return;
      ticking.current = true;
      void api
        .advance(TICK_SECONDS)
        .catch(() => undefined)
        .finally(() => {
          ticking.current = false;
        });
    }, TICK_MS);
    return () => clearInterval(id);
  }, [begun, dashboard.safety.emergency_stopped, dashboard.safety.simulation_status]);

  async function begin() {
    setBusy(true);
    try {
      if (!dashboard.training?.active) await api.trainingStart();
      await refresh();
      setBegun(true);
    } catch (err) {
      report(err);
    } finally {
      setBusy(false);
    }
  }

  async function declare() {
    setBusy(true);
    try {
      const latest = await refresh();
      const contained = latest?.incident.contained ?? dashboard.incident.contained;
      setDeclaration(contained ? "VERIFIED" : "FAILED");
    } catch (err) {
      report(err);
    } finally {
      setBusy(false);
    }
  }

  async function complete() {
    setBusy(true);
    try {
      await api.trainingFinish();
      await refresh();
      go("DEBRIEF");
    } catch (err) {
      report(err);
    } finally {
      setBusy(false);
    }
  }

  if (!begun) return <Briefing onBegin={() => void begin()} />;

  const band = posture(dashboard.environment.risk_score);
  const state = incidentState(
    dashboard,
    declaration === "VERIFIED",
    dashboard.training?.actions_taken ?? 0,
  );

  return (
    <main className="flex h-screen flex-col overflow-hidden">
      <CommandBar dashboard={dashboard} training actions={<EmergencyStop dashboard={dashboard} />} />

      <div className="grid min-h-0 flex-1 grid-cols-[29fr_44fr_27fr] divide-x divide-line [&>*]:min-w-0">
        <InvestigationConsole
          dashboard={dashboard}
          discovered={discovered}
          onDiscover={onDiscover}
        />
        <InfrastructureGraph dashboard={dashboard} fog />
        <TrainingIntel dashboard={dashboard} />
      </div>

      <footer className="flex h-[76px] shrink-0 items-stretch border-t border-line bg-panel">
        <div className="flex w-[220px] flex-col justify-center border-r border-line px-4">
          <span className="label">Business Resilience</span>
          <span className="tnum mt-1.5 text-[24px] leading-none font-light text-ink">
            {dashboard.environment.resilience_score}
            <span className="ml-1 text-[13px] text-dim">/ 100</span>
          </span>
        </div>
        <div className="flex w-[220px] flex-col justify-center border-r border-line px-4">
          <span className="label">Security Posture</span>
          <span
            className={`mt-1.5 font-mono text-[19px] leading-none tracking-[0.16em] ${
              band.tone === "crit" ? "text-crit" : band.tone === "warn" ? "text-warn" : "text-good"
            }`}
          >
            {band.band}
          </span>
        </div>
        <div className="flex w-[260px] flex-col justify-center border-r border-line px-4">
          <span className="label">Incident State</span>
          <span className="mt-1.5 font-mono text-[15px] leading-none tracking-[0.14em] text-ink-2">
            {state}
          </span>
        </div>
        <div className="flex flex-1 flex-col justify-center px-4">
          <span className="label">Exercise</span>
          <span className="tnum mt-1.5 text-[13px] text-muted">
            {dashboard.training?.actions_taken ?? 0} ACTIONS ·{" "}
            {dashboard.training?.tools_used ?? 0} QUERIES ·{" "}
            {dashboard.training?.elapsed_simulation_time ?? "00:00:00"} ELAPSED
          </span>
        </div>

        <div className="flex items-stretch">
          <button
            type="button"
            onClick={() => setAssessing(true)}
            className="border-l border-line px-5 font-mono text-[11.5px] tracking-[0.2em] whitespace-nowrap text-ink-2 uppercase hover:bg-active hover:text-ice"
          >
            Assess Environment
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => void declare()}
            className="border-l border-ice/40 bg-ice/[0.06] px-5 font-mono text-[11.5px] tracking-[0.2em] whitespace-nowrap text-ice uppercase hover:bg-ice/[0.14] disabled:opacity-50"
          >
            Declare Containment
          </button>
        </div>
      </footer>

      {assessing ? (
        <Assessment dashboard={dashboard} onClose={() => setAssessing(false)} />
      ) : null}

      {declaration !== "NONE" ? (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-base/85">
          <div
            className={`w-[520px] border bg-panel ${
              declaration === "VERIFIED" ? "border-good/45" : "border-warn/45"
            }`}
          >
            <div className="border-b border-line px-5 py-3">
              <span
                className={`font-mono text-[13px] tracking-[0.22em] uppercase ${
                  declaration === "VERIFIED" ? "text-good" : "text-warn"
                }`}
              >
                {declaration === "VERIFIED" ? "Containment Verified" : "Containment Not Verified"}
              </span>
            </div>
            <p className="px-5 py-4 text-[13.5px] leading-[1.6] text-ink-2">
              {declaration === "VERIFIED"
                ? "No active containment-relevant threats remain in the environment."
                : "Residual suspicious activity remains observable. The exercise continues — keep investigating."}
            </p>
            <div className="flex justify-end gap-3 border-t border-line px-5 py-3">
              {declaration === "VERIFIED" ? (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => void complete()}
                  className="border border-good/45 bg-good/[0.08] px-5 py-2 font-mono text-[11.5px] tracking-[0.2em] text-good uppercase hover:bg-good/[0.16] disabled:opacity-50"
                >
                  {busy ? "Closing…" : "Complete Exercise"}
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => setDeclaration("NONE")}
                  className="border border-line-2 px-5 py-2 font-mono text-[11.5px] tracking-[0.2em] text-ink-2 uppercase hover:border-ice/50 hover:text-ice"
                >
                  Continue Investigation
                </button>
              )}
            </div>
          </div>
        </div>
      ) : null}
    </main>
  );
}

export { ContainmentPanel };
