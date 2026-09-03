"use client";

import { useState } from "react";
import { api, type Dashboard } from "@/src/lib/api";
import { useSession } from "@/src/state/session";

/**
 * The kill switch. The backend SafetyGovernor is the only authority — this
 * component asks, then renders whatever the range reports back.
 */
export default function EmergencyStop({ dashboard }: { dashboard: Dashboard }) {
  const { refresh, report, go } = useSession();
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const stopped = dashboard.safety.emergency_stopped;

  async function stop() {
    setBusy(true);
    try {
      await api.emergencyStop("Manual operator emergency stop");
      await refresh();
      setConfirming(false);
    } catch (err) {
      report(err);
    } finally {
      setBusy(false);
    }
  }

  async function restore() {
    setBusy(true);
    try {
      await api.restoreBaseline();
      await refresh();
    } catch (err) {
      report(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <button
        type="button"
        onClick={() => setConfirming(true)}
        disabled={stopped}
        className="flex h-14 items-center gap-2 whitespace-nowrap border-l border-crit/45 bg-crit/[0.09] px-4 font-mono text-[11.5px] tracking-[0.22em] text-crit uppercase transition-colors hover:bg-crit/[0.18] disabled:text-crit/45"
      >
        <span className="inline-block h-[6px] w-[6px] bg-crit" />
        Emergency Stop
      </button>

      {confirming && !stopped ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-base/80">
          <div className="w-[420px] border border-crit/50 bg-panel">
            <div className="border-b border-line px-4 py-3">
              <span className="font-mono text-[13.5px] tracking-[0.22em] text-crit uppercase">
                Terminate Active Simulation?
              </span>
            </div>
            <p className="px-4 py-4 text-[14px] leading-[1.6] text-muted">
              The safety governor will freeze the simulation clock, cancel staged attack events and
              lock all environment mutations. Forensic telemetry is preserved.
            </p>
            <div className="flex items-center justify-end gap-3 border-t border-line px-4 py-3">
              <button
                type="button"
                onClick={() => setConfirming(false)}
                className="px-3 py-2 font-mono text-[11.5px] tracking-[0.2em] text-muted uppercase hover:text-ink-2"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() => void stop()}
                className="border border-crit/50 bg-crit/[0.1] px-5 py-2 font-mono text-[11.5px] tracking-[0.22em] text-crit uppercase hover:bg-crit/[0.2] disabled:opacity-50"
              >
                {busy ? "Stopping…" : "Emergency Stop"}
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {stopped ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-base/90">
          <div className="w-[520px] border border-crit/50 bg-panel">
            <div className="flex items-center gap-2 border-b border-crit/40 bg-crit/[0.07] px-4 py-3">
              <span className="inline-block h-[6px] w-[6px] bg-crit blink" />
              <span className="font-mono text-[13.5px] tracking-[0.24em] text-crit uppercase">
                Emergency Stop Activated
              </span>
            </div>
            <div className="grid grid-cols-2 divide-x divide-line border-b border-line">
              {[
                ["ATTACK ENGINE", "STOPPED"],
                ["SIMULATION CLOCK", "FROZEN"],
                ["ENVIRONMENT MUTATIONS", "LOCKED"],
                ["FORENSIC TELEMETRY", "PRESERVED"],
              ].map(([k, v], i) => (
                <div key={k} className={`px-4 py-3 ${i < 2 ? "border-b border-line" : ""}`}>
                  <div className="label">{k}</div>
                  <div className="mt-1.5 font-mono text-[12.5px] tracking-[0.18em] text-ink">{v}</div>
                </div>
              ))}
            </div>
            {dashboard.safety.emergency_stop_reason ? (
              <div className="px-4 py-3">
                <span className="label">Reason</span>
                <p className="mt-1 text-[13.5px] text-ink-2">
                  {dashboard.safety.emergency_stop_reason}
                </p>
              </div>
            ) : null}
            <div className="flex items-center justify-end gap-3 border-t border-line px-4 py-3">
              <button
                type="button"
                onClick={() => go("DEBRIEF")}
                className="border border-line-2 px-4 py-2 font-mono text-[11.5px] tracking-[0.2em] text-ink-2 uppercase hover:border-ice/50 hover:text-ice"
              >
                View Current State
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() => void restore()}
                className="border border-ice/40 bg-ice/[0.06] px-5 py-2 font-mono text-[11.5px] tracking-[0.22em] text-ice uppercase hover:bg-ice/[0.12] disabled:opacity-50"
              >
                {busy ? "Restoring…" : "Restore Baseline"}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </>
  );
}
