"use client";

import { useEffect, useState } from "react";
import { api } from "@/src/lib/api";
import AgentExecution from "@/src/components/AgentExecution";
import CommandBar from "@/src/components/CommandBar";
import CommanderConsole from "@/src/components/CommanderConsole";
import EmergencyStop from "@/src/components/EmergencyStop";
import IncidentIntelligence from "@/src/components/IncidentIntelligence";
import InfrastructureGraph from "@/src/components/InfrastructureGraph";
import TrainingCenter from "@/src/screens/TrainingCenter";
import { useSession } from "@/src/state/session";

/** Compact operator controls. All state comes back from the governor. */
function ClockControls({ paused, halted }: { paused: boolean; halted: boolean }) {
  const { refresh, report } = useSession();
  const [busy, setBusy] = useState(false);

  async function run(fn: () => Promise<unknown>) {
    setBusy(true);
    try {
      await fn();
      await refresh();
    } catch (err) {
      report(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <span className="flex h-14 items-stretch">
      <button
        type="button"
        disabled={busy || halted}
        onClick={() => void run(() => api.advance(30))}
        className="border-l border-line px-3 font-mono text-[11.5px] tracking-[0.18em] whitespace-nowrap text-muted uppercase hover:bg-active hover:text-ink disabled:text-dim"
      >
        +30s
      </button>
      <button
        type="button"
        disabled={busy || halted}
        onClick={() => void run(paused ? api.resume : api.pause)}
        className="border-l border-line px-3 font-mono text-[11.5px] tracking-[0.18em] whitespace-nowrap text-muted uppercase hover:bg-active hover:text-ink disabled:text-dim"
      >
        {paused ? "Resume" : "Pause"}
      </button>
    </span>
  );
}

export default function CommandCenter() {
  const { dashboard, setPolling, error, clearError, offline } = useSession();

  useEffect(() => {
    setPolling(true);
    return () => setPolling(false);
  }, [setPolling]);

  if (!dashboard) {
    return (
      <main className="flex h-screen items-center justify-center bg-base">
        <span className="font-mono text-[12.5px] tracking-[0.24em] text-muted uppercase breathe">
          {offline ? "Backend offline — retrying" : "Synchronising range state"}
        </span>
      </main>
    );
  }

  if (dashboard.mode === "TRAINING") return <TrainingCenter dashboard={dashboard} />;

  const paused = dashboard.safety.simulation_status === "PAUSED";
  const halted = dashboard.safety.emergency_stopped;

  return (
    <main className="flex h-screen flex-col overflow-hidden">
      <CommandBar
        dashboard={dashboard}
        actions={
          <>
            <ClockControls paused={paused} halted={halted} />
            <EmergencyStop dashboard={dashboard} />
          </>
        }
      />

      {error ? (
        <div className="flex h-7 shrink-0 items-center justify-between border-b border-crit/35 bg-crit/[0.06] px-3">
          <span className="font-mono text-[11.5px] tracking-[0.16em] text-crit">{error}</span>
          <button
            type="button"
            onClick={clearError}
            className="font-mono text-[11px] tracking-[0.18em] text-crit/70 uppercase hover:text-crit"
          >
            Dismiss
          </button>
        </div>
      ) : null}

      <div className="grid min-h-0 flex-1 grid-cols-[27fr_47fr_26fr] divide-x divide-line [&>*]:min-w-0 max-[1200px]:grid-cols-[32fr_42fr_26fr]">
        <CommanderConsole dashboard={dashboard} />
        <InfrastructureGraph dashboard={dashboard} />
        <IncidentIntelligence dashboard={dashboard} />
      </div>

      <AgentExecution dashboard={dashboard} />
    </main>
  );
}
