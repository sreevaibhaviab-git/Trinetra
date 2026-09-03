"use client";

import { useState } from "react";
import type { Mode } from "@/src/lib/api";
import { useSession } from "@/src/state/session";

const MODES: {
  id: Mode;
  index: string;
  body: string;
  operator: string;
  detail: string[];
}[] = [
  {
    id: "AUTONOMOUS",
    index: "01",
    body: "TRINETRA investigates, acts, verifies and adapts independently.",
    operator: "oversight + emergency stop",
    detail: ["Agent selects Blue tools", "Verifies after every action", "Adapts on incomplete containment"],
  },
  {
    id: "COPILOT",
    index: "02",
    body: "TRINETRA investigates and recommends one containment action at a time.",
    operator: "approve / reject",
    detail: ["Read-only investigation", "One proposal at a time", "No action without your approval"],
  },
  {
    id: "TRAINING",
    index: "03",
    body: "You are the Blue Team analyst. Investigate and respond manually.",
    operator: "full manual response",
    detail: ["Same 34 Blue tools", "Manual containment", "Scored debrief at the end"],
  },
];

export default function ModeSelect() {
  const { go, setMode, report, error } = useSession();
  const [selected, setSelected] = useState<Mode | null>(null);
  const [locking, setLocking] = useState(false);

  // Selection is local; the backend mode is committed only on confirmation.
  async function confirm() {
    if (!selected) return;
    setLocking(true);
    try {
      await setMode(selected);
      go("ATTACK_LAB");
    } catch (err) {
      report(err);
    } finally {
      setLocking(false);
    }
  }

  return (
    <main className="flex h-screen flex-col overflow-hidden bg-base">
      <header className="flex h-11 shrink-0 items-center justify-between border-b border-line bg-panel px-4">
        <span className="font-mono text-[13px] tracking-[0.24em] text-ink uppercase">
          Select Defense Doctrine
        </span>
        <span className="label">STEP 02 / 03</span>
      </header>

      <div className="min-h-0 flex-1 overflow-hidden">
        {MODES.map((m) => {
          const active = selected === m.id;
          return (
            <button
              key={m.id}
              type="button"
              disabled={locking}
              onClick={() => setSelected(m.id)}
              className={`group relative grid h-1/3 w-full grid-cols-[104px_1fr_280px_210px] items-center border-b border-line px-8 text-left transition-all duration-200 ${
                active ? "bg-ice/[0.05] pl-12" : "hover:bg-panel"
              }`}
            >
              {active ? (
                <span className="absolute inset-y-0 left-0 w-[3px] bg-ice" />
              ) : null}
              <span
                className={`tnum text-[34px] leading-none font-light ${
                  active ? "text-ice" : "text-dim group-hover:text-muted"
                }`}
              >
                {m.index}
              </span>

              <span className="min-w-0 border-l border-line-2 pl-6">
                <span
                  className={`block font-mono text-[22px] tracking-[0.26em] ${
                    active ? "text-ice" : "text-ink"
                  }`}
                >
                  {m.id}
                </span>
                <span className="mt-2 block max-w-[54ch] text-[13.5px] leading-[1.55] text-muted">
                  {m.body}
                </span>
              </span>

              <span className="border-l border-line pl-6">
                {m.detail.map((d) => (
                  <span key={d} className="mt-1 block text-[12.5px] text-ink-2 first:mt-0">
                    <span className="mr-2 text-dim">—</span>
                    {d}
                  </span>
                ))}
              </span>

              <span className="border-l border-line pl-6">
                <span className="label">Operator Role</span>
                <span className="mt-1.5 block font-mono text-[12px] tracking-[0.14em] text-ink-2 uppercase">
                  {m.operator}
                </span>
                <span
                  className={`mt-3 inline-block border px-2.5 py-1 font-mono text-[11px] tracking-[0.2em] uppercase ${
                    active
                      ? "border-ice/50 bg-ice/[0.08] text-ice"
                      : "border-line-2 text-dim group-hover:text-muted"
                  }`}
                >
                  {active ? "Selected" : "Select"}
                </span>
              </span>
            </button>
          );
        })}
      </div>

      <footer className="flex h-14 shrink-0 items-center justify-between border-t border-line bg-panel px-6">
        <span className="label">
          {error ? (
            <span className="text-crit">{error}</span>
          ) : (
            "MODE IS ENFORCED BY THE BACKEND, NOT BY THIS INTERFACE"
          )}
        </span>
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => go("INITIALIZE")}
            className="px-3 py-2 font-mono text-[10px] tracking-[0.2em] text-muted uppercase hover:text-ink-2"
          >
            Back
          </button>
          <button
            type="button"
            disabled={!selected || locking}
            onClick={() => void confirm()}
            className="border border-ice/40 bg-ice/[0.06] px-7 py-2.5 font-mono text-[11px] tracking-[0.24em] text-ice uppercase transition-colors hover:border-ice hover:bg-ice/[0.12] disabled:cursor-not-allowed disabled:border-line-2 disabled:bg-transparent disabled:text-dim"
          >
            Continue to Attack Lab
          </button>
        </div>
      </footer>
    </main>
  );
}
