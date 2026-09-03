"use client";

import { useEffect, useState } from "react";
import { api } from "@/src/lib/api";
import { useSession } from "@/src/state/session";

type Phase = "IDLE" | "ARMED" | "LAUNCHING" | "ACTIVE";

const CHAIN = ["IDENTITY", "SAAS", "DEVELOPER", "CLOUD", "DATA"] as const;

export default function AttackLab() {
  const { go, dashboard, mode, refresh, report, error, clearError } = useSession();
  const [phase, setPhase] = useState<Phase>("IDLE");
  const [count, setCount] = useState(3);

  useEffect(() => {
    const id = setTimeout(() => void refresh(), 0);
    return () => clearTimeout(id);
  }, [refresh]);

  // 1. arm: the backend launches the operation before any countdown is shown
  useEffect(() => {
    if (phase !== "LAUNCHING") return;
    let cancelled = false;
    void (async () => {
      try {
        await api.launchAttack("operation_maya");
        await refresh();
        if (cancelled) return;
        setPhase("ARMED");
      } catch (err) {
        if (cancelled) return;
        report(err);
        setPhase("IDLE");
        setCount(3);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [phase, refresh, report]);

  // 2. countdown, then straight into the command center
  useEffect(() => {
    if (phase !== "ARMED") return;
    const id = setTimeout(() => {
      if (count > 1) setCount((c) => c - 1);
      else setPhase("ACTIVE");
    }, 560);
    return () => clearTimeout(id);
  }, [phase, count]);

  useEffect(() => {
    if (phase !== "ACTIVE") return;
    const id = setTimeout(() => go("COMMAND_CENTER"), 750);
    return () => clearTimeout(id);
  }, [phase, go]);

  const env = dashboard?.environment;

  if (phase !== "IDLE") {
    return (
      <main className="flex h-screen flex-col items-center justify-center bg-base">
        <div className="grid-field pointer-events-none absolute inset-0 opacity-50" />
        <div className="relative flex flex-col items-center">
          <span className="font-mono text-[12px] tracking-[0.34em] text-warn uppercase">
            Simulation Armed
          </span>
          <span className="tnum mt-8 text-[92px] leading-none font-light text-ink">
            {phase === "ARMED" ? String(count).padStart(2, "0") : "00"}
          </span>
          <span
            className={`mt-8 font-mono text-[12px] tracking-[0.3em] uppercase ${
              phase === "ACTIVE" ? "text-crit" : "text-muted"
            }`}
          >
            {phase === "ACTIVE"
              ? "Attack Active"
              : phase === "LAUNCHING"
                ? "Arming Operation Maya"
                : "Operation Maya Live"}
          </span>
          <div className="relative mt-8 h-px w-[280px] overflow-hidden bg-line">
            <span
              className="absolute inset-y-0 left-0 w-1/3 bg-crit/70"
              style={{ animation: "tn-scan 1.4s linear infinite" }}
            />
          </div>
        </div>
      </main>
    );
  }

  return (
    <main className="flex h-screen flex-col overflow-hidden bg-base">
      <header className="grid h-11 shrink-0 grid-cols-[1fr_auto] items-center border-b border-line bg-panel px-4">
        <span className="font-mono text-[13px] tracking-[0.24em] text-ink uppercase">
          Attack Lab
        </span>
        <div className="flex items-center gap-0">
          {[
            ["ENVIRONMENT", env?.scenario === "nexora_baseline" ? "NEXORA SYSTEMS" : "NEXORA"],
            ["STATUS", env?.status ?? "—"],
            ["RESILIENCE", String(env?.resilience_score ?? "—")],
            ["MODE", mode],
          ].map(([k, v]) => (
            <span key={k} className="flex items-baseline gap-2 border-l border-line px-4">
              <span className="label">{k}</span>
              <span className="tnum text-[12.5px] text-ink-2">{v}</span>
            </span>
          ))}
        </div>
      </header>

      <div className="grid min-h-0 flex-1 grid-cols-[1.35fr_1fr] divide-x divide-line">
        {/* scenario */}
        <section className="flex min-h-0 flex-col px-8 py-7">
          <span className="label">A · Choose Scenario</span>

          <article className="mt-4 border border-line-2 bg-panel">
            <div className="flex items-baseline justify-between border-b border-line px-4 py-3">
              <span className="font-mono text-[20px] tracking-[0.26em] text-ink">
                OPERATION MAYA
              </span>
              <span className="flex items-center gap-2">
                <span className="inline-block h-[5px] w-[5px] bg-good" />
                <span className="font-mono text-[12px] tracking-[0.18em] text-good">READY</span>
              </span>
            </div>

            <div className="px-4 py-4">
              <div className="flex flex-col items-start">
                {CHAIN.map((step, i) => (
                  <div key={step} className="flex flex-col items-start">
                    <span className="border border-line-2 px-3 py-1.5 font-mono text-[12px] tracking-[0.2em] text-ink-2">
                      {step}
                    </span>
                    {i < CHAIN.length - 1 ? (
                      <span className="ml-6 flex h-5 flex-col items-center">
                        <span className="h-3 w-px bg-line-2" />
                        <span className="font-mono text-[10px] leading-none text-line-3">
                          &darr;
                        </span>
                      </span>
                    ) : null}
                  </div>
                ))}
              </div>

              <p className="mt-4 max-w-[60ch] text-[13.5px] leading-[1.6] text-muted">
                A supplier-themed lure leads to a device-code authorization, an unmanaged device, a
                consent-less token, mailbox and drive discovery, a clone burst, privileged cloud
                access and staged customer data. Every stage is synthetic state on the range.
              </p>

              <div className="mt-5 grid grid-cols-3 border-t border-line pt-3">
                <div>
                  <div className="label">Difficulty</div>
                  <div className="mt-1 font-mono text-[12.5px] tracking-[0.16em] text-warn">
                    ADVANCED
                  </div>
                </div>
                <div>
                  <div className="label">Domains</div>
                  <div className="mt-1 font-mono text-[12.5px] tracking-[0.14em] text-ink-2">
                    IDENTITY · SAAS · CLOUD · DATA
                  </div>
                </div>
                <div>
                  <div className="label">Stages</div>
                  <div className="tnum mt-1 text-[12.5px] text-ink-2">11</div>
                </div>
              </div>
            </div>

            <div className="flex items-center justify-between border-t border-line px-4 py-3">
              <span className="label">
                {error ? <span className="text-crit">{error}</span> : "SAFETY GOVERNOR ARMED"}
              </span>
              <button
                type="button"
                onClick={() => {
                  clearError();
                  setCount(3);
                  setPhase("LAUNCHING");
                }}
                className="border border-crit/45 bg-crit/[0.07] px-6 py-2.5 font-mono text-[12.5px] tracking-[0.24em] text-crit uppercase transition-colors hover:border-crit hover:bg-crit/[0.14]"
              >
                Arm Operation Maya
              </button>
            </div>
          </article>
        </section>

        {/* randomized */}
        <section className="flex min-h-0 flex-col justify-between bg-panel px-8 py-7">
          <div>
            <span className="label">B · Randomized Simulation</span>
            <article className="mt-4 border border-line bg-base/40 px-4 py-4 opacity-55">
              <div className="flex items-baseline justify-between">
                <span className="font-mono text-[17px] tracking-[0.24em] text-muted">
                  DYNAMIC ATTACK
                </span>
                <span className="font-mono text-[11px] tracking-[0.18em] text-dim">DISABLED</span>
              </div>
              <p className="mt-3 max-w-[46ch] text-[13px] leading-[1.6] text-dim">
                Randomized scenario generation is not implemented in the range engine. This option
                stays disabled rather than presenting a capability the backend does not have.
              </p>
              <div className="mt-4 border-t border-line pt-3">
                <span className="font-mono text-[12px] tracking-[0.2em] text-warn/80">
                  COMING AFTER VALIDATION
                </span>
              </div>
            </article>
          </div>

          <button
            type="button"
            onClick={() => go("MODE_SELECT")}
            className="self-start px-3 py-2 font-mono text-[10px] tracking-[0.2em] text-muted uppercase hover:text-ink-2"
          >
            Back
          </button>
        </section>
      </div>
    </main>
  );
}
