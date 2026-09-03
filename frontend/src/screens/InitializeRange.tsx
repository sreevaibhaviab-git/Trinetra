"use client";

import { useEffect, useState } from "react";
import { api, type Dashboard } from "@/src/lib/api";
import { useSession } from "@/src/state/session";
import { clock } from "@/src/lib/view";

const BOOT = [
  "BASELINING IDENTITY",
  "BASELINING ENDPOINTS",
  "LOADING CLOUD MAP",
  "INITIALIZING SAFETY GOVERNOR",
  "VERIFYING TELEMETRY BUS",
] as const;

const SYSTEMS = [
  ["IDENTITY PROVIDER", "identity-provider"],
  ["ENDPOINT FABRIC", "endpoints"],
  ["SAAS", "saas"],
  ["GITHUB", "github"],
  ["AWS", "aws"],
  ["PRODUCTION", "production-server"],
  ["DATABASE", "customer-database"],
  ["SAFETY GOVERNOR", "safety"],
] as const;

function Counter({ label, value }: { label: string; value: string }) {
  return (
    <div className="border-l border-line-2 pl-3">
      <div className="label">{label}</div>
      <div className="tnum mt-1.5 text-[28px] leading-none font-light text-ink">{value}</div>
    </div>
  );
}

export default function InitializeRange() {
  const { go, refresh, report, error, clearError } = useSession();
  const [phase, setPhase] = useState<"IDLE" | "BOOTING" | "READY">("IDLE");
  const [step, setStep] = useState(0);
  const [snapshot, setSnapshot] = useState<Dashboard | null>(null);

  useEffect(() => {
    // Show whatever the range already reports before anything is pressed.
    const id = setTimeout(() => {
      void api
        .dashboard()
        .then(setSnapshot)
        .catch(() => undefined);
    }, 0);
    return () => clearTimeout(id);
  }, []);

  useEffect(() => {
    if (phase !== "BOOTING") return;
    if (step >= BOOT.length) return;
    const id = setTimeout(() => setStep((s) => s + 1), 260);
    return () => clearTimeout(id);
  }, [phase, step]);

  async function initialize() {
    clearError();
    setPhase("BOOTING");
    setStep(0);
    try {
      await api.initialize();
      const next = await refresh();
      setSnapshot(next);
      setPhase("READY");
    } catch (err) {
      report(err);
      setPhase("IDLE");
    }
  }

  const assets = snapshot?.assets ?? [];
  const critical = assets.filter(
    (a) => a.criticality === "crown_jewel" || a.criticality === "high",
  );

  function systemState(key: string): string {
    if (!snapshot) return "PENDING";
    if (key === "safety") return snapshot.safety.simulation_status;
    if (key === "endpoints") return snapshot.endpoints.every((e) => !e.isolated) ? "NOMINAL" : "ISOLATED";
    if (key === "saas") return "NOMINAL";
    const asset = assets.find((a) => a.asset_id === key);
    return asset ? asset.status.toUpperCase() : "NOMINAL";
  }

  return (
    <main className="flex h-screen flex-col overflow-hidden bg-base">
      <header className="flex h-11 shrink-0 items-center justify-between border-b border-line bg-panel px-4">
        <span className="font-mono text-[13px] tracking-[0.24em] text-ink uppercase">
          Initialize Cyber Range
        </span>
        <span className="label">STEP 01 / 03</span>
      </header>

      <div className="grid min-h-0 flex-1 grid-cols-[1.15fr_1fr] divide-x divide-line">
        {/* estate */}
        <section className="scroll-thin min-h-0 overflow-y-auto px-8 py-7">
          <div className="text-[22px] font-light tracking-[0.16em] text-ink">NEXORA SYSTEMS</div>
          <p className="mt-2 max-w-[52ch] text-[13.5px] leading-[1.6] text-muted">
            A synthetic B2B logistics-analytics estate. Every identity, endpoint, asset and event
            below is simulated — no real system is touched at any point.
          </p>

          <div className="mt-7 grid grid-cols-4 gap-x-4">
            <Counter label="IDENTITIES" value="03" />
            <Counter label="ENDPOINTS" value={String(snapshot?.endpoints.length ?? 3).padStart(2, "0")} />
            <Counter label="CLOUD ASSETS" value={String(assets.length || 6).padStart(2, "0")} />
            <Counter label="CRITICAL SYSTEMS" value={String(critical.length || 2).padStart(2, "0")} />
          </div>

          <div className="mt-8 border-t border-line">
            {SYSTEMS.map(([name, key]) => (
              <div
                key={name}
                className="flex items-center justify-between border-b border-line/70 py-2.5"
              >
                <span className="font-mono text-[12.5px] tracking-[0.12em] text-ink-2">{name}</span>
                <span className="font-mono text-[11.5px] tracking-[0.18em] text-muted">
                  {systemState(key)}
                </span>
              </div>
            ))}
          </div>
        </section>

        {/* boot */}
        <section className="flex min-h-0 flex-col justify-between bg-panel px-8 py-7">
          <div>
            <div className="label">System Boot</div>
            <div className="mt-4 space-y-2">
              {BOOT.map((line, i) => {
                const done = phase === "READY" || i < step;
                const running = phase === "BOOTING" && i === step;
                return (
                  <div key={line} className="flex items-center gap-3">
                    <span
                      className={`font-mono text-[10px] ${
                        done ? "text-good" : running ? "text-ice blink" : "text-dim"
                      }`}
                    >
                      {done ? "✓" : running ? "●" : "○"}
                    </span>
                    <span
                      className={`font-mono text-[12.5px] tracking-[0.18em] ${
                        done ? "text-ink-2" : running ? "text-ink" : "text-dim"
                      }`}
                    >
                      {line}
                    </span>
                  </div>
                );
              })}
            </div>

            {phase === "READY" && snapshot ? (
              <div className="mt-8 border border-line-2 bg-raised">
                <div className="flex items-center justify-between border-b border-line px-3 py-2">
                  <span className="font-mono text-[12.5px] tracking-[0.2em] text-good">
                    NEXORA {snapshot.environment.status}
                  </span>
                  <span className="tnum text-[10px] text-dim">
                    {clock(snapshot.environment.simulation_time)}
                  </span>
                </div>
                <div className="grid grid-cols-2 divide-x divide-line">
                  <div className="px-3 py-3">
                    <div className="label">RISK</div>
                    <div className="tnum mt-1 text-[24px] leading-none font-light text-ink">
                      {snapshot.environment.risk_score}
                    </div>
                  </div>
                  <div className="px-3 py-3">
                    <div className="label">RESILIENCE</div>
                    <div className="tnum mt-1 text-[24px] leading-none font-light text-ink">
                      {snapshot.environment.resilience_score}
                    </div>
                  </div>
                </div>
              </div>
            ) : null}

            {error ? (
              <div className="mt-6 border-l-2 border-crit bg-crit/[0.06] px-3 py-2">
                <span className="font-mono text-[11px] tracking-[0.14em] text-crit">{error}</span>
              </div>
            ) : null}
          </div>

          <div className="flex items-center gap-3">
            {phase === "READY" ? (
              <button
                type="button"
                onClick={() => go("MODE_SELECT")}
                className="border border-ice/40 bg-ice/[0.06] px-7 py-2.5 font-mono text-[11px] tracking-[0.24em] text-ice uppercase transition-colors hover:border-ice hover:bg-ice/[0.12]"
              >
                Continue
              </button>
            ) : (
              <button
                type="button"
                onClick={initialize}
                disabled={phase === "BOOTING"}
                className="border border-line-3 px-7 py-2.5 font-mono text-[11px] tracking-[0.24em] text-ink uppercase transition-colors hover:border-ice/50 hover:text-ice disabled:cursor-not-allowed disabled:text-dim"
              >
                {phase === "BOOTING" ? "Initializing…" : "Initialize Range"}
              </button>
            )}
            <button
              type="button"
              onClick={() => go("LANDING")}
              className="px-3 py-2.5 font-mono text-[10px] tracking-[0.2em] text-muted uppercase hover:text-ink-2"
            >
              Back
            </button>
          </div>
        </section>
      </div>
    </main>
  );
}
