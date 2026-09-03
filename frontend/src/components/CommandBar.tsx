import type { Dashboard } from "@/src/lib/api";
import { StatusDot } from "@/src/components/StatusIndicator";
import { clock, environmentTone, riskBand } from "@/src/lib/view";
import { posture as postureOf } from "@/src/lib/training";

function Mark() {
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" aria-hidden className="shrink-0">
      <path d="M9 1.4 16.6 15H1.4L9 1.4Z" fill="none" stroke="#38444a" strokeWidth="1" />
      <path d="M9 5.6 13.2 13H4.8L9 5.6Z" fill="none" stroke="#4fc4d8" strokeWidth="1" />
      <circle cx="9" cy="10.6" r="1.2" fill="#4fc4d8" />
    </svg>
  );
}

export default function CommandBar({
  dashboard,
  actions,
  training = false,
}: {
  dashboard: Dashboard;
  actions?: React.ReactNode;
  /** Training sees a qualitative posture, never the exact score or threat count. */
  training?: boolean;
}) {
  const { environment, agent, safety, incident } = dashboard;
  const posture = environment.status;
  const tone = environmentTone(posture);
  const postureBand = postureOf(environment.risk_score);
  const band = training
    ? { band: postureBand.band, tone: postureBand.tone as "good" | "warn" | "crit" | "ice" }
    : riskBand(environment.risk_score);

  return (
    <header className="flex h-14 shrink-0 items-center justify-between border-b border-line bg-panel">
      <div className="flex shrink-0 items-center gap-2.5 pl-3">
        <Mark />
        <div className="flex items-baseline gap-2.5">
          <span className="text-[14.5px] font-semibold tracking-[0.22em] text-ink">TRINETRA</span>
          <span className="label hidden whitespace-nowrap 2xl:inline">AUTONOMOUS CYBER CRISIS COMMANDER</span>
        </div>
      </div>

      <div className="mx-4 flex shrink-0 items-center gap-3 border-x border-line px-5 py-[10px] whitespace-nowrap">
        <span className="font-mono text-[12.5px] tracking-[0.14em] text-ink-2">NEXORA SYSTEMS</span>
        <span className="text-line-3">/</span>
        <span className="flex items-center gap-1.5">
          <StatusDot tone={tone} pulse={tone === "crit"} />
          <span
            className={`font-mono text-[12.5px] tracking-[0.14em] ${
              tone === "crit" ? "text-crit" : tone === "warn" ? "text-warn" : "text-good"
            }`}
          >
            {posture}
          </span>
        </span>
        <span className="text-line-3">/</span>
        <span className="label text-ink-2!">{dashboard.mode}</span>
      </div>

      <div className="flex shrink-0 items-center justify-end gap-0">
        {training ? (
          <span className="hidden items-center gap-1.5 px-3 whitespace-nowrap xl:flex">
            <StatusDot tone="ice" />
            <span className="label text-ink-2!">BLUE TEAM EXERCISE</span>
          </span>
        ) : (
          <span className="hidden items-center gap-1.5 px-3 whitespace-nowrap xl:flex">
            <StatusDot tone={agent.running ? "ice" : "idle"} pulse={agent.running} />
            <span className="label text-ink-2!">
              {agent.running ? "AGENT ACTIVE" : `AGENT ${agent.status}`}
            </span>
          </span>
        )}
        {training ? null : (
          <span className="hidden border-l border-line px-3 tnum text-[12.5px] whitespace-nowrap text-muted 2xl:inline">
            {incident.contained ? "CONTAINED" : `${incident.remaining_threats.length} THREATS`}
          </span>
        )}
        <span className="border-l border-line px-3 tnum text-[12.5px] whitespace-nowrap text-ink-2">
          {clock(environment.simulation_time)}
          <span className="ml-1 text-dim">IST</span>
        </span>
        <span
          className={`flex h-14 items-center gap-2 whitespace-nowrap border-l px-3.5 ${
            band.tone === "crit"
              ? "border-crit/40 bg-crit/[0.07]"
              : band.tone === "warn"
                ? "border-warn/30 bg-warn/[0.05]"
                : "border-line"
          }`}
        >
          <span className="label">{training ? "POSTURE" : "RISK"}</span>
          <span
            className={`tnum text-[12.5px] font-medium tracking-[0.12em] ${
              band.tone === "crit" ? "text-crit" : band.tone === "warn" ? "text-warn" : "text-good"
            }`}
          >
            {environment.risk_score} · {band.band}
          </span>
        </span>
        <span className="flex h-14 items-center gap-2 whitespace-nowrap border-l border-line px-3.5">
          <span className="label">RESILIENCE</span>
          <span className="tnum text-[12.5px] text-ink-2">{environment.resilience_score}</span>
        </span>
        {safety.simulation_status === "PAUSED" ? (
          <span className="flex h-14 items-center gap-2 border-l border-warn/40 bg-warn/[0.06] px-3">
            <span className="font-mono text-[11.5px] tracking-[0.18em] text-warn">PAUSED</span>
          </span>
        ) : null}
        {actions}
      </div>
    </header>
  );
}
