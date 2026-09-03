import type { Dashboard } from "@/src/lib/api";
import { buildStages, type StageState } from "@/src/lib/view";

const glyph: Record<StageState, string> = {
  COMPLETE: "\u2713",
  RUNNING: "\u25cf",
  WAITING: "\u25cb",
};

const stageTone: Record<StageState, { name: string; mark: string; state: string }> = {
  COMPLETE: { name: "text-ink-2", mark: "text-good", state: "text-muted" },
  RUNNING: { name: "text-ink", mark: "text-ice", state: "text-ice" },
  WAITING: { name: "text-muted", mark: "text-dim", state: "text-dim" },
};

export default function AgentExecution({ dashboard }: { dashboard: Dashboard }) {
  const { agent, incident, attack, environment } = dashboard;
  const stages = buildStages(agent.events, agent.current_phase, agent.running);
  const operation = agent.running
    ? (agent.current_action ?? agent.current_phase ?? "WORKING")
    : agent.events.length > 0
      ? `AGENT ${agent.status}`
      : "AWAITING OPERATOR COMMAND";

  const metrics: [string, string][] = [
    ["STEPS", String(agent.steps).padStart(2, "0")],
    ["ADAPTATIONS", String(agent.adaptations).padStart(2, "0")],
    ["ATTACK", attack.status],
    ["CONTAINMENT", incident.contained ? "COMPLETE" : `${100 - environment.risk_score}%`],
  ];

  return (
    <footer className="flex h-[104px] shrink-0 items-stretch border-t border-line bg-panel">
      <div className="flex w-[27%] shrink-0 flex-col justify-center border-r border-line px-3">
        <div className="flex items-center justify-between">
          <span className="label whitespace-nowrap">Agent Execution</span>
          <span className="label">{dashboard.mode}</span>
        </div>
        <div className="mt-2 flex items-center gap-2">
          <span
            className={`inline-block h-[5px] w-[5px] ${agent.running ? "bg-ice blink" : "bg-dim"}`}
          />
          <span className="truncate font-mono text-[12.5px] tracking-[0.1em] text-ink">
            {operation}
          </span>
        </div>
        <div className="relative mt-2 h-px w-full overflow-hidden bg-line">
          {agent.running ? (
            <span
              className="absolute inset-y-0 left-0 w-[30%] bg-ice/70"
              style={{ animation: "tn-scan 3.4s linear infinite" }}
            />
          ) : null}
        </div>
      </div>

      <div className="flex min-w-0 flex-1 items-center px-5">
        {stages.map((s, i) => {
          const t = stageTone[s.state];
          return (
            <div key={s.name} className="flex min-w-0 flex-1 items-center pr-1">
              <div className="min-w-0 pr-4">
                <div className="flex items-baseline gap-2">
                  <span className="tnum w-5 shrink-0 text-[10.5px] text-dim">
                    {String(i + 1).padStart(2, "0")}
                  </span>
                  <span className={`font-mono text-[12.5px] tracking-[0.2em] whitespace-nowrap ${t.name}`}>
                    {s.name}
                  </span>
                </div>
                <div className="mt-[6px] flex items-center gap-1.5">
                  <span
                    className={`font-mono text-[10.5px] ${t.mark} ${
                      s.state === "RUNNING" ? "blink" : ""
                    }`}
                  >
                    {glyph[s.state]}
                  </span>
                  <span className={`font-mono text-[10.5px] tracking-[0.16em] whitespace-nowrap ${t.state}`}>
                    {s.state}
                  </span>
                </div>
                {s.state === "RUNNING" ? (
                  <div className="relative mt-[6px] h-px w-16 overflow-hidden bg-line">
                    <span
                      className="absolute inset-y-0 left-0 w-1/3 bg-ice"
                      style={{ animation: "tn-scan 1.9s linear infinite" }}
                    />
                  </div>
                ) : (
                  <div className="mt-[6px] h-px w-16 bg-line/70" />
                )}
              </div>
              {i < stages.length - 1 ? (
                <span
                  className={`mx-4 h-px flex-1 ${
                    s.state === "COMPLETE" ? "bg-line-2" : "bg-line"
                  }`}
                />
              ) : null}
            </div>
          );
        })}
      </div>

      <div className="flex shrink-0 items-stretch border-l border-line">
        {metrics.map(([k, v]) => (
          <div
            key={k}
            className="flex w-[132px] flex-col justify-center border-r border-line px-3 last:border-r-0"
          >
            <span className="label whitespace-nowrap">{k}</span>
            <span className="tnum mt-1.5 truncate text-[17px] leading-none font-light text-ink">
              {v}
            </span>
          </div>
        ))}
      </div>
    </footer>
  );
}
