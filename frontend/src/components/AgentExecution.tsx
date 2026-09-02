import {
  currentOperation,
  executionMetrics,
  stages,
  type StageState,
} from "@/src/data/mockIncident";

const glyph: Record<StageState, string> = {
  COMPLETE: "✓",
  RUNNING: "●",
  WAITING: "○",
};

const stageTone: Record<StageState, { name: string; mark: string; state: string }> = {
  COMPLETE: { name: "text-ink-2", mark: "text-good", state: "text-muted" },
  RUNNING: { name: "text-ink", mark: "text-ice", state: "text-ice" },
  WAITING: { name: "text-muted", mark: "text-dim", state: "text-dim" },
};

export default function AgentExecution() {
  return (
    <footer className="flex h-[86px] shrink-0 items-stretch border-t border-line bg-panel">
      {/* operation */}
      <div className="flex w-[27%] shrink-0 flex-col justify-center border-r border-line px-3">
        <div className="flex items-center justify-between">
          <span className="label">Autonomous Execution</span>
          <span className="label">LOOP 04</span>
        </div>
        <div className="mt-2 flex items-center gap-2">
          <span className="inline-block h-[5px] w-[5px] bg-ice blink" />
          <span className="font-mono text-[11px] tracking-[0.1em] text-ink">
            {currentOperation}
          </span>
        </div>
        <div className="relative mt-2 h-px w-full overflow-hidden bg-line">
          <span
            className="absolute inset-y-0 left-0 w-[30%] bg-ice/70"
            style={{ animation: "tn-scan 3.4s linear infinite" }}
          />
        </div>
      </div>

      {/* lifecycle */}
      <div className="flex min-w-0 flex-1 items-center px-4">
        {stages.map((s, i) => {
          const t = stageTone[s.state];
          return (
            <div key={s.name} className="flex min-w-0 flex-1 items-center">
              <div className="min-w-0">
                <div className="flex items-baseline gap-2">
                  <span className="tnum text-[9px] text-dim">
                    {String(i + 1).padStart(2, "0")}
                  </span>
                  <span
                    className={`font-mono text-[11px] tracking-[0.2em] ${t.name}`}
                  >
                    {s.name}
                  </span>
                </div>
                <div className="mt-[6px] flex items-center gap-1.5">
                  <span
                    className={`font-mono text-[9px] ${t.mark} ${
                      s.state === "RUNNING" ? "blink" : ""
                    }`}
                  >
                    {glyph[s.state]}
                  </span>
                  <span
                    className={`font-mono text-[9px] tracking-[0.16em] ${t.state}`}
                  >
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
                  className={`mx-3 h-px flex-1 ${
                    s.state === "COMPLETE" ? "bg-line-2" : "bg-line"
                  }`}
                />
              ) : null}
            </div>
          );
        })}
      </div>

      {/* metrics */}
      <div className="flex shrink-0 items-stretch border-l border-line">
        {executionMetrics.map((m) => (
          <div
            key={m.k}
            className="flex w-[104px] flex-col justify-center border-r border-line px-3 last:border-r-0"
          >
            <span className="label">{m.k}</span>
            <span className="tnum mt-1.5 text-[17px] leading-none font-light text-ink">
              {m.v}
            </span>
          </div>
        ))}
      </div>
    </footer>
  );
}
