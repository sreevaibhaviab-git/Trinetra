import { incident } from "@/src/data/mockIncident";
import { StatusDot } from "@/src/components/StatusIndicator";

function Mark() {
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" aria-hidden className="shrink-0">
      <path d="M9 1.4 16.6 15H1.4L9 1.4Z" fill="none" stroke="#38444a" strokeWidth="1" />
      <path d="M9 5.6 13.2 13H4.8L9 5.6Z" fill="none" stroke="#4fc4d8" strokeWidth="1" />
      <circle cx="9" cy="10.6" r="1.2" fill="#4fc4d8" />
    </svg>
  );
}

export default function CommandBar() {
  return (
    <header className="grid h-11 shrink-0 grid-cols-[1fr_auto_1fr] items-center border-b border-line bg-panel">
      {/* identity */}
      <div className="flex items-center gap-2.5 pl-3">
        <Mark />
        <div className="flex items-baseline gap-2.5">
          <span className="text-[13px] font-semibold tracking-[0.22em] text-ink">
            TRINETRA
          </span>
          <span className="label hidden lg:inline">
            AUTONOMOUS CYBER CRISIS COMMANDER
          </span>
        </div>
      </div>

      {/* theatre */}
      <div className="flex items-center gap-3 border-x border-line px-5 py-[10px]">
        <span className="font-mono text-[11px] tracking-[0.14em] text-ink-2">
          {incident.environment}
        </span>
        <span className="text-line-3">/</span>
        <span className="flex items-center gap-1.5">
          <StatusDot tone="crit" pulse />
          <span className="font-mono text-[11px] tracking-[0.14em] text-crit">
            {incident.posture}
          </span>
        </span>
      </div>

      {/* state */}
      <div className="flex items-center justify-end gap-0 pr-0">
        <span className="flex items-center gap-1.5 px-3">
          <StatusDot tone="good" pulse />
          <span className="label text-ink-2!">{incident.agentState}</span>
        </span>
        <span className="border-l border-line px-3 tnum text-[11px] text-muted">
          {incident.id}
        </span>
        <span className="border-l border-line px-3 tnum text-[11px] text-ink-2">
          {incident.clock}
          <span className="ml-1 text-dim">{incident.zone}</span>
        </span>
        <span className="flex h-11 items-center gap-2 border-l border-crit/40 bg-crit/[0.07] px-3.5">
          <span className="label text-crit/70!">THREAT</span>
          <span className="font-mono text-[11px] font-medium tracking-[0.16em] text-crit">
            {incident.threatState}
          </span>
        </span>
      </div>
    </header>
  );
}
