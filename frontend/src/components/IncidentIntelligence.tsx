import { hypothesis, threat, timeline } from "@/src/data/mockIncident";
import {
  Label,
  SectionHead,
  StatusDot,
  TickMeter,
  toneText,
} from "@/src/components/StatusIndicator";

export default function IncidentIntelligence() {
  return (
    <section className="flex min-h-0 flex-col bg-panel">
      <SectionHead
        title="Incident Intelligence"
        right={<span className="label">REV 14</span>}
      />

      {/* threat assessment */}
      <div className="shrink-0 border-b border-line px-3 py-3">
        <div className="mb-2 flex items-center justify-between">
          <Label>Threat Assessment</Label>
          <span className="label">NX-DAT-007</span>
        </div>
        <div className="flex items-end justify-between">
          <div className="flex items-baseline gap-1.5">
            <span className="tnum text-[38px] leading-none font-light tracking-tight text-ink">
              {threat.score}
            </span>
            <span className="tnum text-[12px] text-dim">/100</span>
          </div>
          <div className="pb-1 text-right">
            <div className="font-mono text-[11px] tracking-[0.18em] text-crit">
              {threat.band}
            </div>
            <div className="label mt-1">RISING · 6 MIN</div>
          </div>
        </div>
        <div className="mt-3">
          <TickMeter value={threat.score} />
        </div>
        <div className="mt-3 grid grid-cols-3 border-t border-line pt-2.5">
          {threat.facets.map((f) => (
            <div key={f.k}>
              <div className="label">{f.k}</div>
              <div className="tnum mt-1 text-[11px] text-ink-2">{f.v}</div>
            </div>
          ))}
        </div>
      </div>

      {/* timeline */}
      <div className="flex h-6 shrink-0 items-center justify-between border-b border-line px-3">
        <span className="label">Incident Timeline</span>
        <span className="label">{timeline.length} EVENTS</span>
      </div>

      <ol className="scroll-thin min-h-0 flex-1 overflow-y-auto px-3 py-2">
        {timeline.map((e, i) => {
          const last = i === timeline.length - 1;
          return (
            <li key={e.ref} className="group relative grid grid-cols-[54px_1fr] gap-x-2">
              {/* rail */}
              <span
                className={`absolute top-[13px] bottom-0 left-[62px] w-px ${
                  last ? "bg-transparent" : "bg-line"
                }`}
              />
              <span className="tnum pt-[9px] text-[10px] text-muted">{e.t}</span>
              <div className="relative pb-3 pl-3">
                <span className="absolute top-[10px] -left-[2px]">
                  <StatusDot tone={e.tone} pulse={last} size={5} />
                </span>
                <div className="pt-[7px]">
                  <span
                    className={`font-mono text-[9px] tracking-[0.18em] ${toneText[e.tone]}`}
                  >
                    {e.tag}
                  </span>
                  <span className="tnum ml-2 text-[9px] text-dim opacity-0 transition-opacity group-hover:opacity-100">
                    {e.ref}
                  </span>
                  <p className="mt-[3px] text-[12px] leading-[1.45] text-ink-2">
                    {e.text}
                  </p>
                </div>
              </div>
            </li>
          );
        })}
      </ol>

      {/* hypothesis */}
      <div className="shrink-0 border-t border-line px-3 py-3">
        <div className="mb-2 flex items-center justify-between">
          <Label>Current Hypothesis</Label>
          <span className="flex items-center gap-1.5">
            <StatusDot tone="ice" size={4} />
            <span className="label">MODEL · CORRELATION</span>
          </span>
        </div>
        <p className="text-[12.5px] leading-[1.5] text-ink">{hypothesis.primary}</p>

        <div className="mt-3 flex items-center gap-3">
          <span className="label">Confidence</span>
          <span className="tnum text-[12px] text-ink-2">{hypothesis.confidence}%</span>
          <span className="flex-1">
            <TickMeter value={hypothesis.confidence} segments={20} tone="ice" />
          </span>
        </div>

        <div className="mt-3 border-t border-line pt-2">
          {hypothesis.alternatives.map((a) => (
            <div key={a.text} className="flex items-baseline justify-between py-[3px]">
              <span className="text-[11px] text-muted">{a.text}</span>
              <span className="tnum text-[10px] text-dim">{a.pct}%</span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
