"use client";

import type { Dashboard } from "@/src/lib/api";
import { SectionHead, StatusDot, toneText } from "@/src/components/StatusIndicator";
import { buildTimeline } from "@/src/lib/view";
import { useSession } from "@/src/state/session";

/** Right column: observable telemetry, and the trainee's own case notes. */
export default function TrainingIntel({ dashboard }: { dashboard: Dashboard }) {
  const { caseboard, removeCase } = useSession();
  const timeline = buildTimeline(dashboard.telemetry);

  return (
    <section className="flex min-h-0 flex-col bg-panel">
      <SectionHead
        title="Live Telemetry"
        right={<span className="label">{dashboard.attack.telemetry_events} EVENTS</span>}
      />

      <ol className="scroll-thin min-h-0 flex-[1.6] overflow-y-auto px-3 py-2">
        {timeline.length === 0 ? (
          <li className="py-2 text-[13px] text-dim">No telemetry observed yet.</li>
        ) : null}
        {timeline.map((e, i) => {
          const last = i === timeline.length - 1;
          return (
            <li key={`${e.ref}-${i}`} className="group relative grid grid-cols-[54px_1fr] gap-x-2">
              <span
                className={`absolute top-[13px] bottom-0 left-[62px] w-px ${
                  last ? "bg-transparent" : "bg-line"
                }`}
              />
              <span className="tnum pt-[9px] text-[11.5px] text-muted">{e.t}</span>
              <div className="relative pb-3 pl-3">
                <span className="absolute top-[10px] -left-[2px]">
                  <StatusDot tone={e.tone} pulse={last} size={5} />
                </span>
                <div className="pt-[7px]">
                  <span className={`font-mono text-[10.5px] tracking-[0.18em] ${toneText[e.tone]}`}>
                    {e.tag}
                  </span>
                  <span className="tnum ml-2 text-[10.5px] text-dim opacity-0 transition-opacity group-hover:opacity-100">
                    {e.ref}
                  </span>
                  <p className="mt-[3px] text-[13px] leading-[1.45] text-ink-2">{e.text}</p>
                </div>
              </div>
            </li>
          );
        })}
      </ol>

      <div className="flex h-7 shrink-0 items-center justify-between border-y border-line px-3">
        <span className="label">Case Evidence</span>
        <span className="label">{caseboard.length} ITEMS</span>
      </div>

      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto px-3 py-2">
        {caseboard.length === 0 ? (
          <p className="text-[12.5px] leading-[1.5] text-dim">
            Nothing saved yet. Add entities from evidence rows as you find them relevant.
          </p>
        ) : (
          caseboard.map((item) => (
            <div
              key={`${item.kind}:${item.id}`}
              className="group flex items-start justify-between gap-2 border-b border-line/60 py-1.5 last:border-b-0"
            >
              <span className="min-w-0">
                <span className="block truncate font-mono text-[12.5px] text-ink">{item.label}</span>
                <span className="block truncate text-[11.5px] text-muted">
                  {item.kind.toUpperCase()}
                  {item.detail ? ` · ${item.detail}` : ""}
                </span>
              </span>
              <button
                type="button"
                onClick={() => removeCase(item.kind, item.id)}
                className="shrink-0 font-mono text-[11px] text-dim opacity-0 transition-opacity group-hover:opacity-100 hover:text-crit"
              >
                REMOVE
              </button>
            </div>
          ))
        )}
      </div>
    </section>
  );
}
