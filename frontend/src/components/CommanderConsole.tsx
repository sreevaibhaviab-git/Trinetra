"use client";

import { useState } from "react";
import {
  commanderMeta,
  journal,
  objective,
  type JournalPhase,
} from "@/src/data/mockIncident";
import { SectionHead, StatusDot } from "@/src/components/StatusIndicator";

const phaseStyle: Record<JournalPhase, string> = {
  OBSERVE: "text-ice/85",
  DECIDE: "text-ink-2",
  ACTION: "text-warn/90",
  RESULT: "text-crit/90",
};

export default function CommanderConsole() {
  const [value, setValue] = useState("");

  return (
    <section className="flex min-h-0 flex-col bg-panel">
      <SectionHead
        title="Trinetra Command"
        right={
          <>
            {commanderMeta.map((m) => (
              <span key={m.k} className="hidden items-baseline gap-1.5 xl:flex">
                <span className="label">{m.k}</span>
                <span className="tnum text-[10px] text-ink-2">{m.v}</span>
              </span>
            ))}
          </>
        }
      />

      {/* objective */}
      <div className="shrink-0 border-b border-line px-3 py-3">
        <div className="label mb-2">Objective</div>
        <p className="border-l border-ice/45 pl-2.5 text-[12.5px] leading-[1.55] text-ink-2">
          {objective}
        </p>
      </div>

      {/* execution journal */}
      <div className="flex h-6 shrink-0 items-center justify-between border-b border-line px-3">
        <span className="label">Execution Journal</span>
        <span className="label">{journal.length} ENTRIES</span>
      </div>

      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto">
        {journal.map((e, i) => (
          <article
            key={`${e.t}-${i}`}
            className="group grid grid-cols-[52px_1fr] gap-x-2 border-b border-line/60 px-3 py-2 transition-colors hover:bg-raised"
          >
            <div className="tnum pt-[1px] text-[10px] text-dim">{e.t}</div>
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <StatusDot tone={e.tone} size={4} />
                <span
                  className={`font-mono text-[9.5px] tracking-[0.18em] ${phaseStyle[e.phase]}`}
                >
                  {e.phase}
                </span>
                {e.ref ? (
                  <span className="tnum ml-auto text-[9.5px] text-dim opacity-0 transition-opacity group-hover:opacity-100">
                    {e.ref}
                  </span>
                ) : null}
              </div>
              <p className="mt-1 pl-3 text-[12px] leading-[1.5] text-ink-2">
                {e.message}
              </p>
            </div>
          </article>
        ))}
        <div className="flex items-center gap-2 px-3 py-2">
          <span className="tnum w-[52px] text-[10px] text-dim">17:38:52</span>
          <StatusDot tone="ice" pulse size={4} />
          <span className="font-mono text-[10px] tracking-[0.14em] text-muted breathe">
            AWAITING EVALUATION
          </span>
        </div>
      </div>

      {/* command input */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          setValue("");
        }}
        className="flex h-11 shrink-0 items-stretch border-t border-line bg-raised"
      >
        <span className="flex items-center pr-2 pl-3 font-mono text-[13px] text-ice/80">
          &gt;
        </span>
        <input
          value={value}
          onChange={(ev) => setValue(ev.target.value)}
          spellCheck={false}
          placeholder="Give Trinetra an objective..."
          aria-label="Command input"
          className="min-w-0 flex-1 bg-transparent font-mono text-[12px] text-ink outline-none placeholder:text-dim"
        />
        <button
          type="submit"
          className="my-2 mr-2 border border-line-2 px-3 font-mono text-[9.5px] tracking-[0.18em] text-ink-2 uppercase transition-colors hover:border-ice/50 hover:bg-active hover:text-ice active:bg-panel"
        >
          Execute
        </button>
      </form>
    </section>
  );
}
