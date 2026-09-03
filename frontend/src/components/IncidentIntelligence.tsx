import type { Dashboard } from "@/src/lib/api";
import {
  Label,
  SectionHead,
  StatusDot,
  TickMeter,
  toneText,
} from "@/src/components/StatusIndicator";
import { buildTimeline, riskBand } from "@/src/lib/view";

export default function IncidentIntelligence({ dashboard }: { dashboard: Dashboard }) {
  const { incident, environment } = dashboard;
  const band = riskBand(environment.risk_score);
  const timeline = buildTimeline(dashboard.telemetry);
  const facets: [string, string][] = [
    ["IDENTITY", String(incident.identity_risk)],
    ["SAAS", String(incident.saas_risk)],
    ["CLOUD", String(incident.cloud_risk)],
    ["ENDPOINT", String(incident.endpoint_risk)],
    ["DATA", String(incident.data_risk)],
    ["THREATS", String(incident.remaining_threats.length).padStart(2, "0")],
  ];

  return (
    <section className="flex min-h-0 flex-col bg-panel">
      <SectionHead
        title="Incident Intelligence"
        right={
          <span className="label">
            {incident.contained ? "CONTAINED" : "ACTIVE"}
          </span>
        }
      />

      {/* threat assessment */}
      <div className="shrink-0 border-b border-line px-3 py-3">
        <div className="mb-2 flex items-center justify-between">
          <Label>Threat Assessment</Label>
          <span className="label">OBSERVABLE EVIDENCE</span>
        </div>
        <div className="flex items-end justify-between">
          <div className="flex items-baseline gap-1.5">
            <span className="tnum text-[42px] leading-none font-light tracking-tight text-ink">
              {environment.risk_score}
            </span>
            <span className="tnum text-[13.5px] text-dim">/100</span>
          </div>
          <div className="pb-1 text-right">
            <div className={`font-mono text-[12.5px] tracking-[0.18em] ${toneText[band.tone]}`}>
              {band.band}
            </div>
            <div className="label mt-1">RESILIENCE {environment.resilience_score}</div>
          </div>
        </div>
        <div className="mt-3">
          <TickMeter value={environment.risk_score} tone={band.tone} />
        </div>
        <div className="mt-3 grid grid-cols-3 gap-y-2 border-t border-line pt-2.5">
          {facets.map(([k, v]) => (
            <div key={k}>
              <div className="label">{k}</div>
              <div className="tnum mt-1 text-[12.5px] text-ink-2">{v}</div>
            </div>
          ))}
        </div>
      </div>

      {/* telemetry timeline */}
      <div className="flex h-7 shrink-0 items-center justify-between border-b border-line px-3">
        <span className="label">Incident Timeline</span>
        <span className="label">{dashboard.attack.telemetry_events} EVENTS</span>
      </div>

      <ol className="scroll-thin min-h-0 flex-1 overflow-y-auto px-3 py-2">
        {timeline.length === 0 ? (
          <li className="py-2 text-[13.5px] text-dim">No telemetry yet.</li>
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
                  <p className="mt-[3px] text-[13.5px] leading-[1.45] text-ink-2">{e.text}</p>
                </div>
              </div>
            </li>
          );
        })}
      </ol>

      {/* remaining threats — derived by the backend verifier */}
      <div className="shrink-0 border-t border-line px-3 py-3">
        <div className="mb-2 flex items-center justify-between">
          <Label>Remaining Threats</Label>
          <span className="flex items-center gap-1.5">
            <StatusDot tone={incident.contained ? "good" : "crit"} size={4} />
            <span className="label">VERIFIED STATE</span>
          </span>
        </div>
        {incident.remaining_threats.length === 0 ? (
          <p className="text-[14px] leading-[1.5] text-good">
            Verification reports no active containment-relevant threats.
          </p>
        ) : (
          <div className="scroll-thin max-h-28 overflow-y-auto">
            {incident.remaining_threats.map((t, i) => (
              <div key={`${t.type}-${t.target}-${i}`} className="border-b border-line/60 py-[5px] last:border-b-0">
                <div className="flex items-baseline justify-between">
                  <span className="font-mono text-[11px] tracking-[0.16em] text-crit/90">
                    {t.type}
                  </span>
                  <span className="tnum text-[11.5px] text-dim">{t.target}</span>
                </div>
                <p className="mt-[2px] text-[13px] leading-[1.45] text-muted">{t.detail}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
