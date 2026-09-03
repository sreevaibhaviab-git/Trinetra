"use client";

import { useMemo, useState } from "react";
import { api, type Dashboard } from "@/src/lib/api";
import EvidenceTable, { toSections, type EvidenceSection } from "@/src/components/training/EvidenceTable";
import ContainmentPanel from "@/src/components/training/ContainmentPanel";
import { SectionHead } from "@/src/components/StatusIndicator";
import {
  INVESTIGATION_GROUPS,
  extractEntities,
  type Entity,
  type InvestigationItem,
} from "@/src/lib/training";
import { useSession } from "@/src/state/session";

type Tab = "INVESTIGATION" | "CONTAINMENT";

export default function InvestigationConsole({
  dashboard,
  discovered,
  onDiscover,
}: {
  dashboard: Dashboard;
  discovered: Entity[];
  onDiscover: (entities: Entity[]) => void;
}) {
  const { refresh, report, caseboard, addCase } = useSession();
  const [tab, setTab] = useState<Tab>("INVESTIGATION");
  const [open, setOpen] = useState<InvestigationItem | null>(null);
  const [scopeValue, setScopeValue] = useState<string>("");
  const [sections, setSections] = useState<EvidenceSection[] | null>(null);
  const [busy, setBusy] = useState(false);

  const users = useMemo(
    () => [...new Set(dashboard.telemetry.map((t) => t.related_user).filter(Boolean))] as string[],
    [dashboard.telemetry],
  );

  async function run(item: InvestigationItem, scope: string) {
    setBusy(true);
    setOpen(item);
    setSections(null);
    const args: Record<string, unknown> = {};
    if (item.scope === "user" && scope) args.user_id = scope;
    if (item.scope === "endpoint") args.endpoint_id = scope;
    if (item.scope === "asset" && scope) args.asset_id = scope;
    try {
      const result = await api.callBlueTool(item.tool, args);
      setSections(toSections(result.result));
      onDiscover(extractEntities(item.tool, result.result));
      await refresh();
    } catch (err) {
      report(err);
      setSections([]);
    } finally {
      setBusy(false);
    }
  }

  function scopeOptions(item: InvestigationItem) {
    if (item.scope === "endpoint") {
      return dashboard.endpoints.map((e) => ({ value: e.endpoint_id, label: e.hostname }));
    }
    if (item.scope === "asset") {
      return dashboard.assets.map((a) => ({ value: a.asset_id, label: a.name }));
    }
    if (item.scope === "user") {
      return [{ value: "", label: "All identities" }, ...users.map((u) => ({ value: u, label: u }))];
    }
    return [];
  }

  const inCase = (row: Record<string, unknown>) => {
    const id = String(
      row.session_id ?? row.device_id ?? row.token_id ?? row.rule_id ?? row.grant_id ??
      row.connection_id ?? row.entry_id ?? row.endpoint_id ?? row.asset_id ??
      row.source_ip ?? row.user_id ?? row.event_id ?? "",
    );
    return caseboard.some((c) => c.id === id);
  };

  function save(row: Record<string, unknown>) {
    const entities = extractEntities(open?.tool ?? "", [row]);
    for (const entity of entities.slice(0, 3)) {
      addCase({ id: entity.id, kind: entity.kind, label: entity.label, detail: entity.detail });
    }
  }

  return (
    <section className="flex min-h-0 flex-col bg-panel">
      <SectionHead
        title={tab === "INVESTIGATION" ? "Investigation Console" : "Containment"}
        right={
          <div className="flex items-stretch">
            {(["INVESTIGATION", "CONTAINMENT"] as Tab[]).map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => {
                  setTab(t);
                  setOpen(null);
                }}
                className={`px-2.5 py-1 font-mono text-[10.5px] tracking-[0.16em] uppercase transition-colors ${
                  tab === t ? "border border-ice/45 bg-ice/[0.07] text-ice" : "text-dim hover:text-ink-2"
                }`}
              >
                {t === "INVESTIGATION" ? "Investigate" : "Contain"}
              </button>
            ))}
          </div>
        }
      />

      {tab === "CONTAINMENT" ? (
        <ContainmentPanel dashboard={dashboard} discovered={discovered} />
      ) : open ? (
        <>
          <div className="flex shrink-0 items-center justify-between border-b border-line px-3 py-2">
            <span className="font-mono text-[13px] tracking-[0.18em] text-ink uppercase">
              {open.label}
            </span>
            <button
              type="button"
              onClick={() => {
                setOpen(null);
                setSections(null);
              }}
              className="border border-line-2 px-2.5 py-1 font-mono text-[10.5px] tracking-[0.16em] text-muted uppercase hover:border-ice/50 hover:text-ice"
            >
              Back
            </button>
          </div>

          {open.scope !== "none" ? (
            <div className="flex shrink-0 flex-wrap gap-1.5 border-b border-line px-3 py-2">
              {scopeOptions(open).map((o) => (
                <button
                  key={o.value || "all"}
                  type="button"
                  onClick={() => {
                    setScopeValue(o.value);
                    void run(open, o.value);
                  }}
                  className={`border px-2.5 py-1 font-mono text-[11px] tracking-[0.08em] transition-colors ${
                    scopeValue === o.value
                      ? "border-ice/45 bg-ice/[0.07] text-ice"
                      : "border-line-2 text-muted hover:border-line-3 hover:text-ink-2"
                  }`}
                >
                  {o.label}
                </button>
              ))}
            </div>
          ) : null}

          {busy ? (
            <p className="px-3 py-4 font-mono text-[12px] tracking-[0.14em] text-muted breathe">
              QUERYING…
            </p>
          ) : sections ? (
            <EvidenceTable tool={open.tool} sections={sections} onAdd={save} saved={inCase} />
          ) : (
            <p className="px-3 py-4 text-[13px] text-dim">
              Choose a scope above to pull this evidence.
            </p>
          )}
        </>
      ) : (
        <div className="min-h-0 flex-1 overflow-y-auto scroll-thin px-3 py-2">
          {INVESTIGATION_GROUPS.map(({ group, items }) => (
            <div key={group} className="mb-3">
              <div className="label mb-1.5">{group}</div>
              <div className="border-t border-line">
                {items.map((item) => (
                  <button
                    key={item.tool}
                    type="button"
                    onClick={() => {
                      const first = scopeOptions(item)[0];
                      setScopeValue(first?.value ?? "");
                      void run(item, first?.value ?? "");
                    }}
                    className="flex w-full items-center justify-between border-b border-line/70 px-1 py-2 text-left transition-colors hover:bg-raised"
                  >
                    <span className="text-[13px] text-ink-2">{item.label}</span>
                    <span className="font-mono text-[11px] text-dim">&rsaquo;</span>
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
