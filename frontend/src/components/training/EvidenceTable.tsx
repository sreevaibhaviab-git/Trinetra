"use client";

import { COLUMNS, display, isNotable, valueAt, type Column } from "@/src/lib/training";

/** Pick a column set: a declared one when we have it, else the row's own keys. */
function columnsFor(tool: string, section: string | null, row: Record<string, unknown>): Column[] {
  const declared = (section && COLUMNS[section]) || COLUMNS[tool];
  if (declared) return declared.filter((c) => valueAt(row, c.path) !== undefined);
  return Object.keys(row)
    .filter((k) => typeof row[k] !== "object" || Array.isArray(row[k]))
    .slice(0, 8)
    .map((k) => ({ path: k, label: k.replace(/_/g, " ").toUpperCase() }));
}

export interface EvidenceSection {
  title: string | null;
  rows: Record<string, unknown>[];
}

/** Split a tool payload into displayable sections without inventing content. */
export function toSections(payload: unknown): EvidenceSection[] {
  if (Array.isArray(payload)) {
    return [{ title: null, rows: payload as Record<string, unknown>[] }];
  }
  if (payload && typeof payload === "object") {
    const obj = payload as Record<string, unknown>;
    const arrays = Object.entries(obj).filter(([, v]) => Array.isArray(v));
    if (arrays.length > 0) {
      return arrays.map(([key, value]) => ({
        title: key,
        rows: value as Record<string, unknown>[],
      }));
    }
    return [{ title: null, rows: [obj] }];
  }
  return [{ title: null, rows: [] }];
}

const SECTION_KEY: Record<string, string> = {
  grants: "oauth_grants",
  tokens: "oauth_tokens",
  authorization_events: "oauth_events",
  files: "files",
  downloads: "downloads",
  access_events: "cloud_events",
  outbound_transfers: "transfers",
};

export default function EvidenceTable({
  tool,
  sections,
  onAdd,
  saved,
}: {
  tool: string;
  sections: EvidenceSection[];
  onAdd?: (row: Record<string, unknown>) => void;
  saved?: (row: Record<string, unknown>) => boolean;
}) {
  const total = sections.reduce((n, s) => n + s.rows.length, 0);

  if (total === 0) {
    return (
      <p className="px-3 py-4 text-[13px] text-dim">
        No records returned for this query at the current simulation time.
      </p>
    );
  }

  return (
    <div className="min-h-0 flex-1 overflow-y-auto scroll-thin">
      {sections.map((section) => {
        if (section.rows.length === 0) return null;
        const key = section.title ? (SECTION_KEY[section.title] ?? section.title) : null;
        const cols = columnsFor(tool, key, section.rows[0]);
        return (
          <div key={section.title ?? "rows"} className="border-b border-line last:border-b-0">
            {section.title ? (
              <div className="flex items-center justify-between border-b border-line/70 bg-raised px-3 py-1.5">
                <span className="label">{section.title.replace(/_/g, " ")}</span>
                <span className="label">{section.rows.length} RECORDS</span>
              </div>
            ) : null}
            {section.rows.map((row, i) => (
              <article
                key={i}
                className="group border-b border-line/50 px-3 py-2 last:border-b-0 hover:bg-raised"
              >
                <div className="flex flex-wrap gap-x-5 gap-y-1">
                  {cols.map((col) => {
                    const value = valueAt(row, col.path);
                    const notable = isNotable(col.path, value);
                    return (
                      <span key={col.path} className="flex min-w-0 flex-col">
                        <span className="label">{col.label}</span>
                        <span
                          className={`truncate font-mono text-[12.5px] ${
                            notable ? "text-warn" : "text-ink-2"
                          }`}
                          title={display(value)}
                        >
                          {display(value)}
                        </span>
                      </span>
                    );
                  })}
                  {onAdd ? (
                    <button
                      type="button"
                      onClick={() => onAdd(row)}
                      className={`ml-auto self-center border px-2.5 py-1 font-mono text-[10.5px] tracking-[0.16em] uppercase transition-colors ${
                        saved?.(row)
                          ? "border-ice/40 text-ice"
                          : "border-line-2 text-dim opacity-0 group-hover:opacity-100 hover:border-ice/50 hover:text-ice"
                      }`}
                    >
                      {saved?.(row) ? "In case" : "Add to case"}
                    </button>
                  ) : null}
                </div>
              </article>
            ))}
          </div>
        );
      })}
      <div className="px-3 py-2">
        <span className="label">{total} RECORDS RETURNED</span>
      </div>
    </div>
  );
}
