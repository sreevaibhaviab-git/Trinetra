import type { Tone } from "@/src/data/mockIncident";

export const toneText: Record<Tone, string> = {
  ice: "text-ice",
  good: "text-good",
  warn: "text-warn",
  crit: "text-crit",
  idle: "text-muted",
};

export const toneBg: Record<Tone, string> = {
  ice: "bg-ice",
  good: "bg-good",
  warn: "bg-warn",
  crit: "bg-crit",
  idle: "bg-dim",
};

export function StatusDot({
  tone,
  pulse = false,
  size = 5,
}: {
  tone: Tone;
  pulse?: boolean;
  size?: number;
}) {
  return (
    <span
      className={`inline-block shrink-0 ${toneBg[tone]} ${pulse ? "blink" : ""}`}
      style={{ width: size, height: size }}
    />
  );
}

/** Small uppercase instrument label. */
export function Label({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return <span className={`label ${className}`}>{children}</span>;
}

/** Header rule used at the top of every panel section. */
export function SectionHead({
  title,
  right,
  className = "",
}: {
  title: string;
  right?: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`flex h-8 shrink-0 items-center justify-between border-b border-line px-3 ${className}`}
    >
      <span className="font-mono text-[10px] tracking-[0.18em] text-ink-2 uppercase">
        {title}
      </span>
      {right ? <div className="flex items-center gap-3">{right}</div> : null}
    </div>
  );
}

/** Segmented meter — instrumentation, not a chart. */
export function TickMeter({
  value,
  segments = 28,
  tone = "crit",
}: {
  value: number;
  segments?: number;
  tone?: Tone;
}) {
  const filled = Math.round((value / 100) * segments);
  return (
    <div className="flex h-3 items-end gap-[2px]">
      {Array.from({ length: segments }, (_, i) => {
        const on = i < filled;
        const hot = on && i >= segments - 6;
        return (
          <span
            key={i}
            className={
              on
                ? hot
                  ? toneBg[tone]
                  : "bg-line-3"
                : "bg-line"
            }
            style={{ width: 3, height: i % 7 === 0 ? 12 : 8 }}
          />
        );
      })}
    </div>
  );
}
