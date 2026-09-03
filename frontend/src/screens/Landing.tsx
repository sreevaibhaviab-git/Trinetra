"use client";

import { useSession } from "@/src/state/session";

/* Deterministic geometry — no randomness, so the field never jitters between
   renders and the animation cost stays fixed. */

const FAR = [
  [6, 18], [15, 9], [24, 27], [11, 44], [28, 58], [7, 71], [19, 86], [33, 40],
  [67, 11], [76, 26], [88, 17], [70, 41], [84, 52], [64, 66], [79, 79], [92, 36], [58, 22],
] as const;

const FAR_LINKS: [number, number][] = [
  [0, 1], [1, 2], [2, 3], [3, 4], [4, 5], [5, 6], [2, 7], [7, 4], [0, 3],
  [8, 9], [9, 10], [9, 11], [11, 12], [12, 14], [11, 13], [13, 14], [10, 15], [15, 12], [16, 8], [16, 11],
];

/** Far mesh: thin links only, stretched to the viewport. */
function Mesh() {
  return (
    <svg
      className="pointer-events-none absolute inset-0 h-full w-full"
      viewBox="0 0 100 100"
      preserveAspectRatio="none"
      aria-hidden
    >
      <g opacity="0.6">
        {FAR_LINKS.map(([a, b], i) => (
          <line
            key={`fl${i}`}
            x1={FAR[a][0]}
            y1={FAR[a][1]}
            x2={FAR[b][0]}
            y2={FAR[b][1]}
            stroke="#1c2225"
            strokeWidth="0.08"
            strokeDasharray="0.7 1.5"
            style={{ animation: `tn-dash ${11 + (i % 5) * 3}s linear infinite` }}
          />
        ))}
      </g>
    </svg>
  );
}

/** Radar, sensors and data pulses — square aspect, centred on the core. */
function Radar() {
  const near: [number, number][] = [
    [-210, -150],
    [-120, 170],
    [180, -180],
    [250, 120],
    [-20, 260],
  ];
  return (
    <svg
      className="pointer-events-none absolute top-1/2 left-1/2 h-[860px] w-[860px] -translate-x-1/2 -translate-y-1/2"
      viewBox="-360 -360 720 720"
      aria-hidden
    >
      <circle r="180" fill="none" stroke="#161b1e" strokeWidth="1" />
      <circle r="270" fill="none" stroke="#12171a" strokeWidth="1" />
      <circle r="340" fill="none" stroke="#101416" strokeWidth="1" />

      {[0, 90, 180, 270].map((deg) => (
        <line
          key={deg}
          x1="0"
          y1="0"
          x2={340 * Math.cos((deg * Math.PI) / 180)}
          y2={340 * Math.sin((deg * Math.PI) / 180)}
          stroke="#0f1315"
          strokeWidth="1"
        />
      ))}

      <g style={{ animation: "tn-sweep 16s linear infinite", transformOrigin: "0px 0px" }}>
        <path d="M0 0 L340 0 A340 340 0 0 1 316 124 Z" fill="#4fc4d8" opacity="0.045" />
        <line x1="0" y1="0" x2="340" y2="0" stroke="#4fc4d8" strokeWidth="1" opacity="0.4" />
      </g>

      {near.map(([x, y], i) => (
        <g key={`n${i}`}>
          <path
            d={`M ${x} ${y} L 0 0`}
            fill="none"
            stroke="#171d20"
            strokeWidth="1"
          />
          <circle r="3" fill="#4fc4d8" opacity="0.85">
            <animateMotion
              dur={`${6 + i * 1.6}s`}
              begin={`${i * 0.9}s`}
              repeatCount="indefinite"
              path={`M ${x} ${y} L 0 0`}
            />
          </circle>
          <rect x={x - 3} y={y - 3} width="6" height="6" fill="#38444a" />
          <rect
            x={x - 10}
            y={y - 10}
            width="20"
            height="20"
            fill="none"
            stroke="#4fc4d8"
            strokeWidth="0.9"
            opacity="0.4"
            style={{ animation: `tn-breathe ${6 + i * 1.3}s ease-in-out infinite` }}
          />
        </g>
      ))}
    </svg>
  );
}

/** Tri-node intelligence core: three sensors resolving to one focus. */
function Core() {
  return (
    <svg width="150" height="150" viewBox="0 0 150 150" aria-hidden className="shrink-0">
      <g style={{ animation: "tn-breathe 7s ease-in-out infinite" }}>
        <path d="M75 10 L136 122 H14 Z" fill="none" stroke="#1c2225" strokeWidth="1" />
      </g>
      <path d="M75 32 L119 112 H31 Z" fill="none" stroke="#262e32" strokeWidth="1" />
      <path
        d="M44 88 Q75 58 106 88 Q75 118 44 88 Z"
        fill="none"
        stroke="#4fc4d8"
        strokeWidth="1.1"
        opacity="0.9"
      />
      <circle cx="75" cy="88" r="10.5" fill="none" stroke="#4fc4d8" strokeWidth="1" />
      <circle cx="75" cy="88" r="3.6" fill="#4fc4d8" className="breathe" />
      {[
        [75, 10],
        [136, 122],
        [14, 122],
      ].map(([x, y]) => (
        <g key={`${x}-${y}`}>
          <rect x={x - 2.2} y={y - 2.2} width="4.4" height="4.4" fill="#38444a" />
          <rect
            x={x - 5}
            y={y - 5}
            width="10"
            height="10"
            fill="none"
            stroke="#262e32"
            strokeWidth="0.8"
          />
        </g>
      ))}
      <line x1="14" y1="88" x2="36" y2="88" stroke="#262e32" strokeWidth="1" />
      <line x1="114" y1="88" x2="136" y2="88" stroke="#262e32" strokeWidth="1" />
    </svg>
  );
}

const COORDS = [
  ["LAT", "12.9716N"],
  ["LON", "77.5946E"],
  ["GRID", "AP-SOUTH-1"],
  ["BUS", "TELEMETRY / 6 SOURCES"],
];

export default function Landing() {
  const { go, offline, error } = useSession();

  return (
    <main className="relative flex h-screen flex-col overflow-hidden bg-base">
      <Mesh />
      <Radar />
      <div className="grid-field pointer-events-none absolute inset-0 opacity-30" />

      {/* thin sweep line: the range is idle and listening */}
      <div className="pointer-events-none absolute inset-x-0 top-0 h-px overflow-hidden">
        <span
          className="absolute inset-y-0 left-0 w-[20%] bg-ice/35"
          style={{ animation: "tn-scan 11s linear infinite" }}
        />
      </div>

      {/* corner brackets */}
      <span className="pointer-events-none absolute top-4 left-4 h-4 w-4 border-t border-l border-line-2" />
      <span className="pointer-events-none absolute top-4 right-4 h-4 w-4 border-t border-r border-line-2" />
      <span className="pointer-events-none absolute bottom-12 left-4 h-4 w-4 border-b border-l border-line-2" />
      <span className="pointer-events-none absolute right-4 bottom-12 h-4 w-4 border-r border-b border-line-2" />

      {/* telemetry coordinates */}
      <div className="pointer-events-none absolute top-10 left-10 hidden flex-col gap-1.5 xl:flex">
        {COORDS.map(([k, v]) => (
          <span key={k} className="flex items-baseline gap-2">
            <span className="label">{k}</span>
            <span className="tnum text-[11px] text-dim">{v}</span>
          </span>
        ))}
      </div>

      <div className="relative flex min-h-0 flex-1 items-center justify-center px-10">
        <div className="flex items-center gap-16">
          <Core />
          <div className="border-l border-line-2 pl-16">
            <h1 className="text-[76px] leading-none font-light tracking-[0.3em] text-ink">
              TRINETRA
            </h1>
            <p className="mt-6 font-mono text-[14px] tracking-[0.34em] text-ice/90 uppercase">
              The Third Eye of Cyber Defense
            </p>
            <p className="mt-2.5 font-mono text-[12.5px] tracking-[0.24em] text-muted uppercase">
              Autonomous Agentic Cyber Range
            </p>

            <div className="mt-9 flex items-center gap-3 border-t border-line pt-5">
              {["OBSERVE", "DECIDE", "ACT", "EVALUATE", "ADAPT"].map((phase, i) => (
                <span key={phase} className="flex items-center gap-3">
                  <span className="font-mono text-[11px] tracking-[0.2em] text-dim uppercase">
                    {phase}
                  </span>
                  {i < 4 ? <span className="h-px w-6 bg-line-2" /> : null}
                </span>
              ))}
            </div>

            <button
              type="button"
              onClick={() => go("INITIALIZE")}
              className="mt-10 border border-ice/40 bg-ice/[0.06] px-10 py-3.5 font-mono text-[13px] tracking-[0.3em] text-ice uppercase transition-colors hover:border-ice hover:bg-ice/[0.14]"
            >
              Enter System
            </button>
          </div>
        </div>
      </div>

      <footer className="relative flex h-10 shrink-0 items-center justify-between border-t border-line bg-panel px-4">
        <span className="label">NEXORA SYSTEMS · SYNTHETIC RANGE · NO REAL SYSTEMS</span>
        <span className="label">
          {offline ? <span className="text-crit">{error ?? "BACKEND OFFLINE"}</span> : "STANDBY"}
        </span>
      </footer>
    </main>
  );
}
