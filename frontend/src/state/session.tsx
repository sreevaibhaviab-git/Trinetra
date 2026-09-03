"use client";

/**
 * Application stage plus a single poll of `/dashboard`.
 *
 * The backend is the source of truth for every cyber fact; this context holds
 * only where the operator is in the product flow and the latest snapshot.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { ApiError, api, type Dashboard, type Mode } from "@/src/lib/api";

export interface CaseItem {
  kind: string;
  id: string;
  label: string;
  detail: string;
}

export type Stage =
  | "LANDING"
  | "INITIALIZE"
  | "MODE_SELECT"
  | "ATTACK_LAB"
  | "COMMAND_CENTER"
  | "DEBRIEF";

const POLL_MS = 1500;

interface SessionValue {
  stage: Stage;
  go: (stage: Stage) => void;
  dashboard: Dashboard | null;
  error: string | null;
  offline: boolean;
  refresh: () => Promise<Dashboard | null>;
  setPolling: (on: boolean) => void;
  mode: Mode;
  setMode: (mode: Mode) => Promise<void>;
  report: (err: unknown) => void;
  clearError: () => void;
  caseboard: CaseItem[];
  addCase: (item: CaseItem) => void;
  removeCase: (kind: string, id: string) => void;
  clearCase: () => void;
}

const SessionContext = createContext<SessionValue | null>(null);

export function describeError(err: unknown): string {
  if (err instanceof ApiError) return err.message.toUpperCase();
  if (err instanceof Error) return err.message.toUpperCase();
  return "UNEXPECTED ERROR";
}

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [stage, setStage] = useState<Stage>("LANDING");
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [offline, setOffline] = useState(false);
  const [polling, setPolling] = useState(false);
  const [mode, setModeState] = useState<Mode>("AUTONOMOUS");
  const [caseboard, setCaseboard] = useState<CaseItem[]>([]);
  const inFlight = useRef(false);

  const refresh = useCallback(async () => {
    if (inFlight.current) return null;
    inFlight.current = true;
    try {
      const next = await api.dashboard();
      setDashboard(next);
      setModeState(next.mode);
      setOffline(false);
      return next;
    } catch (err) {
      if (err instanceof ApiError && err.offline) {
        setOffline(true);
        setError(err.message.toUpperCase());
      }
      return null;
    } finally {
      inFlight.current = false;
    }
  }, []);

  useEffect(() => {
    if (!polling) return;
    const tick = () => void refresh();
    // Deferred so the first poll lands after paint rather than during the effect.
    const first = setTimeout(tick, 0);
    const id = setInterval(tick, POLL_MS);
    return () => {
      clearTimeout(first);
      clearInterval(id);
    };
  }, [polling, refresh]);

  const setMode = useCallback(
    async (next: Mode) => {
      await api.setMode(next);
      setModeState(next);
      await refresh();
    },
    [refresh],
  );

  const value = useMemo<SessionValue>(
    () => ({
      stage,
      go: setStage,
      dashboard,
      error,
      offline,
      refresh,
      setPolling,
      mode,
      setMode,
      report: (err: unknown) => setError(describeError(err)),
      clearError: () => setError(null),
      caseboard,
      addCase: (item: CaseItem) =>
        setCaseboard((items) =>
          items.some((i) => i.kind === item.kind && i.id === item.id) ? items : [...items, item],
        ),
      removeCase: (kind: string, id: string) =>
        setCaseboard((items) => items.filter((i) => !(i.kind === kind && i.id === id))),
      clearCase: () => setCaseboard([]),
    }),
    [stage, dashboard, error, offline, refresh, mode, setMode, caseboard],
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionValue {
  const value = useContext(SessionContext);
  if (!value) throw new Error("useSession must be used inside SessionProvider");
  return value;
}
