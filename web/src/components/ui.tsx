import { useCallback, useEffect, useState, type ReactNode } from "react";
import { ApiError, type CertStatus, type Violation } from "../api";
import { useI18n } from "../i18n";

// ------------------------------------------------------------------ data

export interface Loaded<T> {
  data: T | undefined;
  error: unknown;
  loading: boolean;
  reload: () => void;
}

// useLoad runs fn on mount and whenever deps change.
export function useLoad<T>(fn: () => Promise<T>, deps: unknown[]): Loaded<T> {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<unknown>();
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const run = useCallback(fn, deps);
  useEffect(() => {
    let live = true;
    setLoading(true);
    run().then(
      (d) => live && (setData(d), setError(undefined), setLoading(false)),
      (e) => live && (setError(e), setLoading(false)),
    );
    return () => {
      live = false;
    };
  }, [run, tick]);
  return { data, error, loading, reload: () => setTick((n) => n + 1) };
}

// ------------------------------------------------------------------ time

export function useFormat() {
  const { lang, t } = useI18n();
  const locale = lang === "zh-TW" ? "zh-TW" : "en";
  const date = (s?: string) => (s ? new Date(s).toLocaleDateString(locale, { year: "numeric", month: "short", day: "numeric" }) : "—");
  const dateTime = (s?: string) =>
    s ? new Date(s).toLocaleString(locale, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "—";
  const relative = (s?: string) => {
    if (!s) return "—";
    const diff = new Date(s).getTime() - Date.now();
    const rtf = new Intl.RelativeTimeFormat(locale, { numeric: "auto" });
    const abs = Math.abs(diff);
    if (abs < 3600e3) return rtf.format(Math.round(diff / 60e3), "minute");
    if (abs < 86400e3) return rtf.format(Math.round(diff / 3600e3), "hour");
    return rtf.format(Math.round(diff / 86400e3), "day");
  };
  const daysLeft = (s?: string) => (s ? Math.floor((new Date(s).getTime() - Date.now()) / 86400e3) : undefined);
  return { date, dateTime, relative, daysLeft, t };
}

// ------------------------------------------------------------------ status

export function CertStatusBadge({ status }: { status: CertStatus }) {
  const { t } = useI18n();
  const cls = { active: "ok", pending: "info", failing: "warn", invalid: "bad" }[status];
  const label = { active: t("Active"), pending: t("Pending"), failing: t("Failing"), invalid: t("Needs attention") }[status];
  return <span className={"badge " + cls}>{label}</span>;
}

export function ExpiryBadge({ notAfter }: { notAfter?: string }) {
  const { daysLeft, t } = useFormat();
  const d = daysLeft(notAfter);
  if (d === undefined) return <span className="muted">—</span>;
  if (d < 0) return <span className="badge bad">{t("Expired")}</span>;
  const cls = d < 7 ? "bad" : d < 21 ? "warn" : "ok";
  return <span className={"badge " + cls}>{t("{n} days", { n: d })}</span>;
}

export function Badge({ kind, children }: { kind?: "ok" | "warn" | "bad" | "info"; children: ReactNode }) {
  return <span className={"badge " + (kind ?? "")}>{children}</span>;
}

// ------------------------------------------------------------------ feedback

export function Loading() {
  const { t } = useI18n();
  return <div className="loading">{t("Loading…")}</div>;
}

export function ErrorBox({ error }: { error: unknown }) {
  const { t } = useI18n();
  if (!error) return null;
  if (error instanceof ApiError) {
    const violations = (error.body as { violations?: Violation[] } | undefined)?.violations;
    return (
      <div className="alert bad" role="alert">
        {error.status === 403 ? t("You don't have permission to do this.") + " " : ""}
        {error.message}
        {violations && (
          <ul>
            {violations.map((v, i) => (
              <li key={i}>
                <code>{v.value || v.field}</code>: {v.reason}
              </li>
            ))}
          </ul>
        )}
      </div>
    );
  }
  return (
    <div className="alert bad" role="alert">
      {String(error)}
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <div className="title">{title}</div>
      {children}
    </div>
  );
}

export function PageHead({ title, sub, crumbs, children }: { title: string; sub?: ReactNode; crumbs?: ReactNode; children?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        {crumbs && <div className="crumbs">{crumbs}</div>}
        <h1>{title}</h1>
        {sub && <div className="sub">{sub}</div>}
      </div>
      {children && <div className="actions">{children}</div>}
    </div>
  );
}

// ------------------------------------------------------------------ modal

export function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={title}>
        <h2>{title}</h2>
        {children}
      </div>
    </div>
  );
}

export function CopyField({ value }: { value: string }) {
  const { t } = useI18n();
  const [copied, setCopied] = useState(false);
  return (
    <div className="copy">
      <code>{value}</code>
      <button
        type="button"
        onClick={() => {
          navigator.clipboard?.writeText(value).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          });
        }}
      >
        {copied ? t("Copied") : t("Copy")}
      </button>
    </div>
  );
}

// useAction wraps a mutation with busy and error state.
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>();
  const run = async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
    setBusy(true);
    setError(undefined);
    try {
      return await fn();
    } catch (e) {
      setError(e);
      return undefined;
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, setError, run };
}
