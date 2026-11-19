import { useEffect, useState, type FormEvent } from "react";
import { api } from "../api";
import { ErrorBox, useAction } from "../components/ui";
import { LanguagePicker, useI18n } from "../i18n";

type Providers = { password: boolean; oidc: { name: string; loginUrl: string } | null };

// Codes the server puts in ?sso_error= when single sign-on fails.
// i18n-table
const ssoErrors: Record<string, string> = {
  sso_no_account: "No Certower account exists for this email. Ask an administrator to add you.",
  sso_email_unverified: "Your identity provider has not verified this email address.",
  sso_domain_not_allowed: "Sign-in from this email domain is not allowed.",
  sso_conflict: "This account is already linked to a different identity.",
  sso_disabled: "This account is disabled.",
  sso_no_email: "The identity provider did not share an email address.",
  sso_expired: "The sign-in attempt expired. Please try again.",
  sso_unavailable: "The identity provider is unreachable. Try again later.",
  sso_failed: "Single sign-on failed. Please try again.",
};

export function Login({ onDone }: { onDone: () => void }) {
  const { t } = useI18n();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [providers, setProviders] = useState<Providers | null>(null);
  const [ssoError] = useState(() => new URLSearchParams(window.location.search).get("sso_error"));
  const { busy, error, run } = useAction();

  useEffect(() => {
    api.get<Providers>("/auth/providers").then(setProviders, () => setProviders(null));
    if (ssoError) window.history.replaceState(null, "", window.location.pathname);
  }, [ssoError]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const ok = await run(() => api.post("/auth/login", { email, password }));
    if (ok !== undefined) onDone();
  };

  return (
    <div className="login">
      <form className="card" onSubmit={submit}>
        <div className="brand">
          <img src="/favicon.svg" alt="" />
          Certower
        </div>
        <div className="tagline">{t("Certificate lifecycle control tower")}</div>
        {ssoError && !error && (
          <div className="alert bad" role="alert">
            {t(ssoErrors[ssoError] ?? ssoErrors.sso_failed)}
          </div>
        )}
        <ErrorBox error={error} />
        {providers?.oidc && (
          <>
            <a className="btn primary" href={providers.oidc.loginUrl}>
              {t("Sign in with {name}", { name: providers.oidc.name })}
            </a>
            <div className="or">{t("or")}</div>
          </>
        )}
        <div className="field">
          <label htmlFor="email">{t("Email")}</label>
          <input id="email" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} autoFocus={!providers?.oidc} />
        </div>
        <div className="field">
          <label htmlFor="password">{t("Password")}</label>
          <input id="password" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>
        <button className={providers?.oidc ? undefined : "primary"} disabled={busy}>
          {busy ? t("Signing in…") : t("Sign in")}
        </button>
        <div style={{ textAlign: "center", marginTop: 16 }}>
          <LanguagePicker className="small" />
        </div>
      </form>
    </div>
  );
}
