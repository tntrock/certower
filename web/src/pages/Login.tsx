import { useState, type FormEvent } from "react";
import { api } from "../api";
import { ErrorBox, useAction } from "../components/ui";
import { useI18n } from "../i18n";

export function Login({ onDone }: { onDone: () => void }) {
  const { t, lang, setLang } = useI18n();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const { busy, error, run } = useAction();

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
        <ErrorBox error={error} />
        <div className="field">
          <label htmlFor="email">{t("Email")}</label>
          <input id="email" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} autoFocus />
        </div>
        <div className="field">
          <label htmlFor="password">{t("Password")}</label>
          <input id="password" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>
        <button className="primary" disabled={busy}>
          {busy ? t("Signing in…") : t("Sign in")}
        </button>
        <div style={{ textAlign: "center", marginTop: 16 }}>
          <button type="button" className="small" onClick={() => setLang(lang === "en" ? "zh-TW" : "en")}>
            {lang === "en" ? "中文" : "English"}
          </button>
        </div>
      </form>
    </div>
  );
}
