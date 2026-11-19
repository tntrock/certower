import { Fragment, useEffect, useState, type FormEvent } from "react";
import { useParams } from "react-router-dom";
import { api, type AuditEntry, type Job, type Policy, type RoleBinding, type RoleInfo } from "../api";
import { Badge, Empty, ErrorBox, Loading, Modal, PageHead, useAction, useFormat, useLoad } from "../components/ui";
import { useI18n } from "../i18n";

const keyTypes = ["ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-3072", "rsa-4096"];

// ------------------------------------------------------------------ policy

export function PolicyPage() {
  const { org, project } = useParams();
  const path = `/orgs/${org}/projects/${project}/policy`;
  const { t } = useI18n();
  const pol = useLoad(() => api.get<Policy>(path), [path]);
  const [names, setNames] = useState("");
  const [issuers, setIssuers] = useState("");
  const [keys, setKeys] = useState<string[]>([]);
  const [wildcard, setWildcard] = useState(false);
  const [maxDays, setMaxDays] = useState(0);
  const { busy, error, run } = useAction();
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (!pol.data) return;
    setNames((pol.data.allowedNames ?? []).join("\n"));
    setIssuers((pol.data.allowedIssuers ?? []).join(", "));
    setKeys(pol.data.allowedKeyTypes ?? []);
    setWildcard(pol.data.allowWildcard);
    setMaxDays(pol.data.maxValidityDays);
  }, [pol.data]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setSaved(false);
    const list = (s: string) => s.split(/[\s,]+/).filter(Boolean);
    const ok = await run(() =>
      api.put(path, { allowedNames: list(names), allowedIssuers: list(issuers), allowedKeyTypes: keys, allowWildcard: wildcard, maxValidityDays: maxDays }).then(() => true),
    );
    if (ok) setSaved(true);
  };

  if (pol.loading && !pol.data) return <Loading />;
  return (
    <>
      <PageHead title={t("Policy")} sub={t("Guardrails on what this project may request. Only organization administrators can change them.")} />
      <form className="card" onSubmit={submit} style={{ maxWidth: 720 }}>
        <ErrorBox error={error || pol.error} />
        {saved && <div className="alert ok">{t("Policy saved.")}</div>}
        <div className="field">
          <label htmlFor="names">{t("Allowed domain names")}</label>
          <textarea id="names" value={names} onChange={(e) => setNames(e.target.value)} placeholder={"shop.example.com\n*.shop.example.com"} />
          <span className="hint">{t("One per line. *.example.com allows every name below example.com. Empty allows any name.")}</span>
        </div>
        <label className="check">
          <input type="checkbox" checked={wildcard} onChange={(e) => setWildcard(e.target.checked)} />
          {t("Allow wildcard certificates (*.example.com)")}
        </label>
        <div className="field">
          <label htmlFor="issuers">{t("Allowed issuers")}</label>
          <input id="issuers" value={issuers} onChange={(e) => setIssuers(e.target.value)} placeholder="letsencrypt, twca" />
          <span className="hint">{t("Issuer configuration names, comma-separated. Empty allows any.")}</span>
        </div>
        <fieldset>
          <legend>{t("Allowed key types (none checked allows all)")}</legend>
          <div className="actions" style={{ marginBottom: 12 }}>
            {keyTypes.map((k) => (
              <label className="check" key={k} style={{ margin: 0 }}>
                <input type="checkbox" checked={keys.includes(k)} onChange={(e) => setKeys(e.target.checked ? [...keys, k] : keys.filter((x) => x !== k))} />
                <span className="mono">{k}</span>
              </label>
            ))}
          </div>
        </fieldset>
        <div className="field">
          <label htmlFor="maxdays">{t("Maximum validity (days)")}</label>
          <input id="maxdays" type="number" min={0} value={maxDays} onChange={(e) => setMaxDays(Number(e.target.value))} style={{ maxWidth: 160 }} />
          <span className="hint">{t("0 means the CA's default.")}</span>
        </div>
        <button className="primary" disabled={busy}>
          {t("Save policy")}
        </button>
      </form>
    </>
  );
}

// ------------------------------------------------------------------ members

export function Members({ scope }: { scope: "org" | "project" }) {
  const { org, project } = useParams();
  const { t } = useI18n();
  const { date } = useFormat();
  const base = scope === "org" ? `/orgs/${org}` : `/orgs/${org}/projects/${project}`;
  const bindings = useLoad(() => api.get<RoleBinding[]>(`${base}/bindings`), [base]);
  const roles = useLoad(() => api.get<RoleInfo[]>(`/orgs/${org}/roles`), [org]);
  const [adding, setAdding] = useState(false);
  const del = useAction();

  const subject = (b: RoleBinding) =>
    b.oidcGroup ? (
      <>
        <Badge>{t("Group")}</Badge> {b.oidcGroup}
      </>
    ) : b.serviceAccountId ? (
      <>
        <Badge>{t("Service account")}</Badge> <span className="mono small">{b.serviceAccountId.slice(0, 8)}</span>
      </>
    ) : (
      <span className="mono small">{b.userId?.slice(0, 8)}…</span>
    );

  return (
    <>
      <PageHead title={scope === "org" ? t("Members") : t("Project members")} sub={scope === "org" ? t("Roles granted on the organization apply to all its projects.") : t("Roles granted on this project only.")}>
        <button className="primary" onClick={() => setAdding(true)}>
          {t("Grant role")}
        </button>
      </PageHead>
      <ErrorBox error={bindings.error || del.error} />
      <div className="card flush">
        {bindings.loading && !bindings.data ? (
          <Loading />
        ) : bindings.data?.length ? (
          <table>
            <thead>
              <tr>
                <th>{t("Who")}</th>
                <th>{t("Role")}</th>
                <th>{t("Since")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {bindings.data.map((b) => (
                <tr key={b.id}>
                  <td>{subject(b)}</td>
                  <td>
                    <Badge kind="info">{b.role}</Badge>
                  </td>
                  <td className="muted">{date(b.createdAt)}</td>
                  <td className="right">
                    <button className="small danger" onClick={() => del.run(() => api.del(`${base}/bindings/${b.id}`)).then(bindings.reload)}>
                      {t("Revoke")}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty title={t("No role bindings here")} />
        )}
      </div>

      {roles.data && (
        <div className="card">
          <h2>{t("Roles")}</h2>
          <table>
            <tbody>
              {roles.data.map((r) => (
                <tr key={r.name}>
                  <td className="nowrap">
                    <b>{r.name}</b> {!r.builtin && <Badge>{t("custom")}</Badge>}
                  </td>
                  <td>
                    {r.permissions.map((p) => (
                      <span className="tag" key={p}>
                        {p}
                      </span>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {adding && <GrantModal base={base} scope={scope} roles={roles.data ?? []} onClose={() => setAdding(false)} onDone={bindings.reload} />}
    </>
  );
}

function GrantModal({ base, scope, roles, onClose, onDone }: { base: string; scope: string; roles: RoleInfo[]; onClose: () => void; onDone: () => void }) {
  const { t } = useI18n();
  const [kind, setKind] = useState<"user" | "oidcGroup" | "serviceAccount">("user");
  const [value, setValue] = useState("");
  const [role, setRole] = useState(scope === "org" ? "viewer" : "operator");
  const { busy, error, run } = useAction();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const ok = await run(() => api.post(`${base}/bindings`, { role, [kind]: value }).then(() => true));
    if (ok) {
      onDone();
      onClose();
    }
  };

  return (
    <Modal title={t("Grant role")} onClose={onClose}>
      <form onSubmit={submit}>
        <ErrorBox error={error} />
        <div className="field">
          <label htmlFor="kind">{t("Grant to")}</label>
          <select id="kind" value={kind} onChange={(e) => setKind(e.target.value as typeof kind)}>
            <option value="user">{t("User (email)")}</option>
            <option value="oidcGroup">{t("Identity provider group")}</option>
            {scope === "project" && <option value="serviceAccount">{t("Service account")}</option>}
          </select>
        </div>
        <div className="field">
          <label htmlFor="value">{kind === "user" ? t("Email") : t("Name")}</label>
          <input id="value" required value={value} onChange={(e) => setValue(e.target.value)} type={kind === "user" ? "email" : "text"} />
        </div>
        <div className="field">
          <label htmlFor="role">{t("Role")}</label>
          <select id="role" value={role} onChange={(e) => setRole(e.target.value)}>
            {roles.map((r) => (
              <option key={r.name}>{r.name}</option>
            ))}
          </select>
          <span className="hint">{t("You can only grant roles whose permissions you hold yourself.")}</span>
        </div>
        <div className="modal-actions">
          <button type="button" onClick={onClose}>
            {t("Cancel")}
          </button>
          <button className="primary" disabled={busy}>
            {t("Grant")}
          </button>
        </div>
      </form>
    </Modal>
  );
}

// ------------------------------------------------------------------ audit

export function Audit() {
  const { org } = useParams();
  const { t } = useI18n();
  const { dateTime } = useFormat();
  const [pages, setPages] = useState<AuditEntry[][]>([]);
  const [error, setError] = useState<unknown>();
  const [open, setOpen] = useState<number | null>(null);
  const entries = pages.flat();

  const load = (before?: number) =>
    api
      .get<AuditEntry[]>(`/orgs/${org}/audit?limit=50${before ? `&before=${before}` : ""}`)
      .then((p) => setPages((prev) => (before ? [...prev, p] : [p])), setError);

  useEffect(() => {
    setPages([]);
    load();
  }, [org]);

  return (
    <>
      <PageHead title={t("Audit log")} sub={t("Every change, by whom and from where.")} />
      <ErrorBox error={error} />
      <div className="card flush">
        {entries.length ? (
          <table>
            <thead>
              <tr>
                <th>{t("When")}</th>
                <th>{t("Action")}</th>
                <th>{t("Actor")}</th>
                <th>{t("Object")}</th>
                <th>{t("From")}</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <Fragment key={e.id}>
                  <tr className="link" onClick={() => setOpen(open === e.id ? null : e.id)}>
                    <td className="nowrap muted">{dateTime(e.at)}</td>
                    <td>
                      <code>{e.action}</code>
                    </td>
                    <td className="small">
                      {e.actorType} <span className="mono muted">{e.actorId.slice(0, 8)}</span>
                    </td>
                    <td className="small">
                      {e.objectType} <span className="mono muted">{e.objectId.slice(0, 8)}</span>
                    </td>
                    <td className="mono small muted">{e.sourceIp}</td>
                  </tr>
                  {open === e.id && (
                    <tr>
                      <td colSpan={5}>
                        <pre className="mono small" style={{ margin: 0, whiteSpace: "pre-wrap" }}>
                          {JSON.stringify({ before: e.before, after: e.after }, null, 2)}
                        </pre>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty title={t("Nothing recorded yet")} />
        )}
      </div>
      {pages.length > 0 && pages[pages.length - 1].length === 50 && (
        <button onClick={() => load(entries[entries.length - 1].id)}>{t("Load older")}</button>
      )}
    </>
  );
}

// ------------------------------------------------------------------ jobs

export function Jobs() {
  const { org, project } = useParams();
  const { t } = useI18n();
  const { dateTime, relative } = useFormat();
  const jobs = useLoad(() => api.get<Job[]>(`/orgs/${org}/projects/${project}/jobs`), [org, project]);
  const kind = (s: string) => ({ done: "ok", failed: "bad", queued: "info", running: "warn" })[s] as "ok" | "bad" | "info" | "warn" | undefined;
  return (
    <>
      <PageHead title={t("Jobs")} sub={t("Background issuance work. Failed attempts are retried with increasing delays.")}>
        <button onClick={jobs.reload}>{t("Refresh")}</button>
      </PageHead>
      <ErrorBox error={jobs.error} />
      <div className="card flush">
        {jobs.data?.length ? (
          <table>
            <thead>
              <tr>
                <th>{t("Created")}</th>
                <th>{t("Type")}</th>
                <th>{t("Status")}</th>
                <th>{t("Attempts")}</th>
                <th>{t("Next try")}</th>
                <th>{t("Last error")}</th>
              </tr>
            </thead>
            <tbody>
              {jobs.data.map((j) => (
                <tr key={j.id}>
                  <td className="nowrap muted">{dateTime(j.createdAt)}</td>
                  <td>{j.type}</td>
                  <td>
                    <Badge kind={kind(j.status)}>{j.status}</Badge>
                  </td>
                  <td>{j.attempts}</td>
                  <td className="nowrap muted">{j.status === "queued" ? relative(j.runAfter) : "—"}</td>
                  <td className="mono small" style={{ maxWidth: 420 }}>
                    {j.lastError}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : jobs.loading ? (
          <Loading />
        ) : (
          <Empty title={t("No jobs yet")} />
        )}
      </div>
    </>
  );
}
