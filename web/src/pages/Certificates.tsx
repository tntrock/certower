import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, type Certificate, type DeploymentView, type PluginConfig, type PluginMeta, type Target, type Version } from "../api";
import {
  Badge, CertStatusBadge, Empty, ErrorBox, ExpiryBadge, Loading, Modal, PageHead, useAction, useFormat, useLoad,
} from "../components/ui";
import { useI18n } from "../i18n";
import { SLUG_PATTERN } from "../patterns";

const keyTypes = ["ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-3072", "rsa-4096"];

function useProjectPath() {
  const { org, project } = useParams();
  return { org: org!, project: project!, base: `/orgs/${org}/projects/${project}`, ui: `/o/${org}/p/${project}` };
}

// ------------------------------------------------------------------ list

export function CertificateList() {
  const { base, ui, project } = useProjectPath();
  const { t } = useI18n();
  const { date } = useFormat();
  const navigate = useNavigate();
  const [filter, setFilter] = useState("");
  const certs = useLoad(() => api.get<Certificate[]>(`${base}/certificates`), [base]);

  const stats = useMemo(() => {
    const list = certs.data ?? [];
    const soon = list.filter((c) => c.current && new Date(c.current.notAfter).getTime() - Date.now() < 21 * 86400e3).length;
    return {
      total: list.length,
      active: list.filter((c) => c.status === "active").length,
      attention: list.filter((c) => c.status === "failing" || c.status === "invalid").length,
      soon,
    };
  }, [certs.data]);

  const shown = (certs.data ?? []).filter(
    (c) => !filter || c.name.includes(filter.toLowerCase()) || c.names.some((n) => n.includes(filter.toLowerCase())),
  );

  return (
    <>
      <PageHead title={t("Certificates")} sub={project}>
        <Link className="btn primary" to={`${ui}/certificates/new`}>
          {t("New certificate")}
        </Link>
      </PageHead>
      <ErrorBox error={certs.error} />
      {certs.data && certs.data.length > 0 && (
        <div className="stats">
          <div className="stat">
            <div className="n">{stats.total}</div>
            <div className="l">{t("Certificates")}</div>
          </div>
          <div className="stat ok">
            <div className="n">{stats.active}</div>
            <div className="l">{t("Active")}</div>
          </div>
          <div className={"stat " + (stats.soon ? "warn" : "")}>
            <div className="n">{stats.soon}</div>
            <div className="l">{t("Expiring within 21 days")}</div>
          </div>
          <div className={"stat " + (stats.attention ? "bad" : "")}>
            <div className="n">{stats.attention}</div>
            <div className="l">{t("Need attention")}</div>
          </div>
        </div>
      )}
      <div className="card flush">
        {certs.loading && !certs.data ? (
          <Loading />
        ) : !certs.data?.length ? (
          <Empty title={t("No certificates yet")}>
            <p>{t("Set up an issuer under Integrations, then request your first certificate.")}</p>
            <Link className="btn primary" to={`${ui}/certificates/new`}>
              {t("New certificate")}
            </Link>
          </Empty>
        ) : (
          <>
            <div style={{ padding: 12, borderBottom: "1px solid var(--border)" }}>
              <input placeholder={t("Filter by name…")} value={filter} onChange={(e) => setFilter(e.target.value)} aria-label={t("Filter by name…")} />
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>{t("Name")}</th>
                    <th>{t("Domains")}</th>
                    <th>{t("Status")}</th>
                    <th>{t("Expires")}</th>
                    <th>{t("Renews")}</th>
                    <th>{t("Key")}</th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map((c) => (
                    <tr key={c.id} className="link" onClick={() => navigate(`${ui}/certificates/${c.name}`)}>
                      <td>
                        <Link to={`${ui}/certificates/${c.name}`}>{c.name}</Link>
                      </td>
                      <td>
                        {c.names.slice(0, 3).map((n) => (
                          <span className="tag" key={n}>
                            {n}
                          </span>
                        ))}
                        {c.names.length > 3 && <span className="muted small">+{c.names.length - 3}</span>}
                      </td>
                      <td>
                        <CertStatusBadge status={c.status} />
                      </td>
                      <td className="nowrap">
                        <ExpiryBadge notAfter={c.current?.notAfter} />
                      </td>
                      <td className="muted nowrap">{date(c.current?.renewAfter)}</td>
                      <td className="muted small">{c.keyLocation === "agent" ? t("On agent") : t("On server")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </>
  );
}

// ------------------------------------------------------------------ create

export function NewCertificate() {
  const { base, ui } = useProjectPath();
  const { t } = useI18n();
  const navigate = useNavigate();
  const configs = useLoad(() => api.get<PluginConfig[]>(`${base}/configs`), [base]);
  const plugins = useLoad(() => api.get<Record<string, PluginMeta[]>>("/plugins"), []);
  const [form, setForm] = useState({ name: "", names: "", keyType: "ecdsa-p256", keyLocation: "server", issuer: "", dns: "", profile: "", ownerEmail: "" });
  const { busy, error, run } = useAction();
  const set = (k: keyof typeof form, v: string) => setForm((f) => ({ ...f, [k]: v }));

  const issuers = (configs.data ?? []).filter((c) => c.kind === "issuer");
  const dnsConfigs = (configs.data ?? []).filter((c) => c.kind === "dns");
  const issuerCfg = issuers.find((c) => c.name === form.issuer);
  const needsDNS = !!plugins.data?.issuer?.find((p) => p.name === issuerCfg?.plugin)?.requiresDns;

  useEffect(() => {
    if (!form.issuer && issuers.length) set("issuer", issuers[0].name);
    if (!form.dns && dnsConfigs.length) set("dns", dnsConfigs[0].name);
  }, [configs.data]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const names = form.names.split(/[\s,]+/).filter(Boolean);
    const res = await run(() =>
      api.post(`${base}/certificates`, {
        name: form.name,
        names,
        keyType: form.keyType,
        keyLocation: form.keyLocation,
        issuer: form.issuer,
        dns: form.dns || undefined,
        profile: form.profile || undefined,
        ownerEmail: form.ownerEmail || undefined,
      }),
    );
    if (res !== undefined) navigate(`${ui}/certificates/${form.name}`);
  };

  return (
    <>
      <PageHead title={t("New certificate")} crumbs={<Link to={ui}>{t("Certificates")}</Link>} />
      <form className="card" onSubmit={submit} style={{ maxWidth: 720 }}>
        <ErrorBox error={error || configs.error} />
        {configs.data && issuers.length === 0 && (
          <div className="alert warn">
            {t("No issuer is configured yet.")} <Link to={`${ui}/configs`}>{t("Add one")}</Link>
          </div>
        )}
        <div className="field">
          <label htmlFor="name">{t("Name")} *</label>
          <input id="name" required pattern={SLUG_PATTERN} value={form.name} onChange={(e) => set("name", e.target.value)} placeholder="www" />
          <span className="hint">{t("A short identifier, e.g. www or api.")}</span>
        </div>
        <div className="field">
          <label htmlFor="names">{t("Domain names")} *</label>
          <textarea id="names" required value={form.names} onChange={(e) => set("names", e.target.value)} placeholder={"www.example.com\nexample.com"} />
          <span className="hint">{t("One per line. The first becomes the subject. Wildcards need allowWildcard in the policy.")}</span>
        </div>
        <div className="form-row">
          <div className="field">
            <label htmlFor="issuer">{t("Issuer")} *</label>
            <select id="issuer" required value={form.issuer} onChange={(e) => set("issuer", e.target.value)}>
              {issuers.map((c) => (
                <option key={c.id} value={c.name}>
                  {c.name} ({c.plugin})
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="dns">
              {t("DNS provider")}
              {needsDNS && " *"}
            </label>
            <select id="dns" required={needsDNS} value={form.dns} onChange={(e) => set("dns", e.target.value)}>
              <option value="">{t("None")}</option>
              {dnsConfigs.map((c) => (
                <option key={c.id} value={c.name}>
                  {c.name} ({c.plugin})
                </option>
              ))}
            </select>
            {needsDNS && <span className="hint">{t("This issuer validates domains with DNS-01.")}</span>}
          </div>
        </div>
        <div className="form-row">
          <div className="field">
            <label htmlFor="keyType">{t("Key type")}</label>
            <select id="keyType" value={form.keyType} onChange={(e) => set("keyType", e.target.value)}>
              {keyTypes.map((k) => (
                <option key={k}>{k}</option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="profile">{t("ACME profile")}</label>
            <input id="profile" value={form.profile} onChange={(e) => set("profile", e.target.value)} placeholder={t("CA default")} />
          </div>
        </div>
        <fieldset>
          <legend>{t("Where is the private key kept?")}</legend>
          <label className="check">
            <input type="radio" name="keyLocation" checked={form.keyLocation === "server"} onChange={() => set("keyLocation", "server")} />
            <span>
              <b>{t("On the Certower server")}</b> — {t("encrypted; issued immediately.")}
            </span>
          </label>
          <label className="check">
            <input type="radio" name="keyLocation" checked={form.keyLocation === "agent"} onChange={() => set("keyLocation", "agent")} />
            <span>
              <b>{t("On an agent's host")}</b> — {t("never leaves the host; issued once attached to a target.")}
            </span>
          </label>
        </fieldset>
        <div className="field">
          <label htmlFor="owner">{t("Owner email")}</label>
          <input id="owner" type="email" value={form.ownerEmail} onChange={(e) => set("ownerEmail", e.target.value)} />
        </div>
        <div className="actions">
          <button className="primary" disabled={busy || issuers.length === 0}>
            {t("Request certificate")}
          </button>
          <Link className="btn" to={ui}>
            {t("Cancel")}
          </Link>
        </div>
      </form>
    </>
  );
}

// ------------------------------------------------------------------ detail

const revokeReasons: [number, string][] = [
  [0, "Unspecified"],
  [1, "Key compromise"],
  [3, "Affiliation changed"],
  [4, "Superseded"],
  [5, "Cessation of operation"],
];

export function CertificateDetail() {
  const { base, ui } = useProjectPath();
  const { cert } = useParams();
  const { t } = useI18n();
  const { date, dateTime, relative } = useFormat();
  const navigate = useNavigate();
  const path = `${base}/certificates/${cert}`;
  const c = useLoad(() => api.get<Certificate>(path), [path]);
  const versions = useLoad(() => api.get<Version[]>(`${path}/versions`), [path]);
  const deps = useLoad(() => api.get<DeploymentView[]>(`${path}/deployments`), [path]);
  const [modal, setModal] = useState<"revoke" | "delete" | "attach" | null>(null);
  const action = useAction();
  const [notice, setNotice] = useState("");

  const reloadAll = () => {
    c.reload();
    versions.reload();
    deps.reload();
  };

  // While something is in progress, refresh every few seconds.
  const busyState = c.data && (c.data.status === "pending" || c.data.status === "failing" || deps.data?.some((d) => d.status === "pending"));
  useEffect(() => {
    if (!busyState) return;
    const id = setInterval(reloadAll, 5000);
    return () => clearInterval(id);
  }, [busyState, path]);

  if (c.loading && !c.data) return <Loading />;
  if (!c.data) return <ErrorBox error={c.error} />;
  const x = c.data;

  const renew = async () => {
    const r = await action.run(() => api.post<{ waitingFor?: string }>(`${path}/renew`));
    if (r !== undefined) {
      setNotice(r.waitingFor === "agent" ? t("The agent will generate a new key and request the certificate on its next sync.") : t("Renewal queued."));
      reloadAll();
    }
  };

  return (
    <>
      <PageHead
        title={x.name}
        crumbs={<Link to={ui}>{t("Certificates")}</Link>}
        sub={
          <span className="actions" style={{ alignItems: "center" }}>
            <CertStatusBadge status={x.status} />
            {x.current && <ExpiryBadge notAfter={x.current.notAfter} />}
          </span>
        }
      >
        <button onClick={renew} disabled={action.busy}>
          {t("Renew now")}
        </button>
        {x.current && (
          <a className="btn" href={`/api/v1${path}/versions/current/chain.pem`} download={`${x.name}.pem`}>
            {t("Download chain")}
          </a>
        )}
        {x.current && (
          <button className="danger" onClick={() => setModal("revoke")}>
            {t("Revoke")}
          </button>
        )}
        <button className="danger" onClick={() => setModal("delete")}>
          {t("Delete")}
        </button>
      </PageHead>

      <ErrorBox error={action.error} />
      {notice && <div className="alert ok">{notice}</div>}
      {x.lastError && (
        <div className={"alert " + (x.status === "invalid" ? "bad" : "warn")}>
          <b>{x.status === "invalid" ? t("Issuance stopped until the cause is fixed:") : t("The last attempt failed and will be retried:")}</b>{" "}
          <span className="mono">{x.lastError}</span>
        </div>
      )}
      {x.keyLocation === "agent" && !x.current && (deps.data?.length ?? 0) === 0 && (
        <div className="alert info">{t("This certificate's key is generated on an agent. Attach a target on an agent to start issuance.")}</div>
      )}

      <div className="grid-2">
        <div className="card">
          <h2>{t("Details")}</h2>
          <dl className="kv">
            <dt>{t("Domains")}</dt>
            <dd>
              {x.names.map((n) => (
                <span className="tag" key={n}>
                  {n}
                </span>
              ))}
            </dd>
            <dt>{t("Key")}</dt>
            <dd>
              {x.keyType} · {x.keyLocation === "agent" ? t("On agent") : t("On server")}
            </dd>
            {x.profile && (
              <>
                <dt>{t("ACME profile")}</dt>
                <dd>{x.profile}</dd>
              </>
            )}
            {x.ownerEmail && (
              <>
                <dt>{t("Owner")}</dt>
                <dd>{x.ownerEmail}</dd>
              </>
            )}
            <dt>{t("Created")}</dt>
            <dd>{date(x.createdAt)}</dd>
          </dl>
        </div>
        <div className="card">
          <h2>{t("Current version")}</h2>
          {x.current ? (
            <dl className="kv">
              <dt>{t("Valid")}</dt>
              <dd>
                {date(x.current.notBefore)} – {date(x.current.notAfter)}
              </dd>
              <dt>{t("Renews")}</dt>
              <dd>
                {dateTime(x.current.renewAfter)} <span className="muted">({relative(x.current.renewAfter)})</span>
              </dd>
              {x.current.ariCheckedAt && (
                <>
                  <dt>{t("Renewal window")}</dt>
                  <dd>{t("Checked with the CA (ARI) {when}", { when: relative(x.current.ariCheckedAt) })}</dd>
                </>
              )}
              <dt>{t("Serial")}</dt>
              <dd className="mono">{x.current.serial}</dd>
              <dt>SHA-256</dt>
              <dd className="mono small">{x.current.fingerprint}</dd>
            </dl>
          ) : (
            <p className="muted">{t("Not issued yet.")}</p>
          )}
        </div>
      </div>

      {x.keyLocation === "agent" && (
        <div className="card flush">
          <div className="page-head" style={{ padding: "16px 20px 0", marginBottom: 12 }}>
            <h2 style={{ margin: 0 }}>{t("Deployments")}</h2>
            <button className="small" onClick={() => setModal("attach")}>
              {t("Attach target")}
            </button>
          </div>
          {deps.data?.length ? (
            <table>
              <thead>
                <tr>
                  <th>{t("Target")}</th>
                  <th>{t("Status")}</th>
                  <th>{t("Message")}</th>
                  <th>{t("When")}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {deps.data.map((d) => (
                  <tr key={d.targetId}>
                    <td>{d.target}</td>
                    <td>
                      {d.status === "done" ? (
                        <Badge kind={d.current ? "ok" : "warn"}>{d.current ? t("Current") : t("Outdated")}</Badge>
                      ) : d.status === "failed" ? (
                        <Badge kind="bad">{t("Failed")}</Badge>
                      ) : (
                        <Badge kind="info">{t("Waiting")}</Badge>
                      )}
                    </td>
                    <td className="small mono" style={{ maxWidth: 420 }}>
                      {d.message}
                    </td>
                    <td className="muted nowrap">{d.finishedAt ? relative(d.finishedAt) : "—"}</td>
                    <td className="right">
                      <button
                        className="small danger"
                        onClick={() =>
                          action.run(() => api.del(`${path}/targets/${d.target}`)).then(() => deps.reload())
                        }
                      >
                        {t("Detach")}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty title={t("Not deployed anywhere")} />
          )}
        </div>
      )}

      <div className="card flush">
        <h2 style={{ padding: "16px 20px 0" }}>{t("History")}</h2>
        {versions.data?.length ? (
          <table>
            <thead>
              <tr>
                <th>{t("Issued")}</th>
                <th>{t("Valid until")}</th>
                <th>{t("Serial")}</th>
                <th>{t("State")}</th>
              </tr>
            </thead>
            <tbody>
              {versions.data.map((v) => (
                <tr key={v.id}>
                  <td className="nowrap">{dateTime(v.createdAt)}</td>
                  <td className="nowrap">{date(v.notAfter)}</td>
                  <td className="mono small">{v.serial}</td>
                  <td>
                    {v.revokedAt ? (
                      <Badge kind="bad">{t("Revoked")}</Badge>
                    ) : v.id === x.current?.id ? (
                      <Badge kind="ok">{t("Current")}</Badge>
                    ) : (
                      <Badge>{t("Replaced")}</Badge>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty title={t("No versions yet")} />
        )}
      </div>

      {modal === "revoke" && x.current && (
        <RevokeModal path={path} onClose={() => setModal(null)} onDone={reloadAll} />
      )}
      {modal === "delete" && (
        <Modal title={t("Delete certificate")} onClose={() => setModal(null)}>
          <p>{t("Certower stops managing this certificate and erases its stored keys. It is not revoked; revoke it first if the key may be compromised.")}</p>
          <div className="modal-actions">
            <button onClick={() => setModal(null)}>{t("Cancel")}</button>
            <button
              className="primary"
              onClick={async () => {
                const ok = await action.run(() => api.del(path).then(() => true));
                if (ok) navigate(ui);
              }}
            >
              {t("Delete")}
            </button>
          </div>
        </Modal>
      )}
      {modal === "attach" && <AttachModal path={path} onClose={() => setModal(null)} onDone={deps.reload} />}
    </>
  );
}

function RevokeModal({ path, onClose, onDone }: { path: string; onClose: () => void; onDone: () => void }) {
  const { t } = useI18n();
  const [reason, setReason] = useState(4);
  const { busy, error, run } = useAction();
  return (
    <Modal title={t("Revoke current version")} onClose={onClose}>
      <ErrorBox error={error} />
      <p>{t("The CA will mark the certificate as revoked. Certower then issues a replacement automatically.")}</p>
      <div className="field">
        <label htmlFor="reason">{t("Reason")}</label>
        <select id="reason" value={reason} onChange={(e) => setReason(Number(e.target.value))}>
          {revokeReasons.map(([code, label]) => (
            <option key={code} value={code}>
              {t(label)}
            </option>
          ))}
        </select>
      </div>
      <div className="modal-actions">
        <button onClick={onClose}>{t("Cancel")}</button>
        <button
          className="primary"
          disabled={busy}
          onClick={async () => {
            const ok = await run(() => api.post(`${path}/revoke`, { reason }).then(() => true));
            if (ok) {
              onDone();
              onClose();
            }
          }}
        >
          {t("Revoke")}
        </button>
      </div>
    </Modal>
  );
}

function AttachModal({ path, onClose, onDone }: { path: string; onClose: () => void; onDone: () => void }) {
  const { base } = useProjectPath();
  const { t } = useI18n();
  const targets = useLoad(() => api.get<Target[]>(`${base}/targets`), [base]);
  const [target, setTarget] = useState("");
  const { busy, error, run } = useAction();
  return (
    <Modal title={t("Attach target")} onClose={onClose}>
      <ErrorBox error={error || targets.error} />
      {targets.data && targets.data.length === 0 ? (
        <p>{t("There are no targets yet. Create one under Agents & targets.")}</p>
      ) : (
        <div className="field">
          <label htmlFor="target">{t("Target")}</label>
          <select id="target" value={target} onChange={(e) => setTarget(e.target.value)}>
            <option value="">{t("Choose…")}</option>
            {targets.data?.map((x) => (
              <option key={x.id} value={x.name}>
                {x.name} ({x.deployer})
              </option>
            ))}
          </select>
        </div>
      )}
      <div className="modal-actions">
        <button onClick={onClose}>{t("Cancel")}</button>
        <button
          className="primary"
          disabled={busy || !target}
          onClick={async () => {
            const ok = await run(() => api.post(`${path}/targets`, { target }).then(() => true));
            if (ok) {
              onDone();
              onClose();
            }
          }}
        >
          {t("Attach")}
        </button>
      </div>
    </Modal>
  );
}
