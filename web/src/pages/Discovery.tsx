import { Fragment, useMemo, useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import { api, type DiscoveryEndpoint, type Finding, type Project } from "../api";
import { Badge, Empty, ErrorBox, ExpiryBadge, Loading, Modal, PageHead, useAction, useFormat, useLoad } from "../components/ui";
import { useI18n } from "../i18n";

const rank = { critical: 2, warning: 1, info: 0 } as const;

function worst(fs?: Finding[]) {
  return (fs ?? []).reduce<Finding | undefined>((w, f) => (!w || rank[f.severity] > rank[w.severity] ? f : w), undefined);
}

export function Discovery() {
  const { org } = useParams();
  const { t } = useI18n();
  const { relative } = useFormat();
  const eps = useLoad(() => api.get<DiscoveryEndpoint[]>(`/orgs/${org}/discovery`), [org]);
  const [adding, setAdding] = useState(false);
  const [filter, setFilter] = useState<"all" | "problems" | "unmanaged">("all");
  const [open, setOpen] = useState<string | null>(null);
  const action = useAction();

  const list = eps.data ?? [];
  const stats = useMemo(
    () => ({
      total: list.length,
      problems: list.filter((e) => e.lastError || (e.certificate?.findings ?? []).some((f) => f.severity !== "info")).length,
      unmanaged: list.filter((e) => e.certificate && !e.managed).length,
      managed: list.filter((e) => e.managed).length,
    }),
    [list],
  );
  const shown = list.filter((e) =>
    filter === "problems"
      ? e.lastError || (e.certificate?.findings ?? []).some((f) => f.severity !== "info")
      : filter === "unmanaged"
        ? e.certificate && !e.managed
        : true,
  );

  return (
    <>
      <PageHead title={t("Discovery")} sub={t("Find every certificate your services present, including ones Certower does not manage. Endpoints are scanned every 12 hours.")}>
        <button onClick={eps.reload}>{t("Refresh")}</button>
        <button className="primary" onClick={() => setAdding(true)}>
          {t("Add endpoints")}
        </button>
      </PageHead>
      <ErrorBox error={eps.error || action.error} />

      {list.length > 0 && (
        <div className="stats">
          <div className="stat">
            <div className="n">{stats.total}</div>
            <div className="l">{t("Endpoints")}</div>
          </div>
          <div className="stat ok">
            <div className="n">{stats.managed}</div>
            <div className="l">{t("Managed by Certower")}</div>
          </div>
          <div className={"stat " + (stats.unmanaged ? "warn" : "")}>
            <div className="n">{stats.unmanaged}</div>
            <div className="l">{t("Unmanaged")}</div>
          </div>
          <div className={"stat " + (stats.problems ? "bad" : "")}>
            <div className="n">{stats.problems}</div>
            <div className="l">{t("With problems")}</div>
          </div>
        </div>
      )}

      <div className="card flush">
        {eps.loading && !eps.data ? (
          <Loading />
        ) : list.length === 0 ? (
          <Empty title={t("No endpoints yet")}>
            <p>{t("Paste the hosts you run, one per line, and Certower checks what they serve.")}</p>
            <button className="primary" onClick={() => setAdding(true)}>
              {t("Add endpoints")}
            </button>
          </Empty>
        ) : (
          <>
            <div className="tabs" style={{ padding: "0 12px", marginBottom: 0 }}>
              {(["all", "problems", "unmanaged"] as const).map((f) => (
                <button key={f} className={filter === f ? "active" : ""} onClick={() => setFilter(f)}>
                  {{ all: t("All"), problems: t("With problems"), unmanaged: t("Unmanaged") }[f]}
                </button>
              ))}
            </div>
            <table>
              <thead>
                <tr>
                  <th>{t("Endpoint")}</th>
                  <th>{t("Certificate")}</th>
                  <th>{t("Expires")}</th>
                  <th>{t("Findings")}</th>
                  <th>{t("Managed")}</th>
                  <th>{t("Scanned")}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {shown.map((e) => {
                  const c = e.certificate;
                  const w = worst(c?.findings);
                  return (
                    <Fragment key={e.id}>
                      <tr className="link" onClick={() => setOpen(open === e.id ? null : e.id)}>
                        <td className="mono">
                          {e.host}:{e.port}
                        </td>
                        <td className="small">
                          {c ? (
                            <>
                              {c.names.slice(0, 2).map((n) => (
                                <span className="tag" key={n}>
                                  {n}
                                </span>
                              ))}
                              <div className="muted">{issuerName(c.issuer)}</div>
                            </>
                          ) : e.lastError ? (
                            <Badge kind="bad">{t("Unreachable")}</Badge>
                          ) : (
                            <span className="muted">{t("Not scanned yet")}</span>
                          )}
                        </td>
                        <td className="nowrap">{c && <ExpiryBadge notAfter={c.notAfter} />}</td>
                        <td>
                          {w ? (
                            <Badge kind={w.severity === "critical" ? "bad" : w.severity === "warning" ? "warn" : "info"}>
                              {(c?.findings.length ?? 0) > 1 ? `${w.code} +${c!.findings.length - 1}` : w.code}
                            </Badge>
                          ) : c ? (
                            <Badge kind="ok">{t("OK")}</Badge>
                          ) : null}
                        </td>
                        <td className="small">
                          {e.managed ? (
                            <Link to={`/o/${org}/p/${e.managed.project}/certificates/${e.managed.certificate}`} onClick={(ev) => ev.stopPropagation()}>
                              {e.managed.certificate}
                            </Link>
                          ) : c ? (
                            <span className="muted">{t("No")}</span>
                          ) : null}
                        </td>
                        <td className="muted nowrap">{e.lastScannedAt ? relative(e.lastScannedAt) : "—"}</td>
                        <td className="right nowrap" onClick={(ev) => ev.stopPropagation()}>
                          <button className="small" onClick={() => action.run(() => api.post(`/orgs/${org}/discovery/${e.id}/scan`)).then(() => setTimeout(eps.reload, 3000))}>
                            {t("Scan now")}
                          </button>{" "}
                          <button
                            className="small danger"
                            onClick={() => {
                              if (confirm(t("Delete {name}?", { name: `${e.host}:${e.port}` })))
                                action.run(() => api.del(`/orgs/${org}/discovery/${e.id}`)).then(eps.reload);
                            }}
                          >
                            {t("Remove")}
                          </button>
                        </td>
                      </tr>
                      {open === e.id && (
                        <tr>
                          <td colSpan={7} style={{ background: "var(--surface-2)" }}>
                            {e.lastError && <div className="alert bad">{e.lastError}</div>}
                            {c && (
                              <dl className="kv">
                                <dt>{t("Subject")}</dt>
                                <dd className="mono small">{c.subject}</dd>
                                <dt>{t("Issuer")}</dt>
                                <dd className="mono small">{c.issuer}</dd>
                                <dt>{t("Names")}</dt>
                                <dd>{c.names.join(", ")}</dd>
                                <dt>SHA-256</dt>
                                <dd className="mono small">{c.fingerprint}</dd>
                                <dt>{t("Findings")}</dt>
                                <dd>
                                  {c.findings.length === 0
                                    ? t("No problems found.")
                                    : c.findings.map((f) => (
                                        <div key={f.code}>
                                          <Badge kind={f.severity === "critical" ? "bad" : f.severity === "warning" ? "warn" : "info"}>{f.code}</Badge> {f.message}
                                        </div>
                                      ))}
                                </dd>
                              </dl>
                            )}
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </>
        )}
      </div>
      {adding && <AddEndpoints org={org!} onClose={() => setAdding(false)} onDone={() => setTimeout(eps.reload, 2500)} />}
    </>
  );
}

function issuerName(dn: string) {
  const cn = /CN=([^,]+)/.exec(dn)?.[1];
  const o = /O=([^,]+)/.exec(dn)?.[1];
  return cn ?? o ?? dn;
}

function AddEndpoints({ org, onClose, onDone }: { org: string; onClose: () => void; onDone: () => void }) {
  const { t } = useI18n();
  const projects = useLoad(() => api.get<Project[]>(`/orgs/${org}/projects`), [org]);
  const [targets, setTargets] = useState("");
  const [project, setProject] = useState("");
  const [result, setResult] = useState<{ added: unknown[]; skipped: string[] } | null>(null);
  const { busy, error, run } = useAction();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const r = await run(() => api.post<{ added: unknown[]; skipped: string[] }>(`/orgs/${org}/discovery`, { targets, project: project || undefined }));
    if (r) {
      setResult(r);
      onDone();
    }
  };

  return (
    <Modal title={t("Add endpoints")} onClose={onClose}>
      {result ? (
        <>
          <div className="alert ok">{t("{n} endpoints added. Scanning has started.", { n: result.added.length })}</div>
          {result.skipped.length > 0 && (
            <div className="alert warn">
              {t("Skipped:")}
              <ul>
                {result.skipped.map((s) => (
                  <li key={s}>{s}</li>
                ))}
              </ul>
            </div>
          )}
          <div className="modal-actions">
            <button className="primary" onClick={onClose}>
              {t("Done")}
            </button>
          </div>
        </>
      ) : (
        <form onSubmit={submit}>
          <ErrorBox error={error} />
          <div className="field">
            <label htmlFor="targets">{t("Endpoints")}</label>
            <textarea id="targets" required value={targets} onChange={(e) => setTargets(e.target.value)} placeholder={"www.example.com\nmail.example.com:465\n10.0.0.12:8443"} style={{ minHeight: 140 }} />
            <span className="hint">{t("One per line: host or host:port (default port 443).")}</span>
          </div>
          <div className="field">
            <label htmlFor="dproject">{t("Project")}</label>
            <select id="dproject" value={project} onChange={(e) => setProject(e.target.value)}>
              <option value="">{t("Organization-wide")}</option>
              {projects.data?.map((p) => (
                <option key={p.id} value={p.slug}>
                  {p.name}
                </option>
              ))}
            </select>
            <span className="hint">{t("Members of the project can see these endpoints, and alerts go to its notifiers.")}</span>
          </div>
          <div className="modal-actions">
            <button type="button" onClick={onClose}>
              {t("Cancel")}
            </button>
            <button className="primary" disabled={busy}>
              {t("Add and scan")}
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}
