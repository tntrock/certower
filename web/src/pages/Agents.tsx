import { useState, type FormEvent } from "react";
import { useParams } from "react-router-dom";
import { api, type Agent, type Target } from "../api";
import { Badge, CopyField, Empty, ErrorBox, Loading, Modal, PageHead, useAction, useFormat, useLoad } from "../components/ui";
import { useI18n } from "../i18n";
import { SLUG_PATTERN } from "../patterns";

// An agent counts as online if it synced within this window (it syncs
// every 30 seconds).
const onlineWindow = 3 * 60e3;

export function Agents() {
  const { org, project } = useParams();
  const base = `/orgs/${org}/projects/${project}`;
  const { t } = useI18n();
  const { relative, dateTime } = useFormat();
  const agents = useLoad(() => api.get<Agent[]>(`${base}/agents`), [base]);
  const targets = useLoad(() => api.get<Target[]>(`${base}/targets`), [base]);
  const [modal, setModal] = useState<"agent" | "target" | null>(null);
  const del = useAction();

  const agentName = (id: string) => agents.data?.find((a) => a.id === id)?.name ?? id.slice(0, 8);

  const agentState = (a: Agent) => {
    if (!a.enrolled) {
      const expired = a.enrollExpiresAt && new Date(a.enrollExpiresAt).getTime() < Date.now();
      return expired ? <Badge kind="bad">{t("Invitation expired")}</Badge> : <Badge kind="info">{t("Awaiting enrollment")}</Badge>;
    }
    const online = a.lastSeenAt && Date.now() - new Date(a.lastSeenAt).getTime() < onlineWindow;
    return online ? <Badge kind="ok">{t("Online")}</Badge> : <Badge kind="warn">{t("Offline")}</Badge>;
  };

  return (
    <>
      <PageHead title={t("Agents & targets")} sub={t("Agents run on your hosts, keep private keys there, and install certificates into services.")}>
        <button onClick={() => setModal("target")} disabled={!agents.data?.some((a) => a.enrolled)}>
          {t("New target")}
        </button>
        <button className="primary" onClick={() => setModal("agent")}>
          {t("Add agent")}
        </button>
      </PageHead>
      <ErrorBox error={agents.error || targets.error || del.error} />

      <div className="card flush">
        <h2 style={{ padding: "16px 20px 0" }}>{t("Agents")}</h2>
        {agents.loading && !agents.data ? (
          <Loading />
        ) : agents.data?.length ? (
          <table>
            <thead>
              <tr>
                <th>{t("Name")}</th>
                <th>{t("State")}</th>
                <th>{t("Host")}</th>
                <th>{t("Version")}</th>
                <th>{t("Last seen")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {agents.data.map((a) => (
                <tr key={a.id}>
                  <td>
                    <b>{a.name}</b>
                  </td>
                  <td>{agentState(a)}</td>
                  <td>
                    {a.hostname || "—"} <span className="muted small">{a.os}</span>
                  </td>
                  <td className="mono small">{a.version || "—"}</td>
                  <td className="muted nowrap" title={dateTime(a.lastSeenAt)}>
                    {a.lastSeenAt ? relative(a.lastSeenAt) : "—"}
                  </td>
                  <td className="right">
                    <button
                      className="small danger"
                      onClick={() => {
                        if (confirm(t("Remove agent {name}? It is disconnected immediately and its targets are deleted.", { name: a.name })))
                          del.run(() => api.del(`${base}/agents/${a.name}`)).then(() => (agents.reload(), targets.reload()));
                      }}
                    >
                      {t("Remove")}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty title={t("No agents yet")}>{t("Add an agent, then run the enroll command it gives you on the host.")}</Empty>
        )}
      </div>

      <div className="card flush">
        <h2 style={{ padding: "16px 20px 0" }}>{t("Targets")}</h2>
        {targets.data?.length ? (
          <table>
            <thead>
              <tr>
                <th>{t("Name")}</th>
                <th>{t("Agent")}</th>
                <th>{t("Deployer")}</th>
                <th>{t("Files")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {targets.data.map((tg) => (
                <tr key={tg.id}>
                  <td>
                    <b>{tg.name}</b>
                  </td>
                  <td>{agentName(tg.agentId)}</td>
                  <td>
                    <Badge>{tg.deployer}</Badge>
                  </td>
                  <td className="mono small">
                    {["fullchainPath", "certPath", "keyPath"]
                      .filter((k) => tg.settings[k])
                      .map((k) => (
                        <div key={k}>{String(tg.settings[k])}</div>
                      ))}
                  </td>
                  <td className="right">
                    <button
                      className="small danger"
                      onClick={() => {
                        if (confirm(t("Delete {name}?", { name: tg.name }))) del.run(() => api.del(`${base}/targets/${tg.name}`)).then(targets.reload);
                      }}
                    >
                      {t("Delete")}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty title={t("No targets yet")}>{t("A target is a service on an agent's host, such as an nginx server.")}</Empty>
        )}
      </div>

      {modal === "agent" && <AddAgentModal base={base} onClose={() => setModal(null)} onDone={agents.reload} />}
      {modal === "target" && <AddTargetModal base={base} agents={(agents.data ?? []).filter((a) => a.enrolled)} onClose={() => setModal(null)} onDone={targets.reload} />}
    </>
  );
}

function AddAgentModal({ base, onClose, onDone }: { base: string; onClose: () => void; onDone: () => void }) {
  const { t } = useI18n();
  const [name, setName] = useState("");
  const [hours, setHours] = useState(24);
  const [result, setResult] = useState<{ command: string; caSha256: string } | null>(null);
  const { busy, error, run } = useAction();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const r = await run(() => api.post<{ command: string; caSha256: string }>(`${base}/agents`, { name, expiresInHours: hours }));
    if (r) {
      setResult(r);
      onDone();
    }
  };

  return (
    <Modal title={t("Add agent")} onClose={onClose}>
      {result ? (
        <>
          <div className="alert ok">{t("Run this on the host as root. The token works once.")}</div>
          <CopyField value={result.command} />
          <p className="small muted" style={{ marginTop: 12 }}>
            {t("Add -allow-path for each directory the agent may write certificates to (default /etc/certower). Then start \"certower-agent run\", for example as a systemd service.")}
          </p>
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
            <label htmlFor="agentname">{t("Name")} *</label>
            <input id="agentname" required autoFocus pattern={SLUG_PATTERN} value={name} onChange={(e) => setName(e.target.value)} placeholder="web-01" />
          </div>
          <div className="field">
            <label htmlFor="hours">{t("Enrollment token valid for (hours)")}</label>
            <input id="hours" type="number" min={1} max={168} value={hours} onChange={(e) => setHours(Number(e.target.value))} />
          </div>
          <div className="modal-actions">
            <button type="button" onClick={onClose}>
              {t("Cancel")}
            </button>
            <button className="primary" disabled={busy}>
              {t("Create")}
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}

function AddTargetModal({ base, agents, onClose, onDone }: { base: string; agents: Agent[]; onClose: () => void; onDone: () => void }) {
  const { t } = useI18n();
  const [f, setF] = useState({
    name: "",
    agent: agents[0]?.name ?? "",
    deployer: "nginx",
    fullchainPath: "/etc/certower/www/fullchain.pem",
    keyPath: "/etc/certower/www/privkey.pem",
    certPath: "",
    reloadCommand: "",
    verifyEndpoint: "",
    verifyServerName: "",
  });
  const { busy, error, run } = useAction();
  const set = (k: keyof typeof f, v: string) => setF((x) => ({ ...x, [k]: v }));

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const settings: Record<string, unknown> = { keyPath: f.keyPath };
    if (f.fullchainPath) settings.fullchainPath = f.fullchainPath;
    if (f.certPath) settings.certPath = f.certPath;
    if (f.reloadCommand) settings.reloadCommand = f.reloadCommand.trim().split(/\s+/);
    if (f.verifyEndpoint) settings.verifyEndpoint = f.verifyEndpoint;
    if (f.verifyServerName) settings.verifyServerName = f.verifyServerName;
    const ok = await run(() => api.post(`${base}/targets`, { name: f.name, agent: f.agent, deployer: f.deployer, settings }).then(() => true));
    if (ok) {
      onDone();
      onClose();
    }
  };

  return (
    <Modal title={t("New target")} onClose={onClose}>
      <form onSubmit={submit}>
        <ErrorBox error={error} />
        <div className="form-row">
          <div className="field">
            <label htmlFor="tname">{t("Name")} *</label>
            <input id="tname" required pattern={SLUG_PATTERN} value={f.name} onChange={(e) => set("name", e.target.value)} placeholder="web-01-nginx" />
          </div>
          <div className="field">
            <label htmlFor="tagent">{t("Agent")}</label>
            <select id="tagent" value={f.agent} onChange={(e) => set("agent", e.target.value)}>
              {agents.map((a) => (
                <option key={a.id}>{a.name}</option>
              ))}
            </select>
          </div>
        </div>
        <div className="field">
          <label htmlFor="tdeployer">{t("Deployer")}</label>
          <select id="tdeployer" value={f.deployer} onChange={(e) => set("deployer", e.target.value)}>
            <option value="nginx">nginx</option>
            <option value="files">{t("files (any service)")}</option>
          </select>
          <span className="hint">
            {f.deployer === "nginx"
              ? t("Runs nginx -t and nginx -s reload, then checks 127.0.0.1:443 serves the new certificate.")
              : t("Writes the files and optionally runs a reload command allowed on the host.")}
          </span>
        </div>
        <div className="field">
          <label htmlFor="fullchain">{t("Full chain path")}</label>
          <input id="fullchain" required={f.deployer === "nginx"} value={f.fullchainPath} onChange={(e) => set("fullchainPath", e.target.value)} className="mono" />
        </div>
        <div className="field">
          <label htmlFor="keypath">{t("Private key path")} *</label>
          <input id="keypath" required value={f.keyPath} onChange={(e) => set("keyPath", e.target.value)} className="mono" />
        </div>
        {f.deployer === "files" && (
          <>
            <div className="field">
              <label htmlFor="certpath">{t("Leaf certificate path")}</label>
              <input id="certpath" value={f.certPath} onChange={(e) => set("certPath", e.target.value)} className="mono" />
            </div>
            <div className="field">
              <label htmlFor="reload">{t("Reload command")}</label>
              <input id="reload" value={f.reloadCommand} onChange={(e) => set("reloadCommand", e.target.value)} className="mono" placeholder="systemctl reload apache2" />
              <span className="hint">{t("Must be listed in allowedCommands in the agent's agent.json.")}</span>
            </div>
          </>
        )}
        <div className="form-row">
          <div className="field">
            <label htmlFor="verify">{t("Verify at (host:port)")}</label>
            <input id="verify" value={f.verifyEndpoint} onChange={(e) => set("verifyEndpoint", e.target.value)} placeholder={f.deployer === "nginx" ? "127.0.0.1:443" : ""} className="mono" />
          </div>
          <div className="field">
            <label htmlFor="sni">{t("Server name (SNI)")}</label>
            <input id="sni" value={f.verifyServerName} onChange={(e) => set("verifyServerName", e.target.value)} placeholder={t("First domain")} />
          </div>
        </div>
        <div className="modal-actions">
          <button type="button" onClick={onClose}>
            {t("Cancel")}
          </button>
          <button className="primary" disabled={busy || !f.agent}>
            {t("Create")}
          </button>
        </div>
      </form>
    </Modal>
  );
}
