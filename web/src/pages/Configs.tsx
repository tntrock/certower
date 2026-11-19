import { useState, type FormEvent } from "react";
import { useParams } from "react-router-dom";
import { api, type CAPreset, type PluginConfig, type PluginMeta } from "../api";
import { SchemaForm } from "../components/SchemaForm";
import { Badge, Empty, ErrorBox, Loading, Modal, PageHead, useAction, useFormat, useLoad } from "../components/ui";
import { useI18n } from "../i18n";
import { SLUG_PATTERN } from "../patterns";

// Configs lists issuers and DNS providers. On a project it shows the
// project's own plus the organization's shared ones.
export function Configs({ scope }: { scope: "org" | "project" }) {
  const { org, project } = useParams();
  const { t } = useI18n();
  const { date } = useFormat();
  const base = scope === "org" ? `/orgs/${org}` : `/orgs/${org}/projects/${project}`;
  const configs = useLoad(() => api.get<PluginConfig[]>(`${base}/configs`), [base]);
  const [adding, setAdding] = useState(false);
  const del = useAction();

  return (
    <>
      <PageHead
        title={scope === "org" ? t("Integrations") : t("Project integrations")}
        sub={
          scope === "org"
            ? t("Shared by every project in the organization.")
            : t("Used only by this project. A project configuration overrides a shared one with the same name.")
        }
      >
        <button className="primary" onClick={() => setAdding(true)}>
          {t("Add integration")}
        </button>
      </PageHead>
      <ErrorBox error={configs.error || del.error} />
      <div className="card flush">
        {configs.loading && !configs.data ? (
          <Loading />
        ) : configs.data?.length ? (
          <table>
            <thead>
              <tr>
                <th>{t("Name")}</th>
                <th>{t("Kind")}</th>
                <th>{t("Plugin")}</th>
                <th>{t("Settings")}</th>
                <th>{t("Scope")}</th>
                <th>{t("Created")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {configs.data.map((c) => {
                const own = scope === "org" ? !c.projectId : !!c.projectId;
                return (
                  <tr key={c.id}>
                    <td>
                      <b>{c.name}</b>
                    </td>
                    <td>
                      <Badge kind={c.kind === "issuer" ? "info" : c.kind === "notifier" ? "warn" : undefined}>
                        {c.kind === "issuer" ? t("Issuer") : c.kind === "dns" ? "DNS" : c.kind === "notifier" ? t("Notifications") : c.kind}
                      </Badge>
                    </td>
                    <td className="mono">{c.plugin}</td>
                    <td className="small mono muted" style={{ maxWidth: 360 }}>
                      {Object.entries(c.config)
                        .filter(([, v]) => typeof v !== "object")
                        .map(([k, v]) => `${k}=${String(v).slice(0, 48)}`)
                        .join("  ")}
                    </td>
                    <td className="muted">{c.projectId ? t("Project") : t("Organization")}</td>
                    <td className="muted nowrap">{date(c.createdAt)}</td>
                    <td className="right nowrap">
                      {own && c.kind === "notifier" && (
                        <button
                          className="small"
                          onClick={() =>
                            del.run(() => api.post(`${base}/configs/${c.id}/test`)).then((r) => r !== undefined && alert(t("Test notification sent.")))
                          }
                        >
                          {t("Send test")}
                        </button>
                      )}{" "}
                      {own && (
                        <button
                          className="small danger"
                          onClick={() => {
                            if (confirm(t("Delete {name}?", { name: c.name }))) del.run(() => api.del(`${base}/configs/${c.id}`)).then(configs.reload);
                          }}
                        >
                          {t("Delete")}
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        ) : (
          <Empty title={t("No integrations yet")}>
            <p>{t("Add an issuer (such as Let's Encrypt or TWCA) and a DNS provider (such as Cloudflare).")}</p>
          </Empty>
        )}
      </div>
      {adding && <AddConfigModal base={base} onClose={() => setAdding(false)} onDone={configs.reload} />}
    </>
  );
}

function AddConfigModal({ base, onClose, onDone }: { base: string; onClose: () => void; onDone: () => void }) {
  const { t } = useI18n();
  const plugins = useLoad(() => api.get<Record<string, PluginMeta[]>>("/plugins"), []);
  const presets = useLoad(() => api.get<CAPreset[]>("/ca-presets"), []);
  const [kind, setKind] = useState<"issuer" | "dns" | "notifier">("issuer");
  const [pluginName, setPluginName] = useState("");
  const [name, setName] = useState("");
  const [config, setConfig] = useState<Record<string, unknown>>({});
  const { busy, error, run } = useAction();

  const available = plugins.data?.[kind] ?? [];
  const plugin = available.find((p) => p.name === pluginName) ?? available[0];
  const preset = presets.data?.find((p) => p.id === config.preset);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const ok = await run(() => api.post(`${base}/configs`, { kind, plugin: plugin!.name, name, config }).then(() => true));
    if (ok) {
      onDone();
      onClose();
    }
  };

  return (
    <Modal title={t("Add integration")} onClose={onClose}>
      {plugins.loading ? (
        <Loading />
      ) : (
        <form onSubmit={submit}>
          <ErrorBox error={error} />
          <div className="tabs" role="tablist">
            {(["issuer", "dns", "notifier"] as const).map((k) => (
              <button
                type="button"
                key={k}
                role="tab"
                aria-selected={kind === k}
                className={kind === k ? "active" : ""}
                onClick={() => {
                  setKind(k);
                  setPluginName("");
                  setConfig({});
                }}
              >
                {k === "issuer" ? t("Certificate authority") : k === "dns" ? t("DNS provider") : t("Notifications")}
              </button>
            ))}
          </div>
          <div className="form-row">
            <div className="field">
              <label htmlFor="plugin">{t("Plugin")}</label>
              <select
                id="plugin"
                value={plugin?.name ?? ""}
                onChange={(e) => {
                  setPluginName(e.target.value);
                  setConfig({});
                }}
              >
                {available.map((p) => (
                  <option key={p.name} value={p.name}>
                    {p.name}
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor="cfgname">{t("Name")} *</label>
              <input id="cfgname" required pattern={SLUG_PATTERN} value={name} onChange={(e) => setName(e.target.value)} placeholder={kind === "issuer" ? "letsencrypt" : kind === "dns" ? "cloudflare" : "ops-email"} />
            </div>
          </div>
          {plugin && <p className="muted small">{plugin.description}</p>}

          {plugin?.name === "acme" && (
            <div className="field">
              <label htmlFor="preset">{t("Certificate authority")}</label>
              <select
                id="preset"
                value={(config.preset as string) ?? ""}
                onChange={(e) => setConfig({ ...config, preset: e.target.value || undefined })}
              >
                <option value="">{t("Custom (enter the directory URL)")}</option>
                {presets.data?.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
              {preset && (
                <span className="hint">
                  {preset.requiresEab && <b>{t("Requires External Account Binding (EAB) from the CA.")} </b>}
                  {!preset.directoryUrl && t("Enter the directory URL from your CA account.") + " "}
                  {preset.notes}{" "}
                  <a href={preset.docsUrl} target="_blank" rel="noreferrer">
                    {t("Docs")}
                  </a>
                </span>
              )}
            </div>
          )}

          {plugin?.configSchema && (
            <SchemaForm
              schema={plugin.configSchema}
              value={config}
              onChange={setConfig}
              omit={plugin.name === "acme" ? ["preset", ...(preset?.directoryUrl ? ["directoryUrl"] : [])] : []}
            />
          )}

          <div className="modal-actions">
            <button type="button" onClick={onClose}>
              {t("Cancel")}
            </button>
            <button className="primary" disabled={busy || !plugin}>
              {t("Save")}
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}
