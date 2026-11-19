import { useState, type FormEvent } from "react";
import { Link, Navigate, useNavigate, useParams } from "react-router-dom";
import { api, type Organization, type Project } from "../api";
import { Empty, ErrorBox, Loading, Modal, PageHead, useAction, useFormat, useLoad } from "../components/ui";
import { useI18n } from "../i18n";
import { useSession } from "../session";
import { SLUG_PATTERN } from "../patterns";

// Home sends the user to their first organization, or offers to create one.
export function Home() {
  const { orgs, me } = useSession();
  const { t } = useI18n();
  const [creating, setCreating] = useState(false);
  if (orgs.length > 0) return <Navigate to={`/o/${orgs[0].slug}`} replace />;
  return (
    <>
      <PageHead title={t("Welcome to Certower")} />
      <div className="card">
        <Empty title={t("You are not a member of any organization yet.")}>
          {me.user?.isSuperuser ? (
            <p>
              <button className="primary" onClick={() => setCreating(true)}>
                {t("Create organization")}
              </button>
            </p>
          ) : (
            <p>{t("Ask an administrator to add you to an organization.")}</p>
          )}
        </Empty>
      </div>
      {creating && <CreateSlugModal kind="org" onClose={() => setCreating(false)} />}
    </>
  );
}

export function OrgOverview() {
  const { org } = useParams();
  const { t } = useI18n();
  const { date } = useFormat();
  const { me } = useSession();
  const navigate = useNavigate();
  const [modal, setModal] = useState<"project" | "org" | null>(null);
  const orgInfo = useLoad(() => api.get<Organization>(`/orgs/${org}`), [org]);
  const projects = useLoad(() => api.get<Project[]>(`/orgs/${org}/projects`), [org]);

  return (
    <>
      <PageHead title={orgInfo.data?.name ?? org!} sub={t("Projects group certificates, agents and policies.")}>
        {me.user?.isSuperuser && <button onClick={() => setModal("org")}>{t("New organization")}</button>}
        <button className="primary" onClick={() => setModal("project")}>
          {t("New project")}
        </button>
      </PageHead>
      <ErrorBox error={orgInfo.error || projects.error} />
      <div className="card flush">
        {projects.loading ? (
          <Loading />
        ) : projects.data?.length ? (
          <table>
            <thead>
              <tr>
                <th>{t("Project")}</th>
                <th>{t("Slug")}</th>
                <th>{t("Created")}</th>
              </tr>
            </thead>
            <tbody>
              {projects.data.map((p) => (
                <tr key={p.id} className="link" onClick={() => navigate(`/o/${org}/p/${p.slug}`)}>
                  <td>
                    <Link to={`/o/${org}/p/${p.slug}`}>{p.name}</Link>
                  </td>
                  <td className="mono muted">{p.slug}</td>
                  <td className="muted">{date(p.createdAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <Empty title={t("No projects yet")}>{t("Create a project to start managing certificates.")}</Empty>
        )}
      </div>
      {modal && <CreateSlugModal kind={modal} org={org} onClose={() => setModal(null)} onDone={projects.reload} />}
    </>
  );
}

function CreateSlugModal({ kind, org, onClose, onDone }: { kind: "org" | "project"; org?: string; onClose: () => void; onDone?: () => void }) {
  const { t } = useI18n();
  const { reloadOrgs } = useSession();
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [slugTouched, setSlugTouched] = useState(false);
  const { busy, error, run } = useAction();
  const autoSlug = (s: string) =>
    s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 63);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const path = kind === "org" ? "/orgs" : `/orgs/${org}/projects`;
    const res = await run(() => api.post(path, { slug, name }));
    if (res === undefined) return;
    if (kind === "org") {
      await reloadOrgs();
      navigate(`/o/${slug}`);
    } else {
      onDone?.();
      navigate(`/o/${org}/p/${slug}`);
    }
    onClose();
  };

  return (
    <Modal title={kind === "org" ? t("New organization") : t("New project")} onClose={onClose}>
      <form onSubmit={submit}>
        <ErrorBox error={error} />
        <div className="field">
          <label htmlFor="name">{t("Name")}</label>
          <input
            id="name"
            required
            autoFocus
            value={name}
            onChange={(e) => {
              setName(e.target.value);
              if (!slugTouched) setSlug(autoSlug(e.target.value));
            }}
          />
        </div>
        <div className="field">
          <label htmlFor="slug">{t("Slug")}</label>
          <input
            id="slug"
            required
            pattern={SLUG_PATTERN}
            value={slug}
            onChange={(e) => {
              setSlugTouched(true);
              setSlug(e.target.value);
            }}
          />
          <span className="hint">{t("Lowercase letters, digits and dashes. Used in URLs and the API.")}</span>
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
    </Modal>
  );
}
