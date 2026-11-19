import { NavLink, Outlet, useNavigate, useParams } from "react-router-dom";
import { api, type Project } from "../api";
import { useI18n } from "../i18n";
import { useSession } from "../session";
import { useLoad } from "./ui";

export function Layout() {
  const { org, project } = useParams();
  const { me, orgs, logout } = useSession();
  const { t, lang, setLang } = useI18n();
  const navigate = useNavigate();
  const projects = useLoad(() => (org ? api.get<Project[]>(`/orgs/${org}/projects`) : Promise.resolve([] as Project[])), [org]);

  const p = (path: string) => `/o/${org}/p/${project}${path}`;
  const o = (path: string) => `/o/${org}${path}`;

  return (
    <div className="app">
      <aside className="sidebar">
        <NavLink to="/" className="brand">
          <img src="/favicon.svg" alt="" />
          Certower
        </NavLink>

        {orgs.length > 0 && (
          <div className="nav-section">
            <label className="nav-label" htmlFor="org-select">
              {t("Organization")}
            </label>
            <select id="org-select" value={org ?? ""} onChange={(e) => navigate(`/o/${e.target.value}`)}>
              {!org && <option value="">—</option>}
              {orgs.map((x) => (
                <option key={x.id} value={x.slug}>
                  {x.name}
                </option>
              ))}
            </select>
          </div>
        )}

        {org && (
          <nav className="nav nav-section">
            <NavLink to={o("")} end>
              {t("Overview")}
            </NavLink>
            <NavLink to={o("/configs")}>{t("Issuers & DNS")}</NavLink>
            <NavLink to={o("/members")}>{t("Members")}</NavLink>
            <NavLink to={o("/audit")}>{t("Audit log")}</NavLink>
          </nav>
        )}

        {org && (projects.data?.length ?? 0) > 0 && (
          <div className="nav-section">
            <label className="nav-label" htmlFor="project-select">
              {t("Project")}
            </label>
            <select id="project-select" value={project ?? ""} onChange={(e) => navigate(`/o/${org}/p/${e.target.value}`)}>
              {!project && <option value="">{t("Choose a project")}</option>}
              {projects.data!.map((x) => (
                <option key={x.id} value={x.slug}>
                  {x.name}
                </option>
              ))}
            </select>
          </div>
        )}

        {org && project && (
          <nav className="nav nav-section">
            <NavLink to={p("")} end>
              {t("Certificates")}
            </NavLink>
            <NavLink to={p("/agents")}>{t("Agents & targets")}</NavLink>
            <NavLink to={p("/configs")}>{t("Project integrations")}</NavLink>
            <NavLink to={p("/policy")}>{t("Policy")}</NavLink>
            <NavLink to={p("/members")}>{t("Project members")}</NavLink>
            <NavLink to={p("/jobs")}>{t("Jobs")}</NavLink>
          </nav>
        )}

        <div className="sidebar-footer">
          <div title={me.user?.email}>{me.user?.email}</div>
          <div className="actions">
            <button className="small" onClick={() => setLang(lang === "en" ? "zh-TW" : "en")}>
              {lang === "en" ? "中文" : "English"}
            </button>
            <button className="small" onClick={() => logout().then(() => navigate("/"))}>
              {t("Sign out")}
            </button>
          </div>
        </div>
      </aside>
      <main className="main">
        <Outlet />
      </main>
    </div>
  );
}
