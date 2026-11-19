import { useState, type FormEvent } from "react";
import { api, type User } from "../api";
import { Badge, ErrorBox, Loading, Modal, PageHead, useAction, useFormat, useLoad } from "../components/ui";
import { useI18n } from "../i18n";
import { useSession } from "../session";

// randomPassword suggests a strong password an administrator can hand over.
function randomPassword() {
  const b = new Uint8Array(15);
  crypto.getRandomValues(b);
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_");
}

// Users is the instance administrators' account list.
export function Users() {
  const { t } = useI18n();
  const { date } = useFormat();
  const { me } = useSession();
  const users = useLoad(() => api.get<User[]>("/users"), []);
  const [modal, setModal] = useState<{ kind: "new" } | { kind: "reset"; user: User } | null>(null);
  const act = useAction();

  if (!me.user?.isSuperuser) {
    return <div className="alert bad">{t("You don't have permission to do this.")}</div>;
  }

  const update = (u: User, body: object) => act.run(() => api.patch(`/users/${u.id}`, body)).then(users.reload);

  return (
    <>
      <PageHead title={t("Users")} sub={t("Accounts on this Certower instance. Roles are granted per organization and project under Members.")}>
        <button className="primary" onClick={() => setModal({ kind: "new" })}>
          {t("New user")}
        </button>
      </PageHead>
      <ErrorBox error={users.error || act.error} />
      <div className="card flush">
        {users.loading && !users.data ? (
          <Loading />
        ) : (
          <table>
            <thead>
              <tr>
                <th>{t("Email")}</th>
                <th>{t("Name")}</th>
                <th>{t("Sign-in")}</th>
                <th>{t("Status")}</th>
                <th>{t("Created")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {users.data?.map((u) => (
                <tr key={u.id}>
                  <td>
                    {u.email} {u.isSuperuser && <Badge kind="info">{t("Instance admin")}</Badge>}
                  </td>
                  <td>{u.displayName || "—"}</td>
                  <td>{u.hasPassword ? t("Password") : t("Single sign-on")}</td>
                  <td>{u.disabled ? <Badge kind="bad">{t("Disabled")}</Badge> : <Badge kind="ok">{t("Active")}</Badge>}</td>
                  <td className="nowrap">{date(u.createdAt)}</td>
                  <td className="nowrap">
                    {u.id !== me.user?.id && (
                      <div className="actions">
                        <button className="small" onClick={() => setModal({ kind: "reset", user: u })}>
                          {t("Reset password")}
                        </button>
                        <button className="small" disabled={act.busy} onClick={() => update(u, { isSuperuser: !u.isSuperuser })}>
                          {u.isSuperuser ? t("Remove admin") : t("Make admin")}
                        </button>
                        <button className={"small" + (u.disabled ? "" : " danger")} disabled={act.busy} onClick={() => update(u, { disabled: !u.disabled })}>
                          {u.disabled ? t("Enable") : t("Disable")}
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {modal?.kind === "new" && <NewUserModal onClose={() => setModal(null)} onDone={users.reload} />}
      {modal?.kind === "reset" && <ResetPasswordModal user={modal.user} onClose={() => setModal(null)} />}
    </>
  );
}

function NewUserModal({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const { t } = useI18n();
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState(randomPassword);
  const [admin, setAdmin] = useState(false);
  const { busy, error, run } = useAction();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const ok = await run(() => api.post("/users", { email, displayName: name, password, isSuperuser: admin }).then(() => true));
    if (ok) {
      onDone();
      onClose();
    }
  };
  return (
    <Modal title={t("New user")} onClose={onClose}>
      <form onSubmit={submit}>
        <ErrorBox error={error} />
        <div className="field">
          <label htmlFor="nu-email">{t("Email")}</label>
          <input id="nu-email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} autoFocus />
        </div>
        <div className="field">
          <label htmlFor="nu-name">{t("Name")}</label>
          <input id="nu-name" value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <PasswordField id="nu-password" value={password} onChange={setPassword} />
        <label className="check">
          <input type="checkbox" checked={admin} onChange={(e) => setAdmin(e.target.checked)} /> {t("Instance administrator (can manage users and create organizations)")}
        </label>
        <p className="hint">{t("Give the password to the user securely; they can change it after signing in. With single sign-on, accounts can also be created on first sign-in.")}</p>
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

function ResetPasswordModal({ user, onClose }: { user: User; onClose: () => void }) {
  const { t } = useI18n();
  const [password, setPassword] = useState(randomPassword);
  const [done, setDone] = useState(false);
  const { busy, error, run } = useAction();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const ok = await run(() => api.patch(`/users/${user.id}`, { password }).then(() => true));
    if (ok) setDone(true);
  };
  return (
    <Modal title={t("Reset password for {email}", { email: user.email })} onClose={onClose}>
      <form onSubmit={submit}>
        <ErrorBox error={error} />
        {done ? (
          <div className="alert ok">{t("Password reset. The user has been signed out everywhere.")}</div>
        ) : (
          <PasswordField id="rp-password" value={password} onChange={setPassword} />
        )}
        <div className="modal-actions">
          <button type="button" onClick={onClose}>
            {done ? t("Done") : t("Cancel")}
          </button>
          {!done && (
            <button className="primary" disabled={busy}>
              {t("Reset password")}
            </button>
          )}
        </div>
      </form>
    </Modal>
  );
}

function PasswordField({ id, value, onChange }: { id: string; value: string; onChange: (v: string) => void }) {
  const { t } = useI18n();
  return (
    <div className="field">
      <label htmlFor={id}>{t("Password")}</label>
      <div className="row">
        <input id={id} className="mono" required minLength={12} value={value} onChange={(e) => onChange(e.target.value)} autoComplete="new-password" />
        <button type="button" onClick={() => onChange(randomPassword())}>
          {t("Generate")}
        </button>
      </div>
      <span className="hint">{t("At least 12 characters.")}</span>
    </div>
  );
}

// ChangePasswordModal lets the signed-in user change their own password.
export function ChangePasswordModal({ onClose }: { onClose: () => void }) {
  const { t } = useI18n();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [done, setDone] = useState(false);
  const { busy, error, setError, run } = useAction();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (next !== confirm) {
      setError(new Error(t("The new passwords do not match.")));
      return;
    }
    const ok = await run(() => api.post("/me/password", { currentPassword: current, newPassword: next }).then(() => true));
    if (ok) setDone(true);
  };
  return (
    <Modal title={t("Change password")} onClose={onClose}>
      <form onSubmit={submit}>
        <ErrorBox error={error} />
        {done ? (
          <div className="alert ok">{t("Password changed. Your other sessions have been signed out.")}</div>
        ) : (
          <>
            <div className="field">
              <label htmlFor="cp-current">{t("Current password")}</label>
              <input id="cp-current" type="password" required autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} autoFocus />
            </div>
            <div className="field">
              <label htmlFor="cp-new">{t("New password")}</label>
              <input id="cp-new" type="password" required minLength={12} autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />
              <span className="hint">{t("At least 12 characters.")}</span>
            </div>
            <div className="field">
              <label htmlFor="cp-confirm">{t("Confirm new password")}</label>
              <input id="cp-confirm" type="password" required minLength={12} autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
            </div>
          </>
        )}
        <div className="modal-actions">
          <button type="button" onClick={onClose}>
            {done ? t("Done") : t("Cancel")}
          </button>
          {!done && (
            <button className="primary" disabled={busy}>
              {t("Change password")}
            </button>
          )}
        </div>
      </form>
    </Modal>
  );
}
