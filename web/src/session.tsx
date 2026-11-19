import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api, ApiError, type Me, type Organization } from "./api";

interface Session {
  me: Me;
  orgs: Organization[];
  reloadOrgs: () => Promise<void>;
  logout: () => Promise<void>;
}

const Ctx = createContext<Session | null>(null);

type State = { kind: "loading" } | { kind: "anonymous" } | { kind: "ready"; me: Me; orgs: Organization[] };

// SessionGate loads the signed-in user, or renders the login page.
export function SessionGate({ login, children }: { login: (onDone: () => void) => ReactNode; children: ReactNode }) {
  const [state, setState] = useState<State>({ kind: "loading" });

  const load = async () => {
    try {
      const [me, orgs] = await Promise.all([api.get<Me>("/me"), api.get<Organization[]>("/orgs")]);
      setState({ kind: "ready", me, orgs });
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) setState({ kind: "anonymous" });
      else throw e;
    }
  };
  useEffect(() => {
    load();
  }, []);

  if (state.kind === "loading") return null;
  if (state.kind === "anonymous") return <>{login(load)}</>;

  const session: Session = {
    me: state.me,
    orgs: state.orgs,
    reloadOrgs: async () => {
      const orgs = await api.get<Organization[]>("/orgs");
      setState({ ...state, orgs });
    },
    logout: async () => {
      await api.post("/auth/logout");
      setState({ kind: "anonymous" });
    },
  };
  return <Ctx.Provider value={session}>{children}</Ctx.Provider>;
}

export function useSession(): Session {
  const s = useContext(Ctx);
  if (!s) throw new Error("useSession outside SessionGate");
  return s;
}
