import {
  createContext,
  useContext,
  useState,
  useEffect,
  type ReactNode,
} from "react";
import { getMe, type SessionUser } from "./api/auth";

type AuthState = {
  user: SessionUser | null;
  loading: boolean;
  refetch: () => Promise<void>;
  patchUser: (patch: Partial<SessionUser>) => void;
};

const AuthContext = createContext<AuthState>({
  user: null,
  loading: true,
  refetch: () => Promise.resolve(),
  patchUser: () => {},
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [loading, setLoading] = useState(true);

  const load = (): Promise<void> => {
    setLoading(true);
    return getMe()
      .then(setUser)
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  };

  const patchUser = (patch: Partial<SessionUser>) => {
    setUser((prev) => prev ? { ...prev, ...patch } : prev);
  };

  useEffect(() => {
    load();
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, refetch: load, patchUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
