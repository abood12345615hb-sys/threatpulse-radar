import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { authService, type RegisterPayload } from "@/services/authService";
import type { User } from "@/types";
import { supabase } from "@/lib/supabase";

interface AuthValue {
  user: User | null;
  ready: boolean;
  pending: boolean;
  login: (email: string, password: string) => Promise<User>;
  register: (payload: RegisterPayload) => Promise<User>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [ready, setReady] = useState(false);
  const [pending, setPending] = useState(false);

  useEffect(() => {
    const initAuth = async () => {
      const u = await authService.current();
      setUser(u);
      setReady(true);
    };
    initAuth();

    // Listen for auth state changes
    const { data: { subscription } } = supabase.auth.onAuthStateChange(async (event, session) => {
      if (event === 'SIGNED_OUT') {
        setUser(null);
      } else if (event === 'SIGNED_IN' || event === 'TOKEN_REFRESHED') {
        const u = await authService.current();
        setUser(u);
      }
    });

    return () => {
      subscription.unsubscribe();
    };
  }, []);

  const wrap = async <T,>(fn: () => Promise<T>) => {
    setPending(true);
    try {
      return await fn();
    } finally {
      setPending(false);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        ready,
        pending,
        login: (email, password) =>
          wrap(async () => {
            const u = await authService.login(email, password);
            setUser(u);
            return u;
          }),
        register: (payload) =>
          wrap(async () => {
            const u = await authService.register(payload);
            setUser(u);
            return u;
          }),
        logout: async () => {
          await authService.logout();
          setUser(null);
        },
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
