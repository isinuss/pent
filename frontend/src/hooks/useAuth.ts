import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  type ReactNode,
} from 'react';
import { createElement } from 'react';
import {
  login as apiLogin,
  register as apiRegister,
  setToken,
  getToken,
  type User,
} from '../lib/api';
import { disconnectSocket } from '../lib/socket';

interface AuthContextValue {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<string | null>;
  register: (username: string, password: string) => Promise<string | null>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

function loadStoredUser(): User | null {
  try {
    const raw = localStorage.getItem('pent_user');
    if (raw) return JSON.parse(raw) as User;
  } catch {
    // ignore
  }
  return null;
}

function storeUser(user: User | null): void {
  if (user) {
    localStorage.setItem('pent_user', JSON.stringify(user));
  } else {
    localStorage.removeItem('pent_user');
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(loadStoredUser);
  const [isLoading, setIsLoading] = useState(false);

  const isAuthenticated = !!user && !!getToken();

  useEffect(() => {
    if (!getToken()) {
      setUser(null);
      storeUser(null);
    }
  }, []);

  const login = useCallback(async (username: string, password: string): Promise<string | null> => {
    setIsLoading(true);
    try {
      const result = await apiLogin(username, password);
      if (result.error) {
        return result.error;
      }
      if (result.data) {
        setUser(result.data.user);
        storeUser(result.data.user);
      }
      return null;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const register = useCallback(async (username: string, password: string): Promise<string | null> => {
    setIsLoading(true);
    try {
      const result = await apiRegister(username, password);
      if (result.error) {
        return result.error;
      }
      if (result.data) {
        setUser(result.data.user);
        storeUser(result.data.user);
      }
      return null;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const logout = useCallback(() => {
    setUser(null);
    storeUser(null);
    setToken(null);
    disconnectSocket();
  }, []);

  return createElement(
    AuthContext.Provider,
    {
      value: { user, isAuthenticated, isLoading, login, register, logout },
    },
    children
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
}
