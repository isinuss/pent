import { useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard,
  Crosshair,
  List,
  BookOpen,
  LogOut,
  Menu,
  X,
  Shield,
  Target,
} from 'lucide-react';
import { useAuth } from '../hooks/useAuth';
import ThemeToggle from './ThemeToggle';

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/targets', icon: Target, label: 'Targets' },
  { to: '/scan', icon: Crosshair, label: 'New Scan' },
  { to: '/results', icon: List, label: 'Results' },
  { to: '/guides', icon: BookOpen, label: 'Guides' },
];

export default function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <div className="flex h-screen overflow-hidden bg-[var(--color-bg-primary)]">
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/50 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`
          fixed inset-y-0 left-0 z-40 flex w-60 flex-col
          bg-[var(--color-bg-secondary)] border-r border-[var(--color-border)]
          transition-transform duration-200 ease-in-out
          lg:static lg:translate-x-0
          ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}
        `}
      >
        {/* Logo */}
        <div className="flex items-center gap-3 px-5 py-5 border-b border-[var(--color-border)]">
          <Shield className="h-8 w-8 text-[var(--color-accent)]" />
          <div>
            <h1 className="text-xl font-bold tracking-wider text-[var(--color-text-primary)]">
              PENT
            </h1>
            <p className="text-xs text-[var(--color-text-muted)] tracking-wide">
              Pentest Toolkit
            </p>
          </div>
          <button
            className="ml-auto lg:hidden text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
            onClick={() => setSidebarOpen(false)}
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-1">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              onClick={() => setSidebarOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors duration-150 ${
                  isActive
                    ? 'bg-[var(--color-accent-dim)] text-[var(--color-accent)] border-l-2 border-[var(--color-accent)]'
                    : 'text-[var(--color-text-secondary)] hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text-primary)]'
                }`
              }
            >
              <item.icon className="h-5 w-5 shrink-0" />
              {item.label}
            </NavLink>
          ))}
        </nav>

        {/* User section */}
        <div className="px-3 py-4 border-t border-[var(--color-border)]">
          <div className="flex items-center gap-3 px-3 py-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-[var(--color-bg-hover)] text-sm font-bold text-[var(--color-accent)]">
              {user?.username?.charAt(0).toUpperCase() || '?'}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-[var(--color-text-primary)] truncate">
                {user?.username || 'User'}
              </p>
              <p className="text-xs text-[var(--color-text-muted)]">
                {user?.role || 'operator'}
              </p>
            </div>
            <ThemeToggle />
            <button
              onClick={handleLogout}
              className="p-1.5 rounded-lg text-[var(--color-text-muted)] hover:text-[var(--color-severity-critical)] hover:bg-[var(--color-bg-hover)] transition-colors"
              title="Logout"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Mobile header */}
        <header className="flex items-center gap-3 px-4 py-3 border-b border-[var(--color-border)] lg:hidden bg-[var(--color-bg-secondary)]">
          <button
            onClick={() => setSidebarOpen(true)}
            className="p-1.5 rounded-lg text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-bg-hover)]"
          >
            <Menu className="h-5 w-5" />
          </button>
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-[var(--color-accent)]" />
            <span className="text-sm font-bold tracking-wider text-[var(--color-text-primary)]">
              PENT
            </span>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
