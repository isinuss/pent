import { useState, useEffect, type FormEvent } from 'react';
import {
  KeyRound,
  Plus,
  Trash2,
  X,
  Loader2,
  Shield,
  Cookie,
  FileKey,
  LogIn,
} from 'lucide-react';
import {
  getAuthProfiles,
  createAuthProfile,
  deleteAuthProfile,
  getTargets,
  type AuthProfile,
  type Target,
} from '../lib/api';

const PROFILE_TYPES = [
  { value: 'bearer', label: 'Bearer Token', icon: Shield, description: 'Authorization: Bearer <token>' },
  { value: 'cookie', label: 'Cookie', icon: Cookie, description: 'Session cookies' },
  { value: 'header', label: 'Custom Header', icon: FileKey, description: 'Custom HTTP headers' },
  { value: 'form', label: 'Form Login', icon: LogIn, description: 'Login form + capture session' },
] as const;

function ProfileTypeIcon({ type }: { type: string }) {
  const pt = PROFILE_TYPES.find((t) => t.value === type);
  if (!pt) return <KeyRound className="h-5 w-5" />;
  const Icon = pt.icon;
  return <Icon className="h-5 w-5" />;
}

interface ConfigFieldsProps {
  type: string;
  config: Record<string, string>;
  onChange: (config: Record<string, string>) => void;
}

function ConfigFields({ type, config, onChange }: ConfigFieldsProps) {
  const inputClass =
    'w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] px-3 py-2 text-sm text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] outline-none transition-colors focus:border-[var(--color-accent)] font-mono';
  const labelClass = 'mb-1.5 block text-xs font-medium text-[var(--color-text-muted)]';

  if (type === 'bearer') {
    return (
      <div>
        <label className={labelClass}>Token</label>
        <input
          type="text"
          value={config.token || ''}
          onChange={(e) => onChange({ ...config, token: e.target.value })}
          placeholder="eyJhbGciOiJIUzI1NiIs..."
          className={inputClass}
        />
      </div>
    );
  }

  if (type === 'cookie') {
    return (
      <div className="space-y-3">
        <div>
          <label className={labelClass}>Cookie Name</label>
          <input
            type="text"
            value={config.name || ''}
            onChange={(e) => onChange({ ...config, name: e.target.value })}
            placeholder="session_id"
            className={inputClass}
          />
        </div>
        <div>
          <label className={labelClass}>Cookie Value</label>
          <input
            type="text"
            value={config.value || ''}
            onChange={(e) => onChange({ ...config, value: e.target.value })}
            placeholder="abc123..."
            className={inputClass}
          />
        </div>
      </div>
    );
  }

  if (type === 'header') {
    return (
      <div className="space-y-3">
        <div>
          <label className={labelClass}>Header Name</label>
          <input
            type="text"
            value={config.header_name || ''}
            onChange={(e) => onChange({ ...config, header_name: e.target.value })}
            placeholder="X-API-Key"
            className={inputClass}
          />
        </div>
        <div>
          <label className={labelClass}>Header Value</label>
          <input
            type="text"
            value={config.header_value || ''}
            onChange={(e) => onChange({ ...config, header_value: e.target.value })}
            placeholder="your-api-key-here"
            className={inputClass}
          />
        </div>
      </div>
    );
  }

  if (type === 'form') {
    return (
      <div className="space-y-3">
        <div>
          <label className={labelClass}>Login URL</label>
          <input
            type="text"
            value={config.login_url || ''}
            onChange={(e) => onChange({ ...config, login_url: e.target.value })}
            placeholder="https://example.com/login"
            className={inputClass}
          />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className={labelClass}>Username Field</label>
            <input
              type="text"
              value={config.username_field || ''}
              onChange={(e) => onChange({ ...config, username_field: e.target.value })}
              placeholder="username"
              className={inputClass}
            />
          </div>
          <div>
            <label className={labelClass}>Password Field</label>
            <input
              type="text"
              value={config.password_field || ''}
              onChange={(e) => onChange({ ...config, password_field: e.target.value })}
              placeholder="password"
              className={inputClass}
            />
          </div>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className={labelClass}>Username</label>
            <input
              type="text"
              value={config.username || ''}
              onChange={(e) => onChange({ ...config, username: e.target.value })}
              placeholder="admin"
              className={inputClass}
            />
          </div>
          <div>
            <label className={labelClass}>Password</label>
            <input
              type="password"
              value={config.password || ''}
              onChange={(e) => onChange({ ...config, password: e.target.value })}
              placeholder="••••••••"
              className={inputClass}
            />
          </div>
        </div>
      </div>
    );
  }

  return null;
}

export default function AuthProfilesPage() {
  const [profiles, setProfiles] = useState<AuthProfile[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [deletingId, setDeletingId] = useState<number | null>(null);

  // Form state
  const [formName, setFormName] = useState('');
  const [formType, setFormType] = useState<string>('bearer');
  const [formConfig, setFormConfig] = useState<Record<string, string>>({});
  const [formTargetId, setFormTargetId] = useState<string>('');

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    const [profilesRes, targetsRes] = await Promise.all([
      getAuthProfiles(),
      getTargets(),
    ]);
    if (profilesRes.error) setError(profilesRes.error);
    else if (profilesRes.data) setProfiles(profilesRes.data);
    if (targetsRes.data) setTargets(targetsRes.data);
    setLoading(false);
  };

  const handleCreate = async (e: FormEvent) => {
    e.preventDefault();
    if (!formName.trim()) return;
    setIsSubmitting(true);

    const result = await createAuthProfile({
      name: formName.trim(),
      profile_type: formType,
      config: formConfig,
      target_id: formTargetId || undefined,
    });

    if (result.error) {
      setError(result.error);
    } else if (result.data) {
      setProfiles((prev) => [result.data!, ...prev]);
      setShowForm(false);
      resetForm();
    }
    setIsSubmitting(false);
  };

  const handleDelete = async (id: number) => {
    setDeletingId(id);
    const result = await deleteAuthProfile(id);
    if (result.error) {
      setError(result.error);
    } else {
      setProfiles((prev) => prev.filter((p) => p.id !== id));
    }
    setDeletingId(null);
  };

  const resetForm = () => {
    setFormName('');
    setFormType('bearer');
    setFormConfig({});
    setFormTargetId('');
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-[var(--color-border)] border-t-[var(--color-accent)]" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">Auth Profiles</h1>
          <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
            Manage authentication configurations for scanning protected targets
          </p>
        </div>
        {!showForm && (
          <button
            onClick={() => setShowForm(true)}
            className="inline-flex items-center gap-2 rounded-lg bg-[var(--color-accent)] px-4 py-2.5 text-sm font-semibold text-[var(--color-bg-primary)] transition-colors hover:bg-[var(--color-accent-hover)]"
          >
            <Plus className="h-4 w-4" />
            New Profile
          </button>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="flex items-center justify-between rounded-lg border border-[var(--color-severity-critical)]/30 bg-[var(--color-severity-critical)]/10 px-4 py-3 text-sm text-[var(--color-severity-critical)]">
          {error}
          <button onClick={() => setError(null)} className="ml-4 hover:opacity-80">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Create Form */}
      {showForm && (
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)] p-5">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-[var(--color-text-secondary)]">
              New Auth Profile
            </h2>
            <button
              onClick={() => { setShowForm(false); resetForm(); }}
              className="rounded-lg p-1 text-[var(--color-text-muted)] transition-colors hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text-primary)]"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          <form onSubmit={handleCreate} className="space-y-4">
            {/* Name */}
            <div>
              <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-muted)]">
                Profile Name
              </label>
              <input
                type="text"
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
                placeholder="e.g. Staging API Token"
                className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] px-3 py-2 text-sm text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] outline-none transition-colors focus:border-[var(--color-accent)]"
                required
              />
            </div>

            {/* Type Selector */}
            <div>
              <label className="mb-2 block text-xs font-medium text-[var(--color-text-muted)]">
                Authentication Type
              </label>
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                {PROFILE_TYPES.map((pt) => {
                  const Icon = pt.icon;
                  const selected = formType === pt.value;
                  return (
                    <button
                      key={pt.value}
                      type="button"
                      onClick={() => { setFormType(pt.value); setFormConfig({}); }}
                      className={`flex flex-col items-center gap-1.5 rounded-lg border p-3 text-xs transition-colors ${
                        selected
                          ? 'border-[var(--color-accent)] bg-[var(--color-accent)]/10 text-[var(--color-accent)]'
                          : 'border-[var(--color-border)] bg-[var(--color-bg-secondary)] text-[var(--color-text-secondary)] hover:bg-[var(--color-bg-hover)]'
                      }`}
                    >
                      <Icon className="h-5 w-5" />
                      <span className="font-medium">{pt.label}</span>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Config Fields */}
            <ConfigFields type={formType} config={formConfig} onChange={setFormConfig} />

            {/* Target Link */}
            <div>
              <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-muted)]">
                Link to Target (optional)
              </label>
              <select
                value={formTargetId}
                onChange={(e) => setFormTargetId(e.target.value)}
                className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] px-3 py-2 text-sm text-[var(--color-text-primary)] outline-none transition-colors focus:border-[var(--color-accent)]"
              >
                <option value="">No target (global)</option>
                {targets.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name} ({t.target})
                  </option>
                ))}
              </select>
            </div>

            {/* Actions */}
            <div className="flex justify-end gap-3">
              <button
                type="button"
                onClick={() => { setShowForm(false); resetForm(); }}
                className="rounded-lg border border-[var(--color-border)] px-4 py-2 text-sm font-medium text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-bg-hover)]"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isSubmitting || !formName.trim()}
                className="inline-flex items-center gap-2 rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-[var(--color-bg-primary)] transition-colors hover:bg-[var(--color-accent-hover)] disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isSubmitting ? (
                  <><Loader2 className="h-4 w-4 animate-spin" /> Creating...</>
                ) : (
                  <><Plus className="h-4 w-4" /> Create Profile</>
                )}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Profile List */}
      {profiles.length === 0 ? (
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)] px-6 py-16 text-center">
          <KeyRound className="mx-auto mb-3 h-10 w-10 text-[var(--color-text-muted)] opacity-40" />
          <p className="text-sm text-[var(--color-text-muted)]">
            No auth profiles yet. Create one to scan authenticated targets.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {profiles.map((p) => {
            const pt = PROFILE_TYPES.find((t) => t.value === p.profile_type);
            const linkedTarget = targets.find((t) => t.id === p.target_id);

            return (
              <div
                key={p.id}
                className="flex items-center gap-4 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)] p-4 transition-colors hover:bg-[var(--color-bg-hover)]"
              >
                <div
                  className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg"
                  style={{ backgroundColor: 'var(--color-accent)', opacity: 0.15 }}
                >
                  <ProfileTypeIcon type={p.profile_type} />
                </div>

                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold text-[var(--color-text-primary)]">
                      {p.name}
                    </span>
                    <span className="rounded-full bg-[var(--color-bg-secondary)] px-2 py-0.5 text-xs font-medium text-[var(--color-text-muted)]">
                      {pt?.label || p.profile_type}
                    </span>
                  </div>
                  <div className="mt-0.5 flex items-center gap-3 text-xs text-[var(--color-text-muted)]">
                    {linkedTarget && (
                      <span>
                        Target: <span className="font-mono">{linkedTarget.target}</span>
                      </span>
                    )}
                    <span>{new Date(p.created_at).toLocaleDateString()}</span>
                  </div>
                </div>

                <button
                  onClick={() => handleDelete(p.id)}
                  disabled={deletingId === p.id}
                  className="rounded-lg p-2 text-[var(--color-text-muted)] transition-colors hover:bg-[var(--color-severity-critical)]/10 hover:text-[var(--color-severity-critical)] disabled:opacity-50"
                  title="Delete profile"
                >
                  {deletingId === p.id ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Trash2 className="h-4 w-4" />
                  )}
                </button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
