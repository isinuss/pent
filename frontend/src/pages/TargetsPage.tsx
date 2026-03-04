import { useState, useEffect, useMemo, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Target,
  Plus,
  Search,
  Trash2,
  Play,
  Eye,
  ChevronDown,
  ChevronRight,
  X,
  Loader2,
  FolderOpen,
  Workflow,
} from 'lucide-react';
import {
  getTargets,
  createTarget,
  deleteTarget,
  type Target as TargetType,
} from '../lib/api';

function formatDate(dateStr: string | null): string {
  if (!dateStr) return '-';
  return new Date(dateStr).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

interface AddTargetFormProps {
  projects: string[];
  onSubmit: (data: { name: string; target: string; project: string; scope_notes?: string }) => Promise<void>;
  onCancel: () => void;
  isSubmitting: boolean;
}

function AddTargetForm({ projects, onSubmit, onCancel, isSubmitting }: AddTargetFormProps) {
  const [name, setName] = useState('');
  const [target, setTarget] = useState('');
  const [project, setProject] = useState(projects[0] || '');
  const [newProject, setNewProject] = useState('');
  const [useNewProject, setUseNewProject] = useState(projects.length === 0);
  const [scopeNotes, setScopeNotes] = useState('');

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    const resolvedProject = useNewProject ? newProject.trim() : project;
    if (!name.trim() || !target.trim() || !resolvedProject) return;
    onSubmit({
      name: name.trim(),
      target: target.trim(),
      project: resolvedProject,
      scope_notes: scopeNotes.trim() || undefined,
    });
  };

  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)] p-5">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-[var(--color-text-secondary)]">
          Add Target
        </h2>
        <button
          onClick={onCancel}
          className="rounded-lg p-1 text-[var(--color-text-muted)] transition-colors hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text-primary)]"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          {/* Friendly Name */}
          <div>
            <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-muted)]">
              Friendly Name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Main Website"
              className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] px-3 py-2 text-sm text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] outline-none transition-colors focus:border-[var(--color-accent)]"
              required
            />
          </div>

          {/* Target URL/Domain */}
          <div>
            <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-muted)]">
              Target URL / Domain
            </label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="e.g. example.com or 192.168.1.1"
              className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] px-3 py-2 text-sm text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] outline-none transition-colors focus:border-[var(--color-accent)]"
              required
            />
          </div>
        </div>

        {/* Project */}
        <div>
          <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-muted)]">
            Project
          </label>
          <div className="flex items-center gap-3">
            {projects.length > 0 && (
              <>
                <select
                  value={useNewProject ? '__new__' : project}
                  onChange={(e) => {
                    if (e.target.value === '__new__') {
                      setUseNewProject(true);
                    } else {
                      setUseNewProject(false);
                      setProject(e.target.value);
                    }
                  }}
                  className="flex-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] px-3 py-2 text-sm text-[var(--color-text-primary)] outline-none transition-colors focus:border-[var(--color-accent)]"
                >
                  {projects.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                  <option value="__new__">+ New Project</option>
                </select>
              </>
            )}
            {(useNewProject || projects.length === 0) && (
              <input
                type="text"
                value={newProject}
                onChange={(e) => setNewProject(e.target.value)}
                placeholder="New project name"
                className="flex-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] px-3 py-2 text-sm text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] outline-none transition-colors focus:border-[var(--color-accent)]"
                required={useNewProject || projects.length === 0}
              />
            )}
          </div>
        </div>

        {/* Scope Notes */}
        <div>
          <label className="mb-1.5 block text-xs font-medium text-[var(--color-text-muted)]">
            Scope Notes (optional)
          </label>
          <textarea
            value={scopeNotes}
            onChange={(e) => setScopeNotes(e.target.value)}
            placeholder="Any notes about the scope of testing..."
            rows={3}
            className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] px-3 py-2 text-sm text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] outline-none transition-colors focus:border-[var(--color-accent)] resize-none"
          />
        </div>

        <div className="flex justify-end gap-3">
          <button
            type="button"
            onClick={onCancel}
            className="rounded-lg border border-[var(--color-border)] px-4 py-2 text-sm font-medium text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text-primary)]"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={isSubmitting || !name.trim() || !target.trim()}
            className="inline-flex items-center gap-2 rounded-lg bg-[var(--color-accent)] px-4 py-2 text-sm font-semibold text-[var(--color-bg-primary)] transition-colors hover:bg-[var(--color-accent-hover)] disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isSubmitting ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Adding...
              </>
            ) : (
              <>
                <Plus className="h-4 w-4" />
                Add Target
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
}

export default function TargetsPage() {
  const navigate = useNavigate();
  const [targets, setTargets] = useState<TargetType[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [collapsedProjects, setCollapsedProjects] = useState<Set<string>>(new Set());
  const [deletingId, setDeletingId] = useState<string | null>(null);

  useEffect(() => {
    loadTargets();
  }, []);

  const loadTargets = async () => {
    const result = await getTargets();
    if (result.error) {
      setError(result.error);
    } else if (result.data) {
      setTargets(result.data);
    }
    setLoading(false);
  };

  const projects = useMemo(() => {
    const set = new Set(targets.map((t) => t.project));
    return Array.from(set).sort();
  }, [targets]);

  const filteredTargets = useMemo(() => {
    if (!searchQuery.trim()) return targets;
    const q = searchQuery.toLowerCase();
    return targets.filter(
      (t) =>
        t.name.toLowerCase().includes(q) ||
        t.target.toLowerCase().includes(q) ||
        t.project.toLowerCase().includes(q)
    );
  }, [targets, searchQuery]);

  const groupedTargets = useMemo(() => {
    const groups: Record<string, TargetType[]> = {};
    for (const t of filteredTargets) {
      if (!groups[t.project]) groups[t.project] = [];
      groups[t.project].push(t);
    }
    return groups;
  }, [filteredTargets]);

  const toggleProject = (project: string) => {
    setCollapsedProjects((prev) => {
      const next = new Set(prev);
      if (next.has(project)) {
        next.delete(project);
      } else {
        next.add(project);
      }
      return next;
    });
  };

  const handleAddTarget = async (data: {
    name: string;
    target: string;
    project: string;
    scope_notes?: string;
  }) => {
    setIsSubmitting(true);
    const result = await createTarget(data);
    if (result.error) {
      setError(result.error);
    } else if (result.data) {
      setTargets((prev) => [...prev, result.data!]);
      setShowForm(false);
    }
    setIsSubmitting(false);
  };

  const handleDeleteTarget = async (id: string) => {
    setDeletingId(id);
    const result = await deleteTarget(id);
    if (result.error) {
      setError(result.error);
    } else {
      setTargets((prev) => prev.filter((t) => t.id !== id));
    }
    setDeletingId(null);
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
          <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">
            Targets
          </h1>
          <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
            Manage your penetration testing targets
          </p>
        </div>
        {!showForm && (
          <button
            onClick={() => setShowForm(true)}
            className="inline-flex items-center gap-2 rounded-lg bg-[var(--color-accent)] px-4 py-2.5 text-sm font-semibold text-[var(--color-bg-primary)] transition-colors hover:bg-[var(--color-accent-hover)]"
          >
            <Plus className="h-4 w-4" />
            Add Target
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

      {/* Add Target Form */}
      {showForm && (
        <AddTargetForm
          projects={projects}
          onSubmit={handleAddTarget}
          onCancel={() => setShowForm(false)}
          isSubmitting={isSubmitting}
        />
      )}

      {/* Search/Filter Bar */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--color-text-muted)]" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search targets..."
            className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] py-2 pl-10 pr-4 text-sm text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] outline-none transition-colors focus:border-[var(--color-accent)]"
          />
        </div>
        <span className="text-sm text-[var(--color-text-muted)]">
          {filteredTargets.length} target{filteredTargets.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Targets grouped by project */}
      {Object.keys(groupedTargets).length === 0 ? (
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)] px-6 py-16 text-center">
          <Target className="mx-auto mb-3 h-10 w-10 text-[var(--color-text-muted)] opacity-40" />
          <p className="text-sm text-[var(--color-text-muted)]">
            {targets.length === 0
              ? 'No targets yet. Add your first target to get started.'
              : 'No targets match your search.'}
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {Object.entries(groupedTargets)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([project, projectTargets]) => {
              const isCollapsed = collapsedProjects.has(project);

              return (
                <div
                  key={project}
                  className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)] overflow-hidden"
                >
                  {/* Project Header */}
                  <button
                    onClick={() => toggleProject(project)}
                    className="flex w-full items-center gap-3 px-5 py-3 text-left transition-colors hover:bg-[var(--color-bg-hover)]"
                  >
                    {isCollapsed ? (
                      <ChevronRight className="h-4 w-4 text-[var(--color-text-muted)]" />
                    ) : (
                      <ChevronDown className="h-4 w-4 text-[var(--color-text-muted)]" />
                    )}
                    <FolderOpen className="h-4 w-4 text-[var(--color-accent)]" />
                    <span className="text-sm font-semibold text-[var(--color-text-primary)]">
                      {project}
                    </span>
                    <span className="ml-auto text-xs text-[var(--color-text-muted)]">
                      {projectTargets.length} target{projectTargets.length !== 1 ? 's' : ''}
                    </span>
                  </button>

                  {/* Targets Table */}
                  {!isCollapsed && (
                    <div className="border-t border-[var(--color-border)]">
                      <table className="w-full">
                        <thead>
                          <tr className="border-b border-[var(--color-border)] bg-[var(--color-bg-secondary)]">
                            <th className="px-5 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-[var(--color-text-muted)]">
                              Name
                            </th>
                            <th className="px-5 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-[var(--color-text-muted)]">
                              Domain / IP
                            </th>
                            <th className="hidden px-5 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-[var(--color-text-muted)] md:table-cell">
                              Last Scan
                            </th>
                            <th className="hidden px-5 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-[var(--color-text-muted)] sm:table-cell">
                              Findings
                            </th>
                            <th className="px-5 py-2.5 text-right text-xs font-semibold uppercase tracking-wide text-[var(--color-text-muted)]">
                              Actions
                            </th>
                          </tr>
                        </thead>
                        <tbody>
                          {projectTargets.map((t) => (
                            <tr
                              key={t.id}
                              className="border-b border-[var(--color-border)] last:border-b-0 transition-colors hover:bg-[var(--color-bg-hover)]"
                            >
                              <td className="px-5 py-3">
                                <span className="text-sm font-medium text-[var(--color-text-primary)]">
                                  {t.name}
                                </span>
                              </td>
                              <td className="px-5 py-3">
                                <span className="font-mono text-sm text-[var(--color-text-secondary)]">
                                  {t.target}
                                </span>
                              </td>
                              <td className="hidden px-5 py-3 md:table-cell">
                                <span className="text-sm text-[var(--color-text-muted)]">
                                  {formatDate(t.last_scan_at)}
                                </span>
                              </td>
                              <td className="hidden px-5 py-3 sm:table-cell">
                                <span className="text-sm text-[var(--color-text-secondary)]">
                                  {t.finding_count}
                                </span>
                              </td>
                              <td className="px-5 py-3">
                                <div className="flex items-center justify-end gap-1">
                                  <button
                                    onClick={() => navigate(`/results?target=${encodeURIComponent(t.target)}`)}
                                    className="rounded-lg p-1.5 text-[var(--color-text-muted)] transition-colors hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text-primary)]"
                                    title="View Scans"
                                  >
                                    <Eye className="h-4 w-4" />
                                  </button>
                                  <button
                                    onClick={() => navigate(`/pipeline?target=${encodeURIComponent(t.target)}`)}
                                    className="rounded-lg p-1.5 text-[var(--color-accent)] transition-colors hover:bg-[var(--color-accent)]/10"
                                    title="Run Pipeline"
                                  >
                                    <Workflow className="h-4 w-4" />
                                  </button>
                                  <button
                                    onClick={() => navigate(`/scan?target=${encodeURIComponent(t.target)}`)}
                                    className="rounded-lg p-1.5 text-[var(--color-text-muted)] transition-colors hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text-primary)]"
                                    title="Start Scan"
                                  >
                                    <Play className="h-4 w-4" />
                                  </button>
                                  <button
                                    onClick={() => handleDeleteTarget(t.id)}
                                    disabled={deletingId === t.id}
                                    className="rounded-lg p-1.5 text-[var(--color-text-muted)] transition-colors hover:bg-[var(--color-severity-critical)]/10 hover:text-[var(--color-severity-critical)] disabled:opacity-50"
                                    title="Delete"
                                  >
                                    {deletingId === t.id ? (
                                      <Loader2 className="h-4 w-4 animate-spin" />
                                    ) : (
                                      <Trash2 className="h-4 w-4" />
                                    )}
                                  </button>
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              );
            })}
        </div>
      )}
    </div>
  );
}
