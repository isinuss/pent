import { useEffect, useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Clock, Filter, ArrowRight } from 'lucide-react';
import { getScans, type ScanSummary } from '../lib/api';

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    running: 'bg-[var(--color-accent)]/15 text-[var(--color-accent)]',
    completed: 'bg-[var(--color-severity-low)]/15 text-[var(--color-severity-low)]',
    error: 'bg-[var(--color-severity-critical)]/15 text-[var(--color-severity-critical)]',
    pending: 'bg-[var(--color-severity-info)]/15 text-[var(--color-severity-info)]',
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold ${colors[status] || colors.pending}`}
    >
      {status === 'running' && (
        <span className="h-1.5 w-1.5 rounded-full bg-[var(--color-accent)] animate-pulse" />
      )}
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}

function formatDate(dateStr: string): string {
  return new Date(dateStr).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function formatDuration(start: string | null, end: string | null): string {
  if (!start) return '-';
  const startTime = new Date(start).getTime();
  const endTime = end ? new Date(end).getTime() : Date.now();
  const seconds = Math.floor((endTime - startTime) / 1000);

  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

const statusFilters = ['all', 'running', 'completed', 'error', 'pending'] as const;
type StatusFilter = typeof statusFilters[number];

export default function ResultsPage() {
  const navigate = useNavigate();
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [typeFilter, setTypeFilter] = useState<string>('all');

  useEffect(() => {
    let cancelled = false;

    async function load() {
      const result = await getScans();
      if (cancelled) return;

      if (result.error) {
        setError(result.error);
      } else if (result.data) {
        setScans(result.data);
      }
      setLoading(false);
    }

    load();
    return () => { cancelled = true; };
  }, []);

  const scanTypes = useMemo(() => {
    const types = new Set(scans.map((s) => s.scan_type));
    return ['all', ...Array.from(types).sort()];
  }, [scans]);

  const filteredScans = useMemo(() => {
    return scans.filter((scan) => {
      if (statusFilter !== 'all' && scan.status !== statusFilter) return false;
      if (typeFilter !== 'all' && scan.scan_type !== typeFilter) return false;
      if (
        searchQuery &&
        !scan.target.toLowerCase().includes(searchQuery.toLowerCase())
      )
        return false;
      return true;
    });
  }, [scans, statusFilter, typeFilter, searchQuery]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-[var(--color-border)] border-t-[var(--color-accent)]" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-lg border border-[var(--color-severity-critical)]/30 bg-[var(--color-severity-critical)]/10 px-6 py-4 text-sm text-[var(--color-severity-critical)]">
        Failed to load scans: {error}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">Scan Results</h1>
        <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
          Browse and filter scan history
        </p>
      </div>

      {/* Filters */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center">
        {/* Search */}
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--color-text-muted)]" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by target..."
            className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)] py-2 pl-10 pr-4 text-sm text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] outline-none transition-colors focus:border-[var(--color-accent)]"
          />
        </div>

        {/* Status Filter */}
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-[var(--color-text-muted)]" />
          <div className="flex gap-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)] p-1">
            {statusFilters.map((status) => (
              <button
                key={status}
                onClick={() => setStatusFilter(status)}
                className={`rounded-md px-3 py-1 text-xs font-medium transition-colors ${
                  statusFilter === status
                    ? 'bg-[var(--color-accent)]/15 text-[var(--color-accent)]'
                    : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)]'
                }`}
              >
                {status.charAt(0).toUpperCase() + status.slice(1)}
              </button>
            ))}
          </div>
        </div>

        {/* Type Filter */}
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)] px-3 py-2 text-sm text-[var(--color-text-primary)] outline-none transition-colors focus:border-[var(--color-accent)]"
        >
          {scanTypes.map((type) => (
            <option key={type} value={type}>
              {type === 'all' ? 'All Types' : type}
            </option>
          ))}
        </select>
      </div>

      {/* Results Table */}
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)] overflow-hidden">
        {filteredScans.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[var(--color-border)]">
                  <th className="px-5 py-3 text-left text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wide">
                    Target
                  </th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wide">
                    Type
                  </th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wide">
                    Status
                  </th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wide">
                    Findings
                  </th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wide">
                    Started
                  </th>
                  <th className="px-5 py-3 text-left text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wide">
                    Duration
                  </th>
                  <th className="px-5 py-3 text-right text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wide">
                    Action
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border)]">
                {filteredScans.map((scan) => (
                  <tr
                    key={scan.id}
                    className="cursor-pointer transition-colors hover:bg-[var(--color-bg-hover)]"
                    onClick={() => navigate(`/results/${scan.id}`)}
                  >
                    <td className="px-5 py-3 text-sm font-medium text-[var(--color-text-primary)]">
                      {scan.target}
                    </td>
                    <td className="px-5 py-3 text-sm text-[var(--color-text-secondary)]">
                      {scan.scan_type}
                    </td>
                    <td className="px-5 py-3">
                      <StatusBadge status={scan.status} />
                    </td>
                    <td className="px-5 py-3 text-sm text-[var(--color-text-secondary)]">
                      {scan.finding_count}
                    </td>
                    <td className="px-5 py-3 text-sm text-[var(--color-text-muted)]">
                      <div className="flex items-center gap-1.5">
                        <Clock className="h-3.5 w-3.5" />
                        {formatDate(scan.created_at)}
                      </div>
                    </td>
                    <td className="px-5 py-3 text-sm text-[var(--color-text-muted)]">
                      {formatDuration(scan.started_at, scan.completed_at)}
                    </td>
                    <td className="px-5 py-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          navigate(`/results/${scan.id}`);
                        }}
                        className="inline-flex items-center gap-1 rounded-md px-2.5 py-1 text-xs font-medium text-[var(--color-accent)] hover:bg-[var(--color-accent)]/10 transition-colors"
                      >
                        View
                        <ArrowRight className="h-3 w-3" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="px-5 py-16 text-center">
            <p className="text-sm text-[var(--color-text-muted)]">
              {scans.length === 0
                ? 'No scans found. Start your first scan to see results here.'
                : 'No scans match your filters.'}
            </p>
          </div>
        )}
      </div>

      {/* Count */}
      <p className="text-xs text-[var(--color-text-muted)]">
        Showing {filteredScans.length} of {scans.length} scan{scans.length !== 1 ? 's' : ''}
      </p>
    </div>
  );
}
