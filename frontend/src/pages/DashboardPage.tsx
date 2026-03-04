import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Crosshair,
  AlertTriangle,
  ShieldAlert,
  Activity,
  ArrowRight,
  Clock,
  Plus,
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  Legend,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
} from 'recharts';
import { getStats, type Stats, type ScanSummary } from '../lib/api';

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

interface StatCardProps {
  icon: React.ElementType;
  label: string;
  value: number;
  color: string;
}

function StatCard({ icon: Icon, label, value, color }: StatCardProps) {
  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)] p-5 transition-colors hover:bg-[var(--color-bg-hover)]">
      <div className="flex items-center gap-4">
        <div
          className="flex h-12 w-12 items-center justify-center rounded-lg"
          style={{ backgroundColor: `${color}15` }}
        >
          <Icon className="h-6 w-6" style={{ color }} />
        </div>
        <div>
          <p className="text-sm text-[var(--color-text-secondary)]">{label}</p>
          <p className="text-2xl font-bold text-[var(--color-text-primary)]">{value}</p>
        </div>
      </div>
    </div>
  );
}

function formatDate(dateStr: string): string {
  const d = new Date(dateStr);
  return d.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

const SEVERITY_COLORS: Record<string, string> = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#22c55e',
  Info: '#64748b',
};

export default function DashboardPage() {
  const navigate = useNavigate();
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      const result = await getStats();
      if (cancelled) return;

      if (result.error) {
        setError(result.error);
      } else if (result.data) {
        setStats(result.data);
      }
      setLoading(false);
    }

    load();
    return () => { cancelled = true; };
  }, []);

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
        Failed to load dashboard: {error}
      </div>
    );
  }

  if (!stats) return null;

  const severityData = [
    { name: 'Critical', value: stats.critical_findings },
    { name: 'High', value: stats.high_findings },
    { name: 'Medium', value: stats.medium_findings },
    { name: 'Low', value: stats.low_findings },
    { name: 'Info', value: stats.info_findings },
  ].filter((d) => d.value > 0);

  const barData = [
    { name: 'Critical', count: stats.critical_findings, fill: '#ef4444' },
    { name: 'High', count: stats.high_findings, fill: '#f97316' },
    { name: 'Medium', count: stats.medium_findings, fill: '#eab308' },
    { name: 'Low', count: stats.low_findings, fill: '#22c55e' },
    { name: 'Info', count: stats.info_findings, fill: '#64748b' },
  ];

  const totalFindings =
    stats.critical_findings +
    stats.high_findings +
    stats.medium_findings +
    stats.low_findings +
    stats.info_findings;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">Dashboard</h1>
          <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
            Security assessment overview
          </p>
        </div>
        <button
          onClick={() => navigate('/scan')}
          className="inline-flex items-center gap-2 rounded-lg bg-[var(--color-accent)] px-4 py-2.5 text-sm font-semibold text-[var(--color-bg-primary)] transition-colors hover:bg-[var(--color-accent-hover)]"
        >
          <Plus className="h-4 w-4" />
          New Scan
        </button>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          icon={Crosshair}
          label="Total Scans"
          value={stats.total_scans}
          color="#3b82f6"
        />
        <StatCard
          icon={ShieldAlert}
          label="Critical Findings"
          value={stats.critical_findings}
          color="#ef4444"
        />
        <StatCard
          icon={AlertTriangle}
          label="High Findings"
          value={stats.high_findings}
          color="#f97316"
        />
        <StatCard
          icon={Activity}
          label="Active Scans"
          value={stats.active_scans}
          color="#00d4aa"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Pie Chart */}
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)] p-5">
          <h2 className="mb-4 text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide">
            Severity Distribution
          </h2>
          {totalFindings > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={90}
                    paddingAngle={3}
                    dataKey="value"
                    stroke="none"
                  >
                    {severityData.map((entry) => (
                      <Cell
                        key={entry.name}
                        fill={SEVERITY_COLORS[entry.name]}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#1a2233',
                      border: '1px solid #2a3a52',
                      borderRadius: '8px',
                      color: '#e2e8f0',
                      fontSize: '13px',
                    }}
                  />
                  <Legend
                    formatter={(value: string) => (
                      <span style={{ color: '#94a3b8', fontSize: '12px' }}>{value}</span>
                    )}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="flex h-64 items-center justify-center text-sm text-[var(--color-text-muted)]">
              No findings yet
            </div>
          )}
        </div>

        {/* Bar Chart */}
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)] p-5">
          <h2 className="mb-4 text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide">
            Findings by Severity
          </h2>
          {totalFindings > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={barData} barSize={36}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#2a3a52" />
                  <XAxis
                    dataKey="name"
                    tick={{ fill: '#94a3b8', fontSize: 12 }}
                    axisLine={{ stroke: '#2a3a52' }}
                    tickLine={false}
                  />
                  <YAxis
                    tick={{ fill: '#94a3b8', fontSize: 12 }}
                    axisLine={{ stroke: '#2a3a52' }}
                    tickLine={false}
                    allowDecimals={false}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#1a2233',
                      border: '1px solid #2a3a52',
                      borderRadius: '8px',
                      color: '#e2e8f0',
                      fontSize: '13px',
                    }}
                    cursor={{ fill: '#1e2a3f' }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {barData.map((entry) => (
                      <Cell key={entry.name} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="flex h-64 items-center justify-center text-sm text-[var(--color-text-muted)]">
              No findings yet
            </div>
          )}
        </div>
      </div>

      {/* Recent Scans */}
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)]">
        <div className="flex items-center justify-between border-b border-[var(--color-border)] px-5 py-4">
          <h2 className="text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide">
            Recent Scans
          </h2>
          <button
            onClick={() => navigate('/results')}
            className="inline-flex items-center gap-1 text-xs text-[var(--color-accent)] hover:text-[var(--color-accent-hover)] transition-colors"
          >
            View All
            <ArrowRight className="h-3 w-3" />
          </button>
        </div>

        {stats.recent_scans.length > 0 ? (
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
                    Date
                  </th>
                  <th className="px-5 py-3 text-right text-xs font-medium text-[var(--color-text-muted)] uppercase tracking-wide">
                    Action
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--color-border)]">
                {stats.recent_scans.map((scan: ScanSummary) => (
                  <tr
                    key={scan.id}
                    className="transition-colors hover:bg-[var(--color-bg-hover)] cursor-pointer"
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
          <div className="px-5 py-12 text-center text-sm text-[var(--color-text-muted)]">
            No scans yet. Start your first scan to see results here.
          </div>
        )}
      </div>
    </div>
  );
}
