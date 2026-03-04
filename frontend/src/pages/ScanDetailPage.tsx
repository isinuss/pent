import { useEffect, useState, useMemo } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  Search,
  Download,
  Clock,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';
import SeverityBadge from '../components/SeverityBadge';
import {
  getScan,
  getScanFindings,
  exportScanReport,
  type Scan,
  type Finding,
} from '../lib/api';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

const severityOrder: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const severityColors: Record<Severity, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  info: '#64748b',
};

function formatDate(dateStr: string | null): string {
  if (!dateStr) return '-';
  return new Date(dateStr).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    running: 'bg-[var(--color-accent)]/15 text-[var(--color-accent)]',
    completed: 'bg-[var(--color-severity-low)]/15 text-[var(--color-severity-low)]',
    error: 'bg-[var(--color-severity-critical)]/15 text-[var(--color-severity-critical)]',
    pending: 'bg-[var(--color-severity-info)]/15 text-[var(--color-severity-info)]',
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-semibold ${colors[status] || colors.pending}`}
    >
      {status === 'running' && (
        <span className="h-1.5 w-1.5 rounded-full bg-[var(--color-accent)] animate-pulse" />
      )}
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}

function FindingRow({ finding }: { finding: Finding }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="border-b border-[var(--color-border)] last:border-b-0">
      <button
        onClick={() => setExpanded((prev) => !prev)}
        className="flex w-full items-center gap-4 px-5 py-3 text-left transition-colors hover:bg-[var(--color-bg-hover)]"
      >
        {expanded ? (
          <ChevronDown className="h-4 w-4 shrink-0 text-[var(--color-text-muted)]" />
        ) : (
          <ChevronRight className="h-4 w-4 shrink-0 text-[var(--color-text-muted)]" />
        )}
        <SeverityBadge severity={finding.severity} />
        <span className="flex-1 truncate text-sm font-medium text-[var(--color-text-primary)]">
          {finding.title}
        </span>
        <span className="shrink-0 text-xs text-[var(--color-text-muted)]">
          {finding.category}
        </span>
      </button>

      {expanded && (
        <div className="border-t border-[var(--color-border)] bg-[var(--color-bg-secondary)] px-5 py-4 space-y-3">
          {finding.description && (
            <div>
              <h4 className="mb-1 text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wide">
                Description
              </h4>
              <p className="text-sm text-[var(--color-text-secondary)] leading-relaxed whitespace-pre-wrap">
                {finding.description}
              </p>
            </div>
          )}
          {finding.evidence && (
            <div>
              <h4 className="mb-1 text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wide">
                Evidence
              </h4>
              <pre className="overflow-x-auto rounded-lg bg-[var(--color-terminal-bg)] p-3 text-xs text-[var(--color-text-secondary)] font-mono leading-relaxed">
                {finding.evidence}
              </pre>
            </div>
          )}
          {finding.recommendation && (
            <div>
              <h4 className="mb-1 text-xs font-semibold text-[var(--color-text-muted)] uppercase tracking-wide">
                Recommendation
              </h4>
              <p className="text-sm text-[var(--color-text-secondary)] leading-relaxed whitespace-pre-wrap">
                {finding.recommendation}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all');
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;

    async function load() {
      const [scanResult, findingsResult] = await Promise.all([
        getScan(id!),
        getScanFindings(id!),
      ]);

      if (cancelled) return;

      if (scanResult.error) {
        setError(scanResult.error);
      } else if (scanResult.data) {
        setScan(scanResult.data);
      }

      if (findingsResult.data) {
        setFindings(findingsResult.data);
      }

      setLoading(false);
    }

    load();
    return () => { cancelled = true; };
  }, [id]);

  const severityCounts = useMemo(() => {
    const counts: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    for (const f of findings) {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
    }
    return counts;
  }, [findings]);

  const filteredFindings = useMemo(() => {
    return findings
      .filter((f) => {
        if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
        if (
          searchQuery &&
          !f.title.toLowerCase().includes(searchQuery.toLowerCase()) &&
          !f.description.toLowerCase().includes(searchQuery.toLowerCase()) &&
          !f.category.toLowerCase().includes(searchQuery.toLowerCase())
        )
          return false;
        return true;
      })
      .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  }, [findings, severityFilter, searchQuery]);

  const handleExport = async (format: 'md' | 'html' | 'json') => {
    if (!id) return;
    setExporting(true);

    const blob = await exportScanReport(id, format);
    if (blob) {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `scan-${id.slice(0, 8)}.${format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }

    setExporting(false);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-[var(--color-border)] border-t-[var(--color-accent)]" />
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="space-y-4">
        <button
          onClick={() => navigate('/results')}
          className="inline-flex items-center gap-2 text-sm text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Results
        </button>
        <div className="rounded-lg border border-[var(--color-severity-critical)]/30 bg-[var(--color-severity-critical)]/10 px-6 py-4 text-sm text-[var(--color-severity-critical)]">
          {error || 'Scan not found'}
        </div>
      </div>
    );
  }

  const totalFindings = findings.length;
  const severityBarSegments = (['critical', 'high', 'medium', 'low', 'info'] as Severity[])
    .filter((s) => severityCounts[s] > 0)
    .map((s) => ({
      severity: s,
      count: severityCounts[s],
      percent: totalFindings > 0 ? (severityCounts[s] / totalFindings) * 100 : 0,
    }));

  return (
    <div className="space-y-6">
      {/* Back button */}
      <button
        onClick={() => navigate('/results')}
        className="inline-flex items-center gap-2 text-sm text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to Results
      </button>

      {/* Header */}
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)] p-5">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <h1 className="text-xl font-bold text-[var(--color-text-primary)]">
              {scan.target}
            </h1>
            <div className="mt-2 flex flex-wrap items-center gap-3 text-sm text-[var(--color-text-secondary)]">
              <span>Type: {scan.scan_type}</span>
              <span className="text-[var(--color-border)]">&bull;</span>
              <StatusBadge status={scan.status} />
              <span className="text-[var(--color-border)]">&bull;</span>
              <span className="inline-flex items-center gap-1 text-[var(--color-text-muted)]">
                <Clock className="h-3.5 w-3.5" />
                Started: {formatDate(scan.started_at)}
              </span>
              {scan.completed_at && (
                <>
                  <span className="text-[var(--color-border)]">&bull;</span>
                  <span className="text-[var(--color-text-muted)]">
                    Completed: {formatDate(scan.completed_at)}
                  </span>
                </>
              )}
            </div>
          </div>

          {/* Export Buttons */}
          <div className="flex items-center gap-2">
            {(['md', 'html', 'json'] as const).map((format) => (
              <button
                key={format}
                onClick={() => handleExport(format)}
                disabled={exporting}
                className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text-primary)] disabled:opacity-50"
              >
                <Download className="h-3.5 w-3.5" />
                {format.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        {/* Severity Summary Bar */}
        {totalFindings > 0 && (
          <div className="mt-5">
            <div className="mb-2 flex items-center justify-between text-xs text-[var(--color-text-muted)]">
              <span>{totalFindings} finding{totalFindings !== 1 ? 's' : ''}</span>
              <div className="flex gap-3">
                {severityBarSegments.map((seg) => (
                  <span key={seg.severity} className="flex items-center gap-1">
                    <span
                      className="h-2 w-2 rounded-full"
                      style={{ backgroundColor: severityColors[seg.severity] }}
                    />
                    {seg.count} {seg.severity}
                  </span>
                ))}
              </div>
            </div>
            <div className="flex h-2 overflow-hidden rounded-full bg-[var(--color-bg-secondary)]">
              {severityBarSegments.map((seg) => (
                <div
                  key={seg.severity}
                  className="transition-all duration-300"
                  style={{
                    width: `${seg.percent}%`,
                    backgroundColor: severityColors[seg.severity],
                  }}
                />
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Findings Section */}
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)]">
        <div className="flex flex-col gap-3 border-b border-[var(--color-border)] px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
          <h2 className="text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide">
            Findings
          </h2>
          <div className="flex items-center gap-3">
            {/* Search */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--color-text-muted)]" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search findings..."
                className="w-48 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] py-1.5 pl-9 pr-3 text-xs text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] outline-none transition-colors focus:border-[var(--color-accent)]"
              />
            </div>

            {/* Severity Filter */}
            <div className="flex gap-1 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-0.5">
              <button
                onClick={() => setSeverityFilter('all')}
                className={`rounded-md px-2 py-1 text-xs font-medium transition-colors ${
                  severityFilter === 'all'
                    ? 'bg-[var(--color-bg-hover)] text-[var(--color-text-primary)]'
                    : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)]'
                }`}
              >
                All
              </button>
              {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`rounded-md px-2 py-1 text-xs font-medium transition-colors ${
                    severityFilter === sev
                      ? 'text-[var(--color-text-primary)]'
                      : 'text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)]'
                  }`}
                  style={
                    severityFilter === sev
                      ? { backgroundColor: `${severityColors[sev]}20`, color: severityColors[sev] }
                      : undefined
                  }
                >
                  {sev.charAt(0).toUpperCase() + sev.slice(1)}
                  {severityCounts[sev] > 0 && (
                    <span className="ml-1 opacity-60">({severityCounts[sev]})</span>
                  )}
                </button>
              ))}
            </div>
          </div>
        </div>

        {filteredFindings.length > 0 ? (
          <div>
            {filteredFindings.map((finding) => (
              <FindingRow key={finding.id} finding={finding} />
            ))}
          </div>
        ) : (
          <div className="px-5 py-12 text-center text-sm text-[var(--color-text-muted)]">
            {findings.length === 0
              ? 'No findings for this scan.'
              : 'No findings match your filters.'}
          </div>
        )}
      </div>
    </div>
  );
}
