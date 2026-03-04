import { useState, type FormEvent } from 'react';
import {
  Crosshair,
  Globe,
  Shield,
  Code,
  AlertTriangle,
  CheckCircle,
  Zap,
  Search,
  Play,
  Loader2,
} from 'lucide-react';
import { startScan, type Scan } from '../lib/api';
import Terminal from '../components/Terminal';

interface ScanTypeOption {
  id: string;
  label: string;
  description: string;
  icon: React.ElementType;
}

const scanTypes: ScanTypeOption[] = [
  {
    id: 'recon',
    label: 'Recon',
    description: 'Subdomain enumeration, DNS, WHOIS, and technology detection',
    icon: Search,
  },
  {
    id: 'vuln',
    label: 'Vuln Scan',
    description: 'Vulnerability scanning with CVE identification',
    icon: Shield,
  },
  {
    id: 'web',
    label: 'Web Test',
    description: 'Web application security testing and fuzzing',
    icon: Globe,
  },
  {
    id: 'js',
    label: 'JS Analyze',
    description: 'JavaScript source analysis for secrets and endpoints',
    icon: Code,
  },
  {
    id: 'takeover',
    label: 'Takeover',
    description: 'Subdomain takeover vulnerability checks',
    icon: AlertTriangle,
  },
  {
    id: 'checks',
    label: 'Checks',
    description: 'Security header and configuration checks',
    icon: CheckCircle,
  },
  {
    id: 'full',
    label: 'Full Auto',
    description: 'Run all scan types automatically in sequence',
    icon: Zap,
  },
];

interface ScanTypeOptionsMap {
  [key: string]: { key: string; label: string; type: 'boolean' | 'string'; default: boolean | string }[];
}

const typeOptions: ScanTypeOptionsMap = {
  recon: [
    { key: 'passive', label: 'Passive only (no active probing)', type: 'boolean', default: false },
    { key: 'deep', label: 'Deep enumeration', type: 'boolean', default: false },
  ],
  vuln: [
    { key: 'quick', label: 'Quick scan (top ports only)', type: 'boolean', default: false },
    { key: 'aggressive', label: 'Aggressive mode', type: 'boolean', default: false },
  ],
  web: [
    { key: 'crawl', label: 'Enable crawling', type: 'boolean', default: true },
    { key: 'fuzz', label: 'Enable fuzzing', type: 'boolean', default: false },
  ],
  js: [
    { key: 'recursive', label: 'Recursive analysis', type: 'boolean', default: false },
  ],
  takeover: [
    { key: 'all_cnames', label: 'Check all CNAME records', type: 'boolean', default: false },
  ],
  checks: [
    { key: 'headers', label: 'Security headers', type: 'boolean', default: true },
    { key: 'ssl', label: 'SSL/TLS analysis', type: 'boolean', default: true },
  ],
  full: [
    { key: 'skip_js', label: 'Skip JS analysis', type: 'boolean', default: false },
    { key: 'quick', label: 'Quick mode', type: 'boolean', default: false },
  ],
};

export default function ScanPage() {
  const [target, setTarget] = useState('');
  const [selectedType, setSelectedType] = useState<string>('recon');
  const [options, setOptions] = useState<Record<string, unknown>>({});
  const [isStarting, setIsStarting] = useState(false);
  const [activeScan, setActiveScan] = useState<Scan | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleOptionChange = (key: string, value: unknown) => {
    setOptions((prev) => ({ ...prev, [key]: value }));
  };

  const handleTypeSelect = (typeId: string) => {
    setSelectedType(typeId);
    setOptions({});
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!target.trim()) {
      setError('Target is required.');
      return;
    }

    setIsStarting(true);

    const result = await startScan(target.trim(), selectedType, options);

    if (result.error) {
      setError(result.error);
      setIsStarting(false);
    } else if (result.data) {
      setActiveScan(result.data);
      setIsStarting(false);
    }
  };

  const currentTypeOptions = typeOptions[selectedType] || [];

  if (activeScan) {
    return (
      <div className="space-y-6">
        {/* Scan Info Header */}
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">
              Scan: {activeScan.target}
            </h1>
            <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
              Type: {activeScan.scan_type} &middot; ID: {activeScan.id.slice(0, 8)}
            </p>
          </div>
          <div className="flex items-center gap-3">
            <span
              className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-semibold ${
                activeScan.status === 'running'
                  ? 'bg-[var(--color-accent)]/15 text-[var(--color-accent)]'
                  : activeScan.status === 'completed'
                    ? 'bg-[var(--color-severity-low)]/15 text-[var(--color-severity-low)]'
                    : activeScan.status === 'error'
                      ? 'bg-[var(--color-severity-critical)]/15 text-[var(--color-severity-critical)]'
                      : 'bg-[var(--color-severity-info)]/15 text-[var(--color-severity-info)]'
              }`}
            >
              {activeScan.status === 'running' && (
                <span className="h-1.5 w-1.5 rounded-full bg-[var(--color-accent)] animate-pulse" />
              )}
              {activeScan.status.charAt(0).toUpperCase() + activeScan.status.slice(1)}
            </span>
            <button
              onClick={() => {
                setActiveScan(null);
                setTarget('');
                setOptions({});
              }}
              className="rounded-lg border border-[var(--color-border)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text-primary)]"
            >
              New Scan
            </button>
          </div>
        </div>

        {/* Terminal */}
        <Terminal scanId={activeScan.id} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">New Scan</h1>
        <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
          Configure and launch a penetration test
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Target Input */}
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)] p-5">
          <label className="mb-2 block text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide">
            Target
          </label>
          <div className="relative">
            <Crosshair className="absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-[var(--color-text-muted)]" />
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] py-3.5 pl-12 pr-4 text-base text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] outline-none transition-colors focus:border-[var(--color-accent)] focus:ring-1 focus:ring-[var(--color-accent)]"
              placeholder="example.com, 192.168.1.0/24, or https://target.com"
              autoFocus
            />
          </div>
        </div>

        {/* Scan Type Selector */}
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)] p-5">
          <label className="mb-3 block text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide">
            Scan Type
          </label>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
            {scanTypes.map((type) => {
              const isSelected = selectedType === type.id;
              return (
                <button
                  key={type.id}
                  type="button"
                  onClick={() => handleTypeSelect(type.id)}
                  className={`flex flex-col items-start gap-2 rounded-lg border p-4 text-left transition-all duration-150 ${
                    isSelected
                      ? 'border-[var(--color-accent)] bg-[var(--color-accent)]/5 ring-1 ring-[var(--color-accent)]'
                      : 'border-[var(--color-border)] bg-[var(--color-bg-secondary)] hover:border-[var(--color-border-light)] hover:bg-[var(--color-bg-hover)]'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <type.icon
                      className={`h-5 w-5 ${isSelected ? 'text-[var(--color-accent)]' : 'text-[var(--color-text-muted)]'}`}
                    />
                    <span
                      className={`text-sm font-semibold ${isSelected ? 'text-[var(--color-accent)]' : 'text-[var(--color-text-primary)]'}`}
                    >
                      {type.label}
                    </span>
                  </div>
                  <p className="text-xs text-[var(--color-text-muted)] leading-relaxed">
                    {type.description}
                  </p>
                </button>
              );
            })}
          </div>
        </div>

        {/* Type-specific Options */}
        {currentTypeOptions.length > 0 && (
          <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)] p-5">
            <label className="mb-3 block text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide">
              Options
            </label>
            <div className="space-y-3">
              {currentTypeOptions.map((opt) => (
                <label
                  key={opt.key}
                  className="flex items-center gap-3 cursor-pointer"
                >
                  {opt.type === 'boolean' ? (
                    <input
                      type="checkbox"
                      checked={
                        (options[opt.key] as boolean | undefined) ??
                        (opt.default as boolean)
                      }
                      onChange={(e) => handleOptionChange(opt.key, e.target.checked)}
                      className="h-4 w-4 rounded border-[var(--color-border)] bg-[var(--color-bg-secondary)] text-[var(--color-accent)] focus:ring-[var(--color-accent)] focus:ring-offset-0"
                    />
                  ) : (
                    <input
                      type="text"
                      value={(options[opt.key] as string) ?? (opt.default as string)}
                      onChange={(e) => handleOptionChange(opt.key, e.target.value)}
                      className="w-60 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] px-3 py-1.5 text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"
                    />
                  )}
                  <span className="text-sm text-[var(--color-text-secondary)]">
                    {opt.label}
                  </span>
                </label>
              ))}
            </div>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="rounded-lg border border-[var(--color-severity-critical)]/30 bg-[var(--color-severity-critical)]/10 px-4 py-3 text-sm text-[var(--color-severity-critical)]">
            {error}
          </div>
        )}

        {/* Submit */}
        <button
          type="submit"
          disabled={isStarting || !target.trim()}
          className="inline-flex items-center gap-2 rounded-lg bg-[var(--color-accent)] px-6 py-3 text-sm font-semibold text-[var(--color-bg-primary)] transition-colors hover:bg-[var(--color-accent-hover)] disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isStarting ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              Starting Scan...
            </>
          ) : (
            <>
              <Play className="h-4 w-4" />
              Start Scan
            </>
          )}
        </button>
      </form>
    </div>
  );
}
