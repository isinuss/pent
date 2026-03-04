type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
}

const severityConfig: Record<Severity, { bg: string; text: string; label: string }> = {
  critical: {
    bg: 'bg-[var(--color-severity-critical)]/15',
    text: 'text-[var(--color-severity-critical)]',
    label: 'Critical',
  },
  high: {
    bg: 'bg-[var(--color-severity-high)]/15',
    text: 'text-[var(--color-severity-high)]',
    label: 'High',
  },
  medium: {
    bg: 'bg-[var(--color-severity-medium)]/15',
    text: 'text-[var(--color-severity-medium)]',
    label: 'Medium',
  },
  low: {
    bg: 'bg-[var(--color-severity-low)]/15',
    text: 'text-[var(--color-severity-low)]',
    label: 'Low',
  },
  info: {
    bg: 'bg-[var(--color-severity-info)]/15',
    text: 'text-[var(--color-severity-info)]',
    label: 'Info',
  },
};

export default function SeverityBadge({ severity, className = '' }: SeverityBadgeProps) {
  const config = severityConfig[severity] || severityConfig.info;

  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold ${config.bg} ${config.text} ${className}`}
    >
      {config.label}
    </span>
  );
}
