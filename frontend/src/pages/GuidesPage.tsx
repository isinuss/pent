import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Globe,
  Search,
  Code,
  Bug,
  Smartphone,
  Network,
  FileText,
  Compass,
  BookOpen,
} from 'lucide-react';
import { getGuides, type GuideTopic } from '../lib/api';

const topicIcons: Record<string, React.ElementType> = {
  recon: Search,
  webapp: Globe,
  api: Code,
  bugbounty: Bug,
  mobile: Smartphone,
  network: Network,
  reporting: FileText,
  dorking: Compass,
};

function getTopicIcon(topic: string): React.ElementType {
  return topicIcons[topic] || BookOpen;
}

const topicColors: Record<string, string> = {
  recon: '#3b82f6',
  webapp: '#f97316',
  api: '#a855f7',
  bugbounty: '#ef4444',
  mobile: '#06b6d4',
  network: '#22c55e',
  reporting: '#eab308',
  dorking: '#00d4aa',
};

function getTopicColor(topic: string): string {
  return topicColors[topic] || '#64748b';
}

export default function GuidesPage() {
  const navigate = useNavigate();
  const [guides, setGuides] = useState<GuideTopic[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      const result = await getGuides();
      if (cancelled) return;

      if (result.error) {
        setError(result.error);
      } else if (result.data) {
        setGuides(result.data);
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
        Failed to load guides: {error}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">Guides</h1>
        <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
          Penetration testing methodology guides and references
        </p>
      </div>

      {/* Guide Grid */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        {guides.map((guide) => {
          const Icon = getTopicIcon(guide.topic);
          const color = getTopicColor(guide.topic);

          return (
            <button
              key={guide.topic}
              onClick={() => navigate(`/guides/${guide.topic}`)}
              className="group flex flex-col items-start rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)] p-5 text-left transition-all duration-200 hover:border-[var(--color-border-light)] hover:bg-[var(--color-bg-hover)] hover:shadow-lg hover:shadow-black/20"
            >
              <div
                className="mb-4 flex h-11 w-11 items-center justify-center rounded-lg transition-transform duration-200 group-hover:scale-110"
                style={{ backgroundColor: `${color}15` }}
              >
                <Icon className="h-5 w-5" style={{ color }} />
              </div>
              <h3 className="mb-1.5 text-sm font-semibold text-[var(--color-text-primary)] group-hover:text-[var(--color-accent)] transition-colors">
                {guide.title}
              </h3>
              <p className="text-xs text-[var(--color-text-muted)] leading-relaxed line-clamp-2">
                {guide.description}
              </p>
            </button>
          );
        })}
      </div>

      {guides.length === 0 && (
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)] px-5 py-16 text-center">
          <BookOpen className="mx-auto mb-3 h-10 w-10 text-[var(--color-text-muted)]" />
          <p className="text-sm text-[var(--color-text-muted)]">
            No guides available yet.
          </p>
        </div>
      )}
    </div>
  );
}
