import { useState, useEffect, useRef } from 'react';
import { Radio } from 'lucide-react';
import SeverityBadge from './SeverityBadge';
import FindingDrawer from './FindingDrawer';
import { onScanFinding } from '../lib/socket';
import type { Finding } from '../lib/api';

interface LiveFinding extends Finding {
  _receivedAt: string;
}

interface LiveFindingsFeedProps {
  scanId: string;
}

export default function LiveFindingsFeed({ scanId }: LiveFindingsFeedProps) {
  const [findings, setFindings] = useState<LiveFinding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Subscribe to live findings
  useEffect(() => {
    const unsubscribe = onScanFinding((data) => {
      if (data.scan_id === scanId) {
        const liveFinding: LiveFinding = {
          ...data.finding,
          _receivedAt: new Date().toISOString(),
        };
        setFindings((prev) => [...prev, liveFinding]);
      }
    });

    return unsubscribe;
  }, [scanId]);

  // Auto-scroll to bottom when new findings arrive
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [findings]);

  const handleFindingClick = (finding: LiveFinding) => {
    setSelectedFinding(finding);
    setDrawerOpen(true);
  };

  const handleCloseDrawer = () => {
    setDrawerOpen(false);
    setTimeout(() => setSelectedFinding(null), 300);
  };

  const formatTime = (dateStr: string) => {
    return new Date(dateStr).toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  };

  return (
    <>
      <div className="flex h-full flex-col rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)]">
        {/* Header */}
        <div className="flex items-center gap-2 border-b border-[var(--color-border)] px-4 py-3">
          <Radio className="h-4 w-4 text-[var(--color-accent)] animate-pulse" />
          <h3 className="text-sm font-semibold text-[var(--color-text-primary)]">
            Live Findings
          </h3>
          <span className="ml-auto rounded-full bg-[var(--color-accent)]/15 px-2 py-0.5 text-xs font-medium text-[var(--color-accent)]">
            {findings.length}
          </span>
        </div>

        {/* Findings List */}
        <div
          ref={scrollRef}
          className="flex-1 overflow-y-auto"
        >
          {findings.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <Radio className="mb-3 h-8 w-8 text-[var(--color-text-muted)] opacity-40" />
              <p className="text-sm text-[var(--color-text-muted)]">
                Waiting for findings...
              </p>
              <p className="mt-1 text-xs text-[var(--color-text-muted)] opacity-60">
                Findings will appear here in real time
              </p>
            </div>
          ) : (
            <div className="divide-y divide-[var(--color-border)]">
              {findings.map((finding, index) => (
                <button
                  key={finding.id || index}
                  onClick={() => handleFindingClick(finding)}
                  className="flex w-full items-start gap-3 px-4 py-3 text-left transition-colors hover:bg-[var(--color-bg-hover)] animate-[fadeIn_0.3s_ease-in-out]"
                >
                  <SeverityBadge severity={finding.severity} />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium text-[var(--color-text-primary)]">
                      {finding.title}
                    </p>
                    <p className="mt-0.5 text-xs text-[var(--color-text-muted)]">
                      {finding.category}
                    </p>
                  </div>
                  <span className="shrink-0 text-xs text-[var(--color-text-muted)]">
                    {formatTime(finding._receivedAt)}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      <FindingDrawer
        finding={selectedFinding}
        isOpen={drawerOpen}
        onClose={handleCloseDrawer}
      />
    </>
  );
}
