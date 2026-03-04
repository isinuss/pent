import { useEffect, useRef } from 'react';
import { X } from 'lucide-react';
import SeverityBadge from './SeverityBadge';
import type { Finding } from '../lib/api';

interface FindingDrawerProps {
  finding: Finding | null;
  onClose: () => void;
  isOpen: boolean;
}

export default function FindingDrawer({ finding, onClose, isOpen }: FindingDrawerProps) {
  const drawerRef = useRef<HTMLDivElement>(null);

  // Close on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  // Prevent body scroll when drawer is open
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
    return () => {
      document.body.style.overflow = '';
    };
  }, [isOpen]);

  return (
    <>
      {/* Overlay */}
      <div
        className={`fixed inset-0 z-50 bg-black/60 transition-opacity duration-300 ${
          isOpen ? 'opacity-100' : 'pointer-events-none opacity-0'
        }`}
        onClick={onClose}
      />

      {/* Drawer */}
      <div
        ref={drawerRef}
        className={`fixed right-0 top-0 z-50 flex h-full w-[480px] max-w-[90vw] flex-col bg-[var(--color-bg-card)] border-l border-[var(--color-border)] shadow-2xl transition-transform duration-300 ease-in-out ${
          isOpen ? 'translate-x-0' : 'translate-x-full'
        }`}
      >
        {/* Header */}
        <div className="flex items-start justify-between gap-4 border-b border-[var(--color-border)] px-6 py-5">
          <div className="min-w-0 flex-1">
            {finding && (
              <>
                <div className="mb-2">
                  <SeverityBadge severity={finding.severity} />
                </div>
                <h2 className="text-lg font-bold text-[var(--color-text-primary)] leading-tight">
                  {finding.title}
                </h2>
                <p className="mt-1 text-xs text-[var(--color-text-muted)]">
                  {finding.category}
                </p>
              </>
            )}
          </div>
          <button
            onClick={onClose}
            className="shrink-0 rounded-lg p-1.5 text-[var(--color-text-muted)] transition-colors hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text-primary)]"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Content */}
        {finding && (
          <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">
            {/* Description */}
            {finding.description && (
              <section>
                <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-[var(--color-text-muted)]">
                  Description
                </h3>
                <p className="text-sm leading-relaxed text-[var(--color-text-secondary)] whitespace-pre-wrap">
                  {finding.description}
                </p>
              </section>
            )}

            {/* Evidence */}
            {finding.evidence && (
              <section>
                <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-[var(--color-text-muted)]">
                  Evidence
                </h3>
                <pre className="overflow-x-auto rounded-lg bg-[var(--color-terminal-bg)] p-4 text-xs leading-relaxed text-[var(--color-text-secondary)] font-mono">
                  {finding.evidence}
                </pre>
              </section>
            )}

            {/* Remediation */}
            {finding.recommendation && (
              <section>
                <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-[var(--color-text-muted)]">
                  Remediation
                </h3>
                <p className="text-sm leading-relaxed text-[var(--color-text-secondary)] whitespace-pre-wrap">
                  {finding.recommendation}
                </p>
              </section>
            )}

            {/* Meta */}
            <section>
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-[var(--color-text-muted)]">
                Details
              </h3>
              <dl className="space-y-2 text-sm">
                <div className="flex items-center justify-between">
                  <dt className="text-[var(--color-text-muted)]">Finding ID</dt>
                  <dd className="font-mono text-xs text-[var(--color-text-secondary)]">
                    {String(finding.id).slice(0, 12)}
                  </dd>
                </div>
                <div className="flex items-center justify-between">
                  <dt className="text-[var(--color-text-muted)]">Scan ID</dt>
                  <dd className="font-mono text-xs text-[var(--color-text-secondary)]">
                    {String(finding.scan_id).slice(0, 12)}
                  </dd>
                </div>
                <div className="flex items-center justify-between">
                  <dt className="text-[var(--color-text-muted)]">Category</dt>
                  <dd className="text-[var(--color-text-secondary)]">
                    {finding.category}
                  </dd>
                </div>
                <div className="flex items-center justify-between">
                  <dt className="text-[var(--color-text-muted)]">Severity</dt>
                  <dd>
                    <SeverityBadge severity={finding.severity} />
                  </dd>
                </div>
              </dl>
            </section>
          </div>
        )}
      </div>
    </>
  );
}
