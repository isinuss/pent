import { useEffect, useRef, useCallback } from 'react';
import { Terminal as XTerm } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import { subscribeScan } from '../lib/socket';

interface TerminalProps {
  scanId: string;
}

export default function Terminal({ scanId }: TerminalProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<XTerm | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);

  const writeLine = useCallback((text: string) => {
    if (termRef.current) {
      termRef.current.writeln(text);
    }
  }, []);

  useEffect(() => {
    if (!containerRef.current) return;

    const term = new XTerm({
      cursorBlink: false,
      disableStdin: true,
      fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', Menlo, Monaco, 'Courier New', monospace",
      fontSize: 13,
      lineHeight: 1.4,
      theme: {
        background: '#0d1117',
        foreground: '#e2e8f0',
        cursor: '#00d4aa',
        selectionBackground: '#2a3a5266',
        black: '#0d1117',
        red: '#ef4444',
        green: '#00d4aa',
        yellow: '#eab308',
        blue: '#3b82f6',
        magenta: '#a855f7',
        cyan: '#06b6d4',
        white: '#e2e8f0',
        brightBlack: '#64748b',
        brightRed: '#f87171',
        brightGreen: '#00f0c0',
        brightYellow: '#fbbf24',
        brightBlue: '#60a5fa',
        brightMagenta: '#c084fc',
        brightCyan: '#22d3ee',
        brightWhite: '#f8fafc',
      },
      scrollback: 5000,
      convertEol: true,
    });

    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);

    term.open(containerRef.current);

    requestAnimationFrame(() => {
      fitAddon.fit();
    });

    termRef.current = term;
    fitAddonRef.current = fitAddon;

    term.writeln('\x1b[36m[PENT]\x1b[0m Terminal connected. Waiting for scan output...');
    term.writeln('');

    const unsubscribe = subscribeScan(
      scanId,
      (data) => {
        term.writeln(data.line);
      },
      (data) => {
        if (data.status === 'completed') {
          term.writeln('');
          term.writeln('\x1b[32m[PENT]\x1b[0m Scan completed successfully.');
          if (data.finding_count !== undefined) {
            term.writeln(`\x1b[32m[PENT]\x1b[0m Findings: ${data.finding_count}`);
          }
        } else if (data.status === 'error') {
          term.writeln('');
          term.writeln('\x1b[31m[PENT]\x1b[0m Scan encountered an error.');
        } else if (data.status === 'running') {
          term.writeln('\x1b[33m[PENT]\x1b[0m Scan is running...');
        }
      }
    );

    const handleResize = () => {
      requestAnimationFrame(() => {
        fitAddon.fit();
      });
    };

    window.addEventListener('resize', handleResize);

    const resizeObserver = new ResizeObserver(() => {
      requestAnimationFrame(() => {
        fitAddon.fit();
      });
    });
    resizeObserver.observe(containerRef.current);

    return () => {
      unsubscribe();
      window.removeEventListener('resize', handleResize);
      resizeObserver.disconnect();
      term.dispose();
      termRef.current = null;
      fitAddonRef.current = null;
    };
  }, [scanId, writeLine]);

  return (
    <div className="rounded-lg border border-[var(--color-border)] overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-2 bg-[var(--color-bg-secondary)] border-b border-[var(--color-border)]">
        <div className="flex gap-1.5">
          <span className="h-3 w-3 rounded-full bg-[var(--color-severity-critical)] opacity-80" />
          <span className="h-3 w-3 rounded-full bg-[var(--color-severity-medium)] opacity-80" />
          <span className="h-3 w-3 rounded-full bg-[var(--color-severity-low)] opacity-80" />
        </div>
        <span className="ml-2 text-xs text-[var(--color-text-muted)] font-mono">
          scan:{scanId.slice(0, 8)}
        </span>
      </div>
      <div
        ref={containerRef}
        className="h-[400px] bg-[var(--color-terminal-bg)] p-2"
      />
    </div>
  );
}
