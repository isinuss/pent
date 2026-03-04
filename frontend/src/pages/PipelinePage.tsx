import { useEffect, useState, useCallback } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  Play,
  CheckCircle,
  AlertTriangle,
  Clock,
  Search,
  Shield,
  Globe,
  Code,
  Zap,
  ChevronRight,
  ArrowRight,
  Loader2,
  Info,
  X,
} from 'lucide-react';
import {
  getPipelinePhases,
  startPipeline,
  getPipelineRecommendations,
  getTargets,
  type PipelinePhase,
  type PipelineRecommendation,
  type Target,
} from '../lib/api';
import { getSocket } from '../lib/socket';

const phaseIcons: Record<string, React.ElementType> = {
  recon: Search,
  vuln_scan: Shield,
  web_test: Globe,
  js_analyze: Code,
  checks: CheckCircle,
  takeover: AlertTriangle,
};

type PhaseStatus = 'pending' | 'running' | 'completed' | 'error';

interface PhaseState {
  status: PhaseStatus;
  scanId?: string;
  findingCount?: number;
}

const priorityColors: Record<string, string> = {
  critical: 'var(--color-severity-critical)',
  high: 'var(--color-severity-high)',
  medium: 'var(--color-severity-medium)',
  low: 'var(--color-severity-low)',
  info: 'var(--color-severity-info)',
};

export default function PipelinePage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const targetParam = searchParams.get('target') || '';

  const [target, setTarget] = useState(targetParam);
  const [targets, setTargets] = useState<Target[]>([]);
  const [phases, setPhases] = useState<PipelinePhase[]>([]);
  const [selectedPhases, setSelectedPhases] = useState<Set<string>>(new Set());
  const [phaseStates, setPhaseStates] = useState<Record<string, PhaseState>>({});
  const [pipelineRunning, setPipelineRunning] = useState(false);
  const [pipelineId, setPipelineId] = useState<string | null>(null);
  const [scanIds, setScanIds] = useState<Record<string, string>>({});
  const [recommendations, setRecommendations] = useState<PipelineRecommendation[]>([]);
  const [completedTypes, setCompletedTypes] = useState<string[]>([]);
  const [totalFindings, setTotalFindings] = useState(0);
  const [loading, setLoading] = useState(true);
  const [showTargetPicker, setShowTargetPicker] = useState(false);

  // Load phases and targets
  useEffect(() => {
    async function load() {
      const [phasesResult, targetsResult] = await Promise.all([
        getPipelinePhases(),
        getTargets(),
      ]);

      if (phasesResult.data) {
        setPhases(phasesResult.data);
        setSelectedPhases(new Set(phasesResult.data.map((p) => p.id)));
      }
      if (targetsResult.data) {
        setTargets(targetsResult.data);
      }
      setLoading(false);
    }
    load();
  }, []);

  // Load existing recommendations when target changes
  useEffect(() => {
    if (!target) return;
    async function loadRecs() {
      const result = await getPipelineRecommendations(target);
      if (result.data) {
        setRecommendations(result.data.recommendations);
        setCompletedTypes(result.data.scan_types_completed);
        setTotalFindings(result.data.total_findings);
      }
    }
    loadRecs();
  }, [target]);

  // Listen for pipeline WebSocket events
  useEffect(() => {
    if (!pipelineId) return;

    const socket = getSocket();

    const handlePhase = (data: {
      pipeline_id: string;
      phase_id: string;
      scan_id: string;
      status: string;
      finding_count?: number;
    }) => {
      if (data.pipeline_id !== pipelineId) return;
      setPhaseStates((prev) => ({
        ...prev,
        [data.phase_id]: {
          status: data.status as PhaseStatus,
          scanId: data.scan_id,
          findingCount: data.finding_count,
        },
      }));
    };

    const handleComplete = (data: {
      pipeline_id: string;
      total_findings: number;
      recommendations: PipelineRecommendation[];
      scan_ids: Record<string, string>;
    }) => {
      if (data.pipeline_id !== pipelineId) return;
      setPipelineRunning(false);
      setRecommendations(data.recommendations);
      setTotalFindings(data.total_findings);
      setScanIds(data.scan_ids);
    };

    socket.on('pipeline_phase', handlePhase);
    socket.on('pipeline_complete', handleComplete);

    return () => {
      socket.off('pipeline_phase', handlePhase);
      socket.off('pipeline_complete', handleComplete);
    };
  }, [pipelineId]);

  const handleStart = useCallback(async () => {
    if (!target.trim()) return;

    setPipelineRunning(true);
    setRecommendations([]);

    // Initialize phase states
    const initialStates: Record<string, PhaseState> = {};
    for (const pid of selectedPhases) {
      initialStates[pid] = { status: 'pending' };
    }
    setPhaseStates(initialStates);

    const result = await startPipeline(
      target,
      Array.from(selectedPhases)
    );

    if (result.data) {
      setPipelineId(result.data.pipeline_id);
      setScanIds(result.data.scan_ids);
    } else {
      setPipelineRunning(false);
    }
  }, [target, selectedPhases]);

  const togglePhase = (phaseId: string) => {
    setSelectedPhases((prev) => {
      const next = new Set(prev);
      if (next.has(phaseId)) {
        next.delete(phaseId);
      } else {
        next.add(phaseId);
      }
      return next;
    });
  };

  const selectAllPhases = () => {
    setSelectedPhases(new Set(phases.map((p) => p.id)));
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-[var(--color-border)] border-t-[var(--color-accent)]" />
      </div>
    );
  }

  const completedCount = Object.values(phaseStates).filter(
    (s) => s.status === 'completed'
  ).length;
  const totalSelected = selectedPhases.size;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">
          Testing Pipeline
        </h1>
        <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
          Automated lateral testing pipeline - test a target through all phases sequentially
        </p>
      </div>

      {/* Target Selection */}
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)] p-5">
        <h2 className="mb-3 text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide">
          Target
        </h2>
        <div className="flex gap-3">
          <div className="relative flex-1">
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="Enter target (e.g., example.com or https://example.com)"
              disabled={pipelineRunning}
              className="w-full rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] px-4 py-2.5 text-sm text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] outline-none transition-colors focus:border-[var(--color-accent)] disabled:opacity-50"
            />
          </div>
          <div className="relative">
            <button
              onClick={() => setShowTargetPicker(!showTargetPicker)}
              disabled={pipelineRunning}
              className="inline-flex items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] px-4 py-2.5 text-sm font-medium text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-bg-hover)] disabled:opacity-50"
            >
              Saved Targets
              <ChevronRight className={`h-4 w-4 transition-transform ${showTargetPicker ? 'rotate-90' : ''}`} />
            </button>
            {showTargetPicker && targets.length > 0 && (
              <div className="absolute right-0 top-full z-10 mt-1 w-72 rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)] shadow-xl">
                <div className="max-h-60 overflow-y-auto p-2">
                  {targets.map((t) => (
                    <button
                      key={t.id}
                      onClick={() => {
                        setTarget(t.target);
                        setShowTargetPicker(false);
                      }}
                      className="flex w-full items-center gap-3 rounded-md px-3 py-2 text-left text-sm transition-colors hover:bg-[var(--color-bg-hover)]"
                    >
                      <Globe className="h-4 w-4 shrink-0 text-[var(--color-text-muted)]" />
                      <div className="min-w-0 flex-1">
                        <p className="truncate font-medium text-[var(--color-text-primary)]">
                          {t.name}
                        </p>
                        <p className="truncate text-xs text-[var(--color-text-muted)]">
                          {t.target}
                        </p>
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Previous scan info */}
        {completedTypes.length > 0 && !pipelineRunning && (
          <div className="mt-3 flex items-center gap-2 text-xs text-[var(--color-text-muted)]">
            <Info className="h-3.5 w-3.5" />
            <span>
              Previously completed: {completedTypes.join(', ')} ({totalFindings} findings)
            </span>
          </div>
        )}
      </div>

      {/* Pipeline Phases */}
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)]">
        <div className="flex items-center justify-between border-b border-[var(--color-border)] px-5 py-4">
          <h2 className="text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide">
            Pipeline Phases
          </h2>
          <div className="flex items-center gap-3">
            {pipelineRunning && (
              <span className="flex items-center gap-2 text-xs text-[var(--color-accent)]">
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                {completedCount}/{totalSelected} completed
              </span>
            )}
            {!pipelineRunning && (
              <button
                onClick={selectAllPhases}
                className="text-xs text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)] transition-colors"
              >
                Select All
              </button>
            )}
          </div>
        </div>

        {/* Progress bar */}
        {pipelineRunning && (
          <div className="h-1 bg-[var(--color-bg-secondary)]">
            <div
              className="h-full bg-[var(--color-accent)] transition-all duration-500"
              style={{ width: `${totalSelected > 0 ? (completedCount / totalSelected) * 100 : 0}%` }}
            />
          </div>
        )}

        <div className="divide-y divide-[var(--color-border)]">
          {phases.map((phase, index) => {
            const Icon = phaseIcons[phase.id] || Zap;
            const state = phaseStates[phase.id];
            const isSelected = selectedPhases.has(phase.id);
            const isRunning = state?.status === 'running';
            const isCompleted = state?.status === 'completed';
            const isError = state?.status === 'error';
            const wasPreviouslyRun = completedTypes.includes(phase.scan_type);

            return (
              <div
                key={phase.id}
                className={`flex items-center gap-4 px-5 py-4 transition-colors ${
                  isRunning ? 'bg-[var(--color-accent)]/5' : ''
                } ${isCompleted ? 'bg-[var(--color-severity-low)]/5' : ''}`}
              >
                {/* Phase number / status */}
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full border-2 transition-colors"
                  style={{
                    borderColor: isCompleted
                      ? 'var(--color-severity-low)'
                      : isRunning
                      ? 'var(--color-accent)'
                      : isError
                      ? 'var(--color-severity-critical)'
                      : 'var(--color-border)',
                    backgroundColor: isCompleted
                      ? 'rgba(34, 197, 94, 0.1)'
                      : isRunning
                      ? 'rgba(0, 212, 170, 0.1)'
                      : 'transparent',
                  }}
                >
                  {isRunning ? (
                    <Loader2 className="h-5 w-5 animate-spin text-[var(--color-accent)]" />
                  ) : isCompleted ? (
                    <CheckCircle className="h-5 w-5 text-[var(--color-severity-low)]" />
                  ) : isError ? (
                    <X className="h-5 w-5 text-[var(--color-severity-critical)]" />
                  ) : (
                    <span className="text-sm font-bold text-[var(--color-text-muted)]">
                      {index + 1}
                    </span>
                  )}
                </div>

                {/* Phase info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <Icon className="h-4 w-4 text-[var(--color-text-muted)]" />
                    <h3 className="text-sm font-semibold text-[var(--color-text-primary)]">
                      {phase.name}
                    </h3>
                    {wasPreviouslyRun && !pipelineRunning && (
                      <span className="rounded-full bg-[var(--color-severity-low)]/15 px-2 py-0.5 text-xs text-[var(--color-severity-low)]">
                        Previously run
                      </span>
                    )}
                  </div>
                  <p className="mt-0.5 text-xs text-[var(--color-text-muted)] line-clamp-1">
                    {phase.description}
                  </p>
                </div>

                {/* Time estimate */}
                <div className="hidden sm:flex items-center gap-1 text-xs text-[var(--color-text-muted)]">
                  <Clock className="h-3.5 w-3.5" />
                  {phase.estimated_time}
                </div>

                {/* Finding count (if completed) */}
                {isCompleted && state.findingCount !== undefined && (
                  <button
                    onClick={() => state.scanId && navigate(`/results/${state.scanId}`)}
                    className="flex items-center gap-1 rounded-full bg-[var(--color-bg-secondary)] px-2.5 py-1 text-xs font-medium text-[var(--color-text-secondary)] hover:bg-[var(--color-bg-hover)] transition-colors"
                  >
                    {state.findingCount} findings
                    <ArrowRight className="h-3 w-3" />
                  </button>
                )}

                {/* Selection checkbox (when not running) */}
                {!pipelineRunning && (
                  <button
                    onClick={() => togglePhase(phase.id)}
                    className={`h-5 w-5 shrink-0 rounded border-2 transition-colors ${
                      isSelected
                        ? 'border-[var(--color-accent)] bg-[var(--color-accent)]'
                        : 'border-[var(--color-border)] hover:border-[var(--color-text-muted)]'
                    }`}
                  >
                    {isSelected && (
                      <CheckCircle className="h-full w-full text-white p-0.5" />
                    )}
                  </button>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Start Button */}
      {!pipelineRunning && (
        <button
          onClick={handleStart}
          disabled={!target.trim() || selectedPhases.size === 0}
          className="flex w-full items-center justify-center gap-2 rounded-lg bg-[var(--color-accent)] px-6 py-3 text-sm font-semibold text-white transition-all hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          <Play className="h-4 w-4" />
          Start Pipeline ({selectedPhases.size} phase{selectedPhases.size !== 1 ? 's' : ''})
        </button>
      )}

      {/* Recommendations */}
      {recommendations.length > 0 && (
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)]">
          <div className="border-b border-[var(--color-border)] px-5 py-4">
            <h2 className="text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide">
              Recommendations
            </h2>
            {totalFindings > 0 && (
              <p className="mt-1 text-xs text-[var(--color-text-muted)]">
                Based on {totalFindings} finding{totalFindings !== 1 ? 's' : ''} from completed scans
              </p>
            )}
          </div>
          <div className="divide-y divide-[var(--color-border)]">
            {recommendations.map((rec, i) => (
              <div key={i} className="flex items-start gap-4 px-5 py-4">
                <div
                  className="mt-0.5 h-3 w-3 shrink-0 rounded-full"
                  style={{ backgroundColor: priorityColors[rec.priority] || priorityColors.info }}
                />
                <div className="flex-1 min-w-0">
                  <h3 className="text-sm font-semibold text-[var(--color-text-primary)]">
                    {rec.title}
                  </h3>
                  <p className="mt-0.5 text-xs text-[var(--color-text-secondary)] leading-relaxed">
                    {rec.description}
                  </p>
                  <p className="mt-1.5 text-xs text-[var(--color-accent)]">
                    {rec.action}
                  </p>
                </div>
                <span
                  className="shrink-0 rounded-full px-2 py-0.5 text-xs font-medium"
                  style={{
                    backgroundColor: `${priorityColors[rec.priority] || priorityColors.info}15`,
                    color: priorityColors[rec.priority] || priorityColors.info,
                  }}
                >
                  {rec.priority}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Scan Results Links */}
      {!pipelineRunning && Object.keys(scanIds).length > 0 && (
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)] p-5">
          <h2 className="mb-3 text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wide">
            View Detailed Results
          </h2>
          <div className="flex flex-wrap gap-2">
            {Object.entries(scanIds).map(([phaseId, scanId]) => {
              const phase = phases.find((p) => p.id === phaseId);
              return (
                <button
                  key={phaseId}
                  onClick={() => navigate(`/results/${scanId}`)}
                  className="inline-flex items-center gap-2 rounded-lg border border-[var(--color-border)] px-3 py-2 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text-primary)]"
                >
                  {phase?.name || phaseId}
                  <ArrowRight className="h-3 w-3" />
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
