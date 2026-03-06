import { useState, useEffect, useRef, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, ZoomIn, ZoomOut, Maximize2 } from 'lucide-react';
import { getReconData, type ReconNode, type ReconEdge } from '../lib/api';

const GROUP_COLORS: Record<string, string> = {
  target: '#3b82f6',
  dns: '#8b5cf6',
  subdomain: '#06b6d4',
  tech: '#f59e0b',
  port: '#ef4444',
  ssl: '#10b981',
  header: '#6366f1',
  waf: '#ec4899',
};

const GROUP_RADIUS: Record<string, number> = {
  target: 32,
  dns: 18,
  subdomain: 20,
  tech: 16,
  port: 14,
  ssl: 16,
  header: 14,
  waf: 18,
};

interface SimNode extends ReconNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
  fx?: number;
  fy?: number;
}

function useForceSimulation(
  nodes: ReconNode[],
  edges: ReconEdge[],
  width: number,
  height: number,
) {
  const simNodesRef = useRef<SimNode[]>([]);
  const [tick, setTick] = useState(0);
  const animRef = useRef<number>(0);
  const iterRef = useRef(0);

  useEffect(() => {
    if (nodes.length === 0) return;

    // Initialize positions in a circle around center
    const cx = width / 2;
    const cy = height / 2;
    simNodesRef.current = nodes.map((n, i) => {
      if (n.id === 'target') {
        return { ...n, x: cx, y: cy, vx: 0, vy: 0, fx: cx, fy: cy };
      }
      const angle = (2 * Math.PI * i) / (nodes.length - 1);
      const r = 150 + Math.random() * 80;
      return {
        ...n,
        x: cx + Math.cos(angle) * r,
        y: cy + Math.sin(angle) * r,
        vx: 0,
        vy: 0,
      };
    });
    iterRef.current = 0;

    const nodeMap = new Map<string, SimNode>();

    function simulate() {
      const simNodes = simNodesRef.current;
      nodeMap.clear();
      for (const n of simNodes) nodeMap.set(n.id, n);

      const alpha = Math.max(0.001, 1 - iterRef.current / 300);
      iterRef.current++;

      // Repulsion between all nodes
      for (let i = 0; i < simNodes.length; i++) {
        for (let j = i + 1; j < simNodes.length; j++) {
          const a = simNodes[i];
          const b = simNodes[j];
          let dx = b.x - a.x;
          let dy = b.y - a.y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const force = (800 * alpha) / (dist * dist);
          dx = (dx / dist) * force;
          dy = (dy / dist) * force;
          if (!a.fx) { a.vx -= dx; a.vy -= dy; }
          if (!b.fx) { b.vx += dx; b.vy += dy; }
        }
      }

      // Attraction along edges
      for (const e of edges) {
        const source = nodeMap.get(e.source);
        const target = nodeMap.get(e.target);
        if (!source || !target) continue;
        const dx = target.x - source.x;
        const dy = target.y - source.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const force = (dist - 160) * 0.02 * alpha;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        if (!source.fx) { source.vx += fx; source.vy += fy; }
        if (!target.fx) { target.vx -= fx; target.vy -= fy; }
      }

      // Center gravity
      for (const n of simNodes) {
        if (n.fx !== undefined) { n.x = n.fx; n.y = n.fy!; continue; }
        n.vx += (cx - n.x) * 0.005 * alpha;
        n.vy += (cy - n.y) * 0.005 * alpha;
        n.vx *= 0.85;
        n.vy *= 0.85;
        n.x += n.vx;
        n.y += n.vy;
        // Bounds
        n.x = Math.max(40, Math.min(width - 40, n.x));
        n.y = Math.max(40, Math.min(height - 40, n.y));
      }

      setTick((t) => t + 1);

      if (iterRef.current < 300) {
        animRef.current = requestAnimationFrame(simulate);
      }
    }

    animRef.current = requestAnimationFrame(simulate);
    return () => cancelAnimationFrame(animRef.current);
  }, [nodes, edges, width, height]);

  return { simNodes: simNodesRef.current, tick };
}

export default function ReconMapPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [nodes, setNodes] = useState<ReconNode[]>([]);
  const [edges, setEdges] = useState<ReconEdge[]>([]);
  const [targetName, setTargetName] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<ReconNode | null>(null);
  const [zoom, setZoom] = useState(1);
  const containerRef = useRef<HTMLDivElement>(null);

  const W = 900;
  const H = 600;

  const { simNodes } = useForceSimulation(nodes, edges, W, H);

  useEffect(() => {
    if (!scanId) return;
    (async () => {
      const result = await getReconData(scanId);
      if (result.error) {
        setError(result.error);
      } else if (result.data) {
        setNodes(result.data.nodes);
        setEdges(result.data.edges);
        setTargetName(result.data.target);
      }
      setLoading(false);
    })();
  }, [scanId]);

  const handleZoomIn = useCallback(() => setZoom((z) => Math.min(z + 0.2, 3)), []);
  const handleZoomOut = useCallback(() => setZoom((z) => Math.max(z - 0.2, 0.4)), []);
  const handleReset = useCallback(() => setZoom(1), []);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-[var(--color-border)] border-t-[var(--color-accent)]" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-4">
        <button onClick={() => navigate(-1)} className="inline-flex items-center gap-2 text-sm text-[var(--color-accent)]">
          <ArrowLeft className="h-4 w-4" /> Back
        </button>
        <div className="rounded-lg border border-[var(--color-severity-critical)]/30 bg-[var(--color-severity-critical)]/10 px-6 py-4 text-sm text-[var(--color-severity-critical)]">
          {error}
        </div>
      </div>
    );
  }

  // Build node position map for edges
  const nodePos = new Map<string, { x: number; y: number }>();
  for (const n of simNodes) {
    nodePos.set(n.id, { x: n.x, y: n.y });
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-4">
        <button
          onClick={() => navigate(-1)}
          className="rounded-lg p-2 text-[var(--color-text-muted)] transition-colors hover:bg-[var(--color-bg-hover)] hover:text-[var(--color-text-primary)]"
        >
          <ArrowLeft className="h-5 w-5" />
        </button>
        <div>
          <h1 className="text-xl font-bold text-[var(--color-text-primary)]">Recon Map</h1>
          <p className="text-sm text-[var(--color-text-secondary)]">{targetName}</p>
        </div>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-3">
        {Object.entries(GROUP_COLORS).map(([group, color]) => (
          <div key={group} className="flex items-center gap-1.5 text-xs text-[var(--color-text-muted)]">
            <span className="inline-block h-3 w-3 rounded-full" style={{ backgroundColor: color }} />
            {group.charAt(0).toUpperCase() + group.slice(1)}
          </div>
        ))}
      </div>

      {/* Map */}
      <div
        ref={containerRef}
        className="relative rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)] overflow-hidden"
      >
        {/* Zoom Controls */}
        <div className="absolute right-3 top-3 z-10 flex flex-col gap-1">
          <button onClick={handleZoomIn} className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-1.5 text-[var(--color-text-secondary)] hover:bg-[var(--color-bg-hover)]">
            <ZoomIn className="h-4 w-4" />
          </button>
          <button onClick={handleZoomOut} className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-1.5 text-[var(--color-text-secondary)] hover:bg-[var(--color-bg-hover)]">
            <ZoomOut className="h-4 w-4" />
          </button>
          <button onClick={handleReset} className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-1.5 text-[var(--color-text-secondary)] hover:bg-[var(--color-bg-hover)]">
            <Maximize2 className="h-4 w-4" />
          </button>
        </div>

        {nodes.length === 0 ? (
          <div className="flex h-96 items-center justify-center text-sm text-[var(--color-text-muted)]">
            No recon data available. Run a recon scan first.
          </div>
        ) : (
          <svg
            width="100%"
            height="600"
            viewBox={`0 0 ${W} ${H}`}
            className="block"
            style={{ transform: `scale(${zoom})`, transformOrigin: 'center center' }}
          >
            {/* Edges */}
            {edges.map((e, i) => {
              const s = nodePos.get(e.source);
              const t = nodePos.get(e.target);
              if (!s || !t) return null;
              return (
                <line
                  key={i}
                  x1={s.x}
                  y1={s.y}
                  x2={t.x}
                  y2={t.y}
                  stroke="#334155"
                  strokeWidth={1}
                  strokeOpacity={0.6}
                />
              );
            })}

            {/* Nodes */}
            {simNodes.map((n) => {
              const color = GROUP_COLORS[n.group] || '#64748b';
              const r = GROUP_RADIUS[n.group] || 16;
              const isSelected = selectedNode?.id === n.id;

              return (
                <g
                  key={n.id}
                  transform={`translate(${n.x}, ${n.y})`}
                  onClick={() => setSelectedNode(isSelected ? null : n)}
                  style={{ cursor: 'pointer' }}
                >
                  {isSelected && (
                    <circle r={r + 5} fill="none" stroke={color} strokeWidth={2} strokeDasharray="4 2" opacity={0.8} />
                  )}
                  <circle
                    r={r}
                    fill={color}
                    fillOpacity={0.2}
                    stroke={color}
                    strokeWidth={1.5}
                  />
                  <circle r={r * 0.4} fill={color} fillOpacity={0.8} />
                  <text
                    y={r + 14}
                    textAnchor="middle"
                    fill="#94a3b8"
                    fontSize={n.group === 'target' ? 12 : 10}
                    fontWeight={n.group === 'target' ? 'bold' : 'normal'}
                  >
                    {n.label.length > 28 ? n.label.slice(0, 25) + '...' : n.label}
                  </text>
                </g>
              );
            })}
          </svg>
        )}
      </div>

      {/* Selected Node Detail */}
      {selectedNode && (
        <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)] p-4">
          <div className="flex items-center gap-3 mb-2">
            <span
              className="inline-block h-3 w-3 rounded-full"
              style={{ backgroundColor: GROUP_COLORS[selectedNode.group] || '#64748b' }}
            />
            <span className="text-sm font-semibold text-[var(--color-text-primary)]">
              {selectedNode.label}
            </span>
            <span className="rounded-full bg-[var(--color-bg-secondary)] px-2 py-0.5 text-xs text-[var(--color-text-muted)]">
              {selectedNode.group}
            </span>
            {selectedNode.severity && (
              <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                selectedNode.severity === 'critical' ? 'bg-red-500/15 text-red-400' :
                selectedNode.severity === 'high' ? 'bg-orange-500/15 text-orange-400' :
                selectedNode.severity === 'medium' ? 'bg-yellow-500/15 text-yellow-400' :
                selectedNode.severity === 'low' ? 'bg-green-500/15 text-green-400' :
                'bg-slate-500/15 text-slate-400'
              }`}>
                {selectedNode.severity}
              </span>
            )}
          </div>
          {selectedNode.detail && (
            <p className="text-sm text-[var(--color-text-secondary)] font-mono break-all">
              {selectedNode.detail}
            </p>
          )}
        </div>
      )}
    </div>
  );
}
