import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, BookOpen } from 'lucide-react';
import { getGuide, type Guide } from '../lib/api';

function parseRichContent(content: string): string {
  let html = content;

  // Escape HTML entities first
  html = html
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  // Handle Rich markup tags
  // [bold]...[/bold]
  html = html.replace(/\[bold\](.*?)\[\/bold\]/gs, '<strong class="text-[var(--color-text-primary)] font-semibold">$1</strong>');

  // [italic]...[/italic]
  html = html.replace(/\[italic\](.*?)\[\/italic\]/gs, '<em>$1</em>');

  // [underline]...[/underline]
  html = html.replace(/\[underline\](.*?)\[\/underline\]/gs, '<span class="underline">$1</span>');

  // [dim]...[/dim]
  html = html.replace(/\[dim\](.*?)\[\/dim\]/gs, '<span class="text-[var(--color-text-muted)]">$1</span>');

  // Color tags: [red]...[/red], [green]...[/green], [yellow]...[/yellow], [blue]...[/blue], [cyan]...[/cyan], [magenta]...[/magenta]
  const colorMap: Record<string, string> = {
    red: '#ef4444',
    green: '#00d4aa',
    yellow: '#eab308',
    blue: '#3b82f6',
    cyan: '#06b6d4',
    magenta: '#a855f7',
    white: '#e2e8f0',
  };

  for (const [colorName, colorValue] of Object.entries(colorMap)) {
    const regex = new RegExp(`\\[${colorName}\\](.*?)\\[\\/${colorName}\\]`, 'gs');
    html = html.replace(regex, `<span style="color: ${colorValue}">$1</span>`);
  }

  // Handle combined tags like [bold red]...[/bold red] or [bold green]...[/]
  html = html.replace(/\[bold\s+(\w+)\](.*?)\[\/(?:bold\s+\w+|)\]/gs, (_match, color: string, text: string) => {
    const c = colorMap[color] || '#e2e8f0';
    return `<strong style="color: ${c}" class="font-semibold">${text}</strong>`;
  });

  // Handle [link=url]text[/link]
  html = html.replace(/\[link=(.*?)\](.*?)\[\/link\]/gs, '<a href="$1" target="_blank" rel="noopener noreferrer" class="text-[var(--color-accent)] hover:underline">$2</a>');

  // Remove any remaining unknown bracket tags
  html = html.replace(/\[\/?[a-zA-Z][^\]]*\]/g, '');

  // Convert markdown-style headers
  html = html.replace(/^### (.*$)/gm, '<h3 class="text-base font-semibold text-[var(--color-text-primary)] mt-6 mb-2">$1</h3>');
  html = html.replace(/^## (.*$)/gm, '<h2 class="text-lg font-bold text-[var(--color-text-primary)] mt-8 mb-3">$1</h2>');
  html = html.replace(/^# (.*$)/gm, '<h1 class="text-xl font-bold text-[var(--color-text-primary)] mt-8 mb-4">$1</h1>');

  // Convert markdown-style code blocks
  html = html.replace(/```([\s\S]*?)```/g, '<pre class="rounded-lg bg-[var(--color-terminal-bg)] p-4 text-sm font-mono text-[var(--color-text-secondary)] overflow-x-auto my-3">$1</pre>');

  // Convert inline code
  html = html.replace(/`([^`]+)`/g, '<code class="rounded bg-[var(--color-terminal-bg)] px-1.5 py-0.5 text-sm font-mono text-[var(--color-accent)]">$1</code>');

  // Convert markdown-style bullet points
  html = html.replace(/^[-*] (.*$)/gm, '<li class="ml-4 text-sm text-[var(--color-text-secondary)] leading-relaxed">$1</li>');

  // Wrap consecutive li elements in ul
  html = html.replace(/((?:<li[^>]*>.*?<\/li>\s*)+)/gs, '<ul class="list-disc space-y-1 my-2">$1</ul>');

  // Convert double newlines to paragraph breaks
  html = html.replace(/\n\n/g, '</p><p class="text-sm text-[var(--color-text-secondary)] leading-relaxed mb-3">');

  // Wrap in initial p tag
  html = '<p class="text-sm text-[var(--color-text-secondary)] leading-relaxed mb-3">' + html + '</p>';

  // Clean up empty paragraphs
  html = html.replace(/<p[^>]*>\s*<\/p>/g, '');

  return html;
}

export default function GuideDetailPage() {
  const { topic } = useParams<{ topic: string }>();
  const navigate = useNavigate();

  const [guide, setGuide] = useState<Guide | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!topic) return;
    let cancelled = false;

    async function load() {
      const result = await getGuide(topic!);
      if (cancelled) return;

      if (result.error) {
        setError(result.error);
      } else if (result.data) {
        setGuide(result.data);
      }
      setLoading(false);
    }

    load();
    return () => { cancelled = true; };
  }, [topic]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-[var(--color-border)] border-t-[var(--color-accent)]" />
      </div>
    );
  }

  if (error || !guide) {
    return (
      <div className="space-y-4">
        <button
          onClick={() => navigate('/guides')}
          className="inline-flex items-center gap-2 text-sm text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Guides
        </button>
        <div className="rounded-lg border border-[var(--color-severity-critical)]/30 bg-[var(--color-severity-critical)]/10 px-6 py-4 text-sm text-[var(--color-severity-critical)]">
          {error || 'Guide not found'}
        </div>
      </div>
    );
  }

  const parsedContent = parseRichContent(guide.content);

  return (
    <div className="space-y-6">
      {/* Back button */}
      <button
        onClick={() => navigate('/guides')}
        className="inline-flex items-center gap-2 text-sm text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] transition-colors"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to Guides
      </button>

      {/* Guide Content Card */}
      <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-card)]">
        {/* Title Header */}
        <div className="flex items-center gap-3 border-b border-[var(--color-border)] px-6 py-5">
          <BookOpen className="h-6 w-6 text-[var(--color-accent)]" />
          <h1 className="text-xl font-bold text-[var(--color-text-primary)]">
            {guide.title}
          </h1>
        </div>

        {/* Content */}
        <div
          className="px-6 py-6"
          dangerouslySetInnerHTML={{ __html: parsedContent }}
        />
      </div>
    </div>
  );
}
