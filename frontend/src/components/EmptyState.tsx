/**
 * Honest empty state: names the milestone that will populate the view
 * instead of faking data ("no fake completeness").
 */

interface EmptyStateProps {
  title: string;
  description: string;
  /** Roadmap milestone that fills this view, e.g. "M2". */
  milestone: string;
}

export function EmptyState({ title, description, milestone }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-carbon-600 bg-carbon-900/50 px-6 py-16 text-center">
      <p className="text-sm font-medium text-zinc-200">{title}</p>
      <p className="max-w-md text-xs leading-relaxed text-zinc-500">{description}</p>
      <span className="badge mt-2">Populated in {milestone}</span>
    </div>
  );
}
