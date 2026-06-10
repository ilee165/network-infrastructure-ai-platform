/** Standard page heading: title, one-line description, optional action slot. */

import type { ReactNode } from "react";

interface PageHeaderProps {
  title: string;
  description: string;
  actions?: ReactNode;
}

export function PageHeader({ title, description, actions }: PageHeaderProps) {
  return (
    <header className="flex flex-wrap items-end justify-between gap-4">
      <div>
        <h2 className="text-lg font-semibold text-zinc-100">{title}</h2>
        <p className="mt-1 text-xs text-zinc-500">{description}</p>
      </div>
      {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
    </header>
  );
}
