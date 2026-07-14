import type { ReactNode } from "react";

interface DataTableProps {
  headers: ReactNode[];
  children: ReactNode;
  loading?: boolean;
  loadingLabel?: string;
  empty?: ReactNode;
  pagination?: ReactNode;
  "data-testid"?: string;
}

export function DataTable({ headers, children, loading = false, loadingLabel = "Loading…", empty, pagination, "data-testid": testId }: DataTableProps) {
  if (loading) return <p role="status" className="text-xs text-zinc-500">{loadingLabel}</p>;
  if (empty) return <>{empty}</>;
  return <><div className="panel overflow-x-auto" data-testid={testId}><table className="w-full text-xs"><thead><tr className="border-b border-carbon-700 text-left text-zinc-500">{headers.map((header, index) => <th key={index} className="px-4 py-2 font-medium">{header}</th>)}</tr></thead><tbody>{children}</tbody></table></div>{pagination}</>;
}
