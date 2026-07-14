import { useQuery } from "@tanstack/react-query";

import { listIntegrations } from "../../api/integrations";
import { messageFor } from "../../components/ErrorBanner";
import { StatusPill } from "../../components/StatusPill";

export function SettingsIntegrationsSection() {
  const {
    data,
    isPending,
    error: loadError,
  } = useQuery({
    queryKey: ["integrations"],
    queryFn: listIntegrations,
  });

  return (
    <section
      aria-label="Integrations"
      data-testid="settings-integrations"
      className="flex flex-col gap-4"
    >
      <div className="panel p-4 flex flex-col gap-3">
        <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
          Vendor integrations
        </h3>
        <p className="text-sm text-zinc-300">
          Registered vendor plugins and the capabilities they declare. This is
          inventory only — live device reachability is discovery, not Settings.
        </p>
      </div>

      {isPending && (
        <p role="status" className="text-xs text-zinc-500">
          Loading integrations…
        </p>
      )}
      {loadError && (
        <p role="alert" className="text-xs text-status-error">
          {messageFor(loadError)}
        </p>
      )}

      {data && data.vendors.length === 0 && (
        <div className="panel p-4 text-sm text-zinc-400" data-testid="integrations-empty">
          No vendor plugins are registered in this process.
        </div>
      )}

      {data && data.vendors.length > 0 && (
        <div className="panel overflow-x-auto" data-testid="integrations-table">
          <table className="w-full min-w-[36rem] text-left text-xs">
            <thead className="border-b border-carbon-800 text-[11px] uppercase tracking-wider text-zinc-500">
              <tr>
                <th className="px-3 py-2 font-medium">Vendor</th>
                <th className="px-3 py-2 font-medium">Category</th>
                <th className="px-3 py-2 font-medium">Capabilities</th>
              </tr>
            </thead>
            <tbody>
              {data.vendors.map((v) => (
                <tr
                  key={v.vendor_id}
                  className="border-b border-carbon-900/80 last:border-0"
                  data-testid={`integration-row-${v.vendor_id}`}
                >
                  <td className="px-3 py-2 align-top">
                    <div className="font-medium text-zinc-100">{v.display_name}</div>
                    <code className="font-mono text-[11px] text-zinc-500">
                      {v.vendor_id}
                    </code>
                  </td>
                  <td className="px-3 py-2 align-top">
                    <StatusPill variant="neutral">{v.category}</StatusPill>
                  </td>
                  <td className="px-3 py-2 align-top text-zinc-300">
                    {v.capabilities.length === 0 ? (
                      <span className="text-zinc-500">—</span>
                    ) : (
                      <ul className="flex flex-wrap gap-1">
                        {v.capabilities.map((cap) => (
                          <li key={cap}>
                            <code className="rounded border border-carbon-800 bg-carbon-950/40 px-1.5 py-0.5 font-mono text-[10px] text-zinc-400">
                              {cap}
                            </code>
                          </li>
                        ))}
                      </ul>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="border-t border-carbon-800 px-3 py-2 text-[11px] text-zinc-600">
            {data.vendors.length} vendor{data.vendors.length === 1 ? "" : "s"} registered
          </p>
        </div>
      )}
    </section>
  );
}
