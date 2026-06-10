/**
 * Devices: the normalized multi-vendor inventory view.
 *
 * Populated in M1 by the discovery engine (SSH/SNMP via the Cisco IOS,
 * Cisco IOS-XE, and Arista EOS plugins) — until then this is an honest
 * empty state, never fake rows.
 */

import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";

export function DevicesPage() {
  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Devices"
        description="Normalized multi-vendor inventory: devices, interfaces, routes, and neighbors."
        actions={
          <button type="button" className="btn" disabled title="Discovery engine lands in M1">
            Run discovery
          </button>
        }
      />
      <EmptyState
        title="No devices discovered yet"
        description="The discovery engine (SSH/SNMP through the Cisco IOS, Cisco IOS-XE, and Arista EOS plugins) populates this inventory from seed devices, with every raw command output preserved for audit."
        milestone="M1"
      />
    </div>
  );
}
