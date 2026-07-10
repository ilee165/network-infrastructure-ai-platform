/**
 * Integrations matrix API — registered vendor plugins + capabilities.
 *
 * Mirrors ``GET /api/v1/integrations`` (admin). Inventory only; no live
 * device reachability.
 */

import { apiFetch } from "./client";

export type VendorCategory =
  | "network"
  | "ddi"
  | "virt"
  | "adc"
  | "cloud"
  | "other";

export interface IntegrationVendor {
  vendor_id: string;
  display_name: string;
  capabilities: string[];
  category: VendorCategory;
}

export interface IntegrationsReport {
  vendors: IntegrationVendor[];
}

/** ``GET /integrations`` — registered plugins for Settings → Integrations. */
export function listIntegrations(): Promise<IntegrationsReport> {
  return apiFetch<IntegrationsReport>("/integrations");
}
