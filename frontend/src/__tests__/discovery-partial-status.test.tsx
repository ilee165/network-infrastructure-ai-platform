/**
 * Wave-2 T11: DiscoveryRunStatus includes backend "partial".
 */
import { describe, expect, it } from "vitest";
import type { DiscoveryRunStatus } from "../api/discovery";
import { StatusPill, type StatusPillVariant } from "../components/StatusPill";
import { render, screen } from "@testing-library/react";

const RUN_VARIANT: Record<DiscoveryRunStatus, StatusPillVariant> = {
  pending: "warn",
  running: "info",
  succeeded: "ok",
  failed: "error",
  partial: "warn",
};

describe("DiscoveryRunStatus partial (H14)", () => {
  it("maps partial to a defined StatusPill variant", () => {
    const variant = RUN_VARIANT["partial"];
    expect(variant).toBeDefined();
    render(<StatusPill variant={variant}>partial</StatusPill>);
    expect(screen.getByText("partial")).toBeInTheDocument();
  });
});
