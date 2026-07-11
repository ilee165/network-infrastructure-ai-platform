/**
 * Wave-2 T11: DiscoveryRunStatus includes backend "partial" and DevicesPage
 * maps it to a defined StatusPill variant (production mapping, not a local copy).
 */
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { StatusPill } from "../components/StatusPill";
import { RUN_VARIANT } from "../pages/DevicesPage";

describe("DiscoveryRunStatus partial (H14)", () => {
  it("maps partial via production RUN_VARIANT to a defined StatusPill", () => {
    const variant = RUN_VARIANT.partial;
    expect(variant).toBe("warn");
    render(<StatusPill variant={variant}>partial</StatusPill>);
    expect(screen.getByText("partial")).toBeInTheDocument();
  });
});
