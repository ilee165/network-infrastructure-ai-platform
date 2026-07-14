import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { DataTable } from "../components/DataTable";
import { EmptyState } from "../components/EmptyState";
import { Modal } from "../components/Modal";
import { messageFor } from "../components/ErrorBanner";

describe("platform primitives", () => {
  it("renders a labelled modal with the existing shell", () => {
    render(<Modal aria-label="Edit device">body</Modal>);
    expect(screen.getByRole("dialog", { name: "Edit device" })).toHaveClass("fixed", "inset-0");
  });

  it("renders the common empty-state shape without a milestone", () => {
    render(<EmptyState title="No devices" description="Discover a device to begin." data-testid="empty" />);
    expect(screen.getByTestId("empty")).toHaveTextContent("No devices");
    expect(screen.queryByText(/Populated in/)).not.toBeInTheDocument();
  });

  it("exposes the shared unknown-error formatter", () => {
    expect(messageFor(new Error("offline"))).toBe("offline");
  });

  it("wires table headers, loading, empty, rows, and pagination", () => {
    const onNext = vi.fn();
    const { rerender } = render(
      <DataTable headers={["Name"]} loading loadingLabel="Loading devices…">
        <tr><td>ignored</td></tr>
      </DataTable>,
    );
    expect(screen.getByRole("status")).toHaveTextContent("Loading devices…");
    rerender(<DataTable headers={["Name"]} empty={<p>No devices</p>}><></></DataTable>);
    expect(screen.getByText("No devices")).toBeInTheDocument();
    rerender(
      <DataTable headers={["Name"]} pagination={<button onClick={onNext}>Next</button>}>
        <tr><td>router-1</td></tr>
      </DataTable>,
    );
    expect(screen.getByRole("columnheader", { name: "Name" })).toBeInTheDocument();
    expect(screen.getByText("router-1")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Next" })).toBeInTheDocument();
  });
});
