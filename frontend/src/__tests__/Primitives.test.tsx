import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { DataTable } from "../components/DataTable";
import { EmptyState } from "../components/EmptyState";
import { Modal } from "../components/Modal";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { messageFor } from "../components/ErrorBanner";
import { ApiError } from "../api/client";

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

  it("keeps non-API internals out of the shared action-error formatter", () => {
    expect(messageFor(new Error("missing credential id"))).toBe(
      "Something went wrong. Please try again.",
    );
  });

  it("wires confirm-dialog actions, error state, and pending state", () => {
    const onConfirm = vi.fn();
    const onCancel = vi.fn();
    const { rerender } = render(
      <ConfirmDialog
        message="Delete router-1?"
        error="Delete failed"
        confirmLabel="Delete"
        onConfirm={onConfirm}
        onCancel={onCancel}
      />,
    );

    expect(screen.getByRole("dialog", { name: "Confirm action" })).toHaveTextContent(
      "Delete router-1?",
    );
    expect(screen.getByRole("alert")).toHaveTextContent("Delete failed");
    fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onConfirm).toHaveBeenCalledOnce();
    expect(onCancel).toHaveBeenCalledOnce();

    rerender(
      <ConfirmDialog
        message="Delete router-1?"
        isPending
        pendingLabel="Deleting…"
        onConfirm={onConfirm}
        onCancel={onCancel}
      />,
    );
    expect(screen.getByRole("button", { name: "Deleting…" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Cancel" })).toBeDisabled();
  });

  it("supports explicit legacy message modes where the old page exposed them", () => {
    const apiError = new ApiError({
      type: "urn:netops:error:not-found",
      title: "Not Found",
      status: 404,
      detail: "device has no snapshots",
    });

    expect(messageFor(apiError)).toBe("device has no snapshots");
    expect(messageFor(apiError, { includeProblemTitle: true })).toBe(
      "Not Found: device has no snapshots",
    );
    expect(messageFor(new Error("offline"), { exposeErrorMessage: true })).toBe("offline");
  });

  it("wires table headers, loading, empty, rows, and pagination", () => {
    const onNext = vi.fn();
    const { rerender } = render(
      <DataTable headers={["Name"]} loading loadingLabel="Loading devices…">
        <tr><td>ignored</td></tr>
      </DataTable>,
    );
    expect(screen.getByRole("status")).toHaveTextContent("Loading devices…");
    rerender(<DataTable headers={["Name"]} isEmpty empty={<p>No devices</p>}><></></DataTable>);
    expect(screen.getByText("No devices")).toBeInTheDocument();
    rerender(
      <DataTable headers={["Name"]} isEmpty={false} empty={<p>No devices</p>}>
        <tr><td>router-1</td></tr>
      </DataTable>,
    );
    expect(screen.queryByText("No devices")).not.toBeInTheDocument();
    expect(screen.getByText("router-1")).toBeInTheDocument();
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
