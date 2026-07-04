/**
 * Toaster tests (audit UI_UX #6): portal rendering, manual dismiss,
 * auto-expiry timers, and the aria-live announcement region.
 */

import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Toaster } from "../components/Toaster";
import { useUiStore } from "../stores/ui";

beforeEach(() => {
  useUiStore.setState({ toasts: [] });
});

afterEach(() => {
  vi.useRealTimers();
});

describe("Toaster", () => {
  it("renders nothing when there are no toasts", () => {
    render(<Toaster />);
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("renders pushed toasts into a document.body portal with an aria-live region", () => {
    render(<Toaster />);
    act(() => {
      useUiStore.getState().pushToast("success", "Discovery run finished.");
    });

    const region = screen.getByRole("status");
    expect(region).toHaveAttribute("aria-live", "polite");
    expect(region).toHaveTextContent("Discovery run finished.");
    expect(region.parentElement).toBe(document.body);
  });

  it("dismisses a toast when its dismiss button is clicked", () => {
    render(<Toaster />);
    act(() => {
      useUiStore.getState().pushToast("info", "Heads up.");
    });
    expect(screen.getByText("Heads up.")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Dismiss notification" }));

    expect(screen.queryByText("Heads up.")).not.toBeInTheDocument();
    expect(useUiStore.getState().toasts).toHaveLength(0);
  });

  it("auto-expires a success toast after ~5s", () => {
    vi.useFakeTimers();
    render(<Toaster />);
    act(() => {
      useUiStore.getState().pushToast("success", "Auto success");
    });
    expect(screen.getByText("Auto success")).toBeInTheDocument();

    act(() => {
      vi.advanceTimersByTime(4_999);
    });
    expect(screen.getByText("Auto success")).toBeInTheDocument();

    act(() => {
      vi.advanceTimersByTime(1);
    });
    expect(screen.queryByText("Auto success")).not.toBeInTheDocument();
    expect(useUiStore.getState().toasts).toHaveLength(0);
  });

  it("gives an error toast a longer (~8s) auto-expiry than success/info", () => {
    vi.useFakeTimers();
    render(<Toaster />);
    act(() => {
      useUiStore.getState().pushToast("error", "Auto error");
    });

    act(() => {
      vi.advanceTimersByTime(5_000);
    });
    expect(screen.getByText("Auto error")).toBeInTheDocument();

    act(() => {
      vi.advanceTimersByTime(3_000);
    });
    expect(screen.queryByText("Auto error")).not.toBeInTheDocument();
  });

  it("cleans up timers on unmount without throwing", () => {
    vi.useFakeTimers();
    const { unmount } = render(<Toaster />);
    act(() => {
      useUiStore.getState().pushToast("info", "Will unmount");
    });
    unmount();
    expect(() => vi.advanceTimersByTime(10_000)).not.toThrow();
  });
});
