/**
 * Tests for the toast channel on the `ui.ts` store (audit UI_UX #6).
 *
 * The store only manages the toast array — auto-dismiss timers live in the
 * `Toaster` component, so these tests exercise `pushToast`/`dismissToast` in
 * isolation with no fake timers required.
 */

import { beforeEach, describe, expect, it } from "vitest";
import { useUiStore } from "../stores/ui";

beforeEach(() => {
  useUiStore.setState({ toasts: [] });
});

describe("ui store — toasts", () => {
  it("starts with an empty toast stack", () => {
    expect(useUiStore.getState().toasts).toEqual([]);
  });

  it("pushToast appends a toast with the given kind and message", () => {
    useUiStore.getState().pushToast("success", "Discovery run finished.");
    expect(useUiStore.getState().toasts).toHaveLength(1);
    expect(useUiStore.getState().toasts[0]).toMatchObject({
      kind: "success",
      message: "Discovery run finished.",
    });
  });

  it("pushToast returns the generated id, and does not use Date.now-based ids", () => {
    const id = useUiStore.getState().pushToast("info", "hello");
    expect(useUiStore.getState().toasts[0]?.id).toBe(id);
    expect(id).not.toMatch(/^\d+$/); // not a bare timestamp
  });

  it("generates unique, monotonically distinct ids for toasts pushed back-to-back", () => {
    const id1 = useUiStore.getState().pushToast("info", "one");
    const id2 = useUiStore.getState().pushToast("info", "two");
    const id3 = useUiStore.getState().pushToast("error", "three");
    expect(new Set([id1, id2, id3]).size).toBe(3);
  });

  it("preserves push order in the stack", () => {
    useUiStore.getState().pushToast("info", "first");
    useUiStore.getState().pushToast("error", "second");
    const messages = useUiStore.getState().toasts.map((t) => t.message);
    expect(messages).toEqual(["first", "second"]);
  });

  it("dismissToast removes only the matching toast", () => {
    const id1 = useUiStore.getState().pushToast("info", "keep");
    const id2 = useUiStore.getState().pushToast("error", "remove");
    useUiStore.getState().dismissToast(id2);
    const remaining = useUiStore.getState().toasts;
    expect(remaining).toHaveLength(1);
    expect(remaining[0]?.id).toBe(id1);
  });

  it("dismissToast is a no-op for an unknown id", () => {
    useUiStore.getState().pushToast("info", "keep");
    expect(() => useUiStore.getState().dismissToast("does-not-exist")).not.toThrow();
    expect(useUiStore.getState().toasts).toHaveLength(1);
  });
});
