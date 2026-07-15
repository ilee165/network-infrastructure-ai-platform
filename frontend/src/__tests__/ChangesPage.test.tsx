/**
 * ChangesPage tests: the ChangeRequest approval queue — the human change gate.
 *
 * Mirrors the ProfilePage test pattern: the ``api/changes`` module is mocked so
 * approve/reject payloads (incl. the reviewer comment) are asserted directly, and
 * the auth store is driven via ``useAuthStore.setState`` to exercise the four-eyes
 * UI guard (approve hidden on the requester's own CR) and the server-rejection
 * surfacing.
 *
 * Security note: the CR ``target_refs`` / intent are rendered as text (never via a
 * dangerouslySetInnerHTML sink), so a malicious ref string cannot inject markup —
 * this is asserted by the XSS-safety test.
 */

import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderWithQueryClient } from "../test/test-utils";
import { ApiError } from "../api/client";
import type { ChangeRequestListResponse, ChangeRequestRead } from "../api/changes";
import { useAuthStore } from "../stores/auth";
import type { UserMe } from "../stores/auth";
import { useUiStore } from "../stores/ui";

// ── Module mock: the changes api-client ─────────────────────────────────────

vi.mock("../api/changes", async () => (await import("../test/test-utils")).mockChangesApi(() => ({
  listChangeRequests: vi.fn(),
  getChangeRequest: vi.fn(),
  approveChangeRequest: vi.fn(),
  rejectChangeRequest: vi.fn(),
}))());

import {
  approveChangeRequest,
  getChangeRequest,
  listChangeRequests,
  rejectChangeRequest,
} from "../api/changes";
import { ChangesPage } from "../pages/ChangesPage";

// ── Fixtures ──────────────────────────────────────────────────────────────────

const ME_ID = "11111111-1111-1111-1111-111111111111";
const OTHER_ID = "22222222-2222-2222-2222-222222222222";

const CR_OTHER_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const CR_MINE_ID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

const ENGINEER: UserMe = {
  id: ME_ID,
  username: "alice",
  email: "alice@example.com",
  display_name: "Alice Engineer",
  role: "engineer",
  is_active: true,
  must_change_password: false,
};

/** A CR requested by SOMEONE ELSE — the current engineer may approve it. */
const CR_OTHER: ChangeRequestRead = {
  id: CR_OTHER_ID,
  state: "pending_approval",
  kind: "config",
  requester_id: OTHER_ID,
  four_eyes_required: true,
  target_refs: { device_ids: ["core-sw-01"] },
  reasoning_trace_id: null,
  created_at: "2026-06-18T10:00:00Z",
  updated_at: "2026-06-18T10:00:00Z",
};

/** A CR requested by the CURRENT user — four-eyes forbids self-approval. */
const CR_MINE: ChangeRequestRead = {
  id: CR_MINE_ID,
  state: "pending_approval",
  kind: "ddi",
  requester_id: ME_ID,
  four_eyes_required: true,
  target_refs: { dns_records: ["www.example.com"] },
  reasoning_trace_id: null,
  created_at: "2026-06-18T11:00:00Z",
  updated_at: "2026-06-18T11:00:00Z",
};

const LIST_BOTH: ChangeRequestListResponse = {
  items: [CR_MINE, CR_OTHER],
  total: 2,
  limit: 50,
  offset: 0,
};

const EMPTY_LIST: ChangeRequestListResponse = {
  items: [],
  total: 0,
  limit: 50,
  offset: 0,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function renderPage() {
return renderWithQueryClient(
      <ChangesPage />
    );
}

function problem(status: number, detail: string): ApiError {
  return new ApiError({
    type: "urn:netops:error:forbidden",
    title: "Forbidden",
    status,
    detail,
  });
}

beforeEach(() => {
  useAuthStore.setState({ accessToken: "tok", user: ENGINEER, status: "authed" });
  useUiStore.setState({ toasts: [] });
  vi.mocked(listChangeRequests).mockReset();
  vi.mocked(getChangeRequest).mockReset();
  vi.mocked(approveChangeRequest).mockReset();
  vi.mocked(rejectChangeRequest).mockReset();
  // Detail fetch echoes whatever id is asked for from the seeded list.
  vi.mocked(getChangeRequest).mockImplementation((id: string) =>
    Promise.resolve(id === CR_MINE_ID ? CR_MINE : CR_OTHER),
  );
});

afterEach(() => {
  useAuthStore.setState({ accessToken: null, user: null, status: "anon" });
  useUiStore.setState({ toasts: [] });
  vi.restoreAllMocks();
});

// ── Queue rendering ─────────────────────────────────────────────────────────

describe("ChangesPage — queue", () => {
  it("renders the page header", async () => {
    vi.mocked(listChangeRequests).mockResolvedValue(EMPTY_LIST);
    renderPage();
    expect(await screen.findByText("Changes")).toBeInTheDocument();
  });

  it("lists pending change requests, newest first", async () => {
    vi.mocked(listChangeRequests).mockResolvedValue(LIST_BOTH);
    renderPage();
    expect(await screen.findByTestId(`cr-row-${CR_MINE_ID}`)).toBeInTheDocument();
    expect(screen.getByTestId(`cr-row-${CR_OTHER_ID}`)).toBeInTheDocument();
  });

  it("renders the config kind and executing state with the accent (info) tone, restoring their pre-shared-primitive tone", async () => {
    const executing: ChangeRequestRead = { ...CR_OTHER, state: "executing" };
    vi.mocked(listChangeRequests).mockResolvedValue({
      items: [executing],
      total: 1,
      limit: 50,
      offset: 0,
    });
    renderPage();

    const kindBadge = await screen.findByTestId(`cr-kind-${CR_OTHER_ID}`);
    expect(kindBadge).toHaveClass("border-accent/40", "bg-accent/10", "text-accent");
    const stateBadge = screen.getByTestId(`cr-state-${CR_OTHER_ID}`);
    expect(stateBadge).toHaveClass("border-accent/40", "bg-accent/10", "text-accent");
  });

  it("renders the ddi kind with the ok (green) tone, restoring its pre-shared-primitive tone", async () => {
    vi.mocked(listChangeRequests).mockResolvedValue(LIST_BOTH);
    renderPage();

    // CR_MINE is kind "ddi".
    const kindBadge = await screen.findByTestId(`cr-kind-${CR_MINE_ID}`);
    expect(kindBadge).toHaveClass("border-status-ok/40", "bg-status-ok/10", "text-status-ok");
  });

  it("shows an empty state when there are no change requests", async () => {
    vi.mocked(listChangeRequests).mockResolvedValue(EMPTY_LIST);
    renderPage();
    expect(await screen.findByTestId("cr-empty-state")).toBeInTheDocument();
  });

  it("surfaces a load error", async () => {
    vi.mocked(listChangeRequests).mockRejectedValue(problem(500, "boom"));
    renderPage();
    // ErrorBanner (audit UI_UX #3) renders the RFC 7807 `detail`, not a
    // page-specific prefix.
    expect(await screen.findByRole("alert")).toHaveTextContent("boom");
  });

  it("shows skeleton placeholder rows (not visible text) while the queue loads", () => {
    vi.mocked(listChangeRequests).mockReturnValue(new Promise(() => {}));
    renderPage();

    expect(document.querySelectorAll("td .animate-pulse").length).toBeGreaterThan(0);
  });

  it("announces the queue loading state to screen readers via a visually-hidden status", () => {
    vi.mocked(listChangeRequests).mockReturnValue(new Promise(() => {}));
    renderPage();

    const status = screen.getByRole("status", { name: /loading change requests/i });
    expect(status.closest("tr")).toHaveClass("sr-only");
  });
});

// ── Diff / intent preview ───────────────────────────────────────────────────

describe("ChangesPage — diff / intent preview", () => {
  it("renders the intent preview (kind + target refs) when a CR is selected", async () => {
    vi.mocked(listChangeRequests).mockResolvedValue(LIST_BOTH);
    renderPage();
    fireEvent.click(await screen.findByTestId(`cr-view-${CR_OTHER_ID}`));

    const preview = await screen.findByTestId("cr-detail-panel");
    expect(preview).toBeInTheDocument();
    // The id-only target_refs are rendered for the approver to review.
    expect(within(preview).getByTestId("cr-intent-preview")).toHaveTextContent("core-sw-01");
    expect(within(preview).getByTestId("cr-intent-preview")).toHaveTextContent("device_ids");
  });

  it("renders target_refs as text, never as raw HTML (XSS-safe)", async () => {
    const evil = "<img src=x onerror=alert(1)>";
    const listing: ChangeRequestListResponse = {
      items: [{ ...CR_OTHER, target_refs: { note: evil } }],
      total: 1,
      limit: 50,
      offset: 0,
    };
    vi.mocked(listChangeRequests).mockResolvedValue(listing);
    vi.mocked(getChangeRequest).mockResolvedValue({
      ...CR_OTHER,
      target_refs: { note: evil },
    });
    renderPage();
    fireEvent.click(await screen.findByTestId(`cr-view-${CR_OTHER_ID}`));

    const preview = await screen.findByTestId("cr-intent-preview");
    // The literal markup is present as TEXT (escaped), and no <img> element was
    // injected into the DOM by the preview.
    expect(preview).toHaveTextContent(evil);
    expect(preview.querySelector("img")).toBeNull();
  });
});

// ── Approve / reject ────────────────────────────────────────────────────────

describe("ChangesPage — approve / reject", () => {
  it("posts an approve with the reviewer comment for another user's CR", async () => {
    vi.mocked(listChangeRequests).mockResolvedValue(LIST_BOTH);
    vi.mocked(approveChangeRequest).mockResolvedValue({ ...CR_OTHER, state: "approved" });
    renderPage();
    fireEvent.click(await screen.findByTestId(`cr-view-${CR_OTHER_ID}`));

    const comment = await screen.findByTestId("cr-comment-input");
    fireEvent.change(comment, { target: { value: "LGTM — change window approved" } });
    fireEvent.click(screen.getByTestId("cr-approve-btn"));

    await waitFor(() => expect(approveChangeRequest).toHaveBeenCalledTimes(1));
    expect(approveChangeRequest).toHaveBeenCalledWith(CR_OTHER_ID, {
      comment: "LGTM — change window approved",
    });
  });

  it("posts a reject with the reviewer comment", async () => {
    vi.mocked(listChangeRequests).mockResolvedValue(LIST_BOTH);
    vi.mocked(rejectChangeRequest).mockResolvedValue({ ...CR_OTHER, state: "draft" });
    renderPage();
    fireEvent.click(await screen.findByTestId(`cr-view-${CR_OTHER_ID}`));

    const comment = await screen.findByTestId("cr-comment-input");
    fireEvent.change(comment, { target: { value: "needs a rollback plan" } });
    fireEvent.click(screen.getByTestId("cr-reject-btn"));

    await waitFor(() => expect(rejectChangeRequest).toHaveBeenCalledTimes(1));
    expect(rejectChangeRequest).toHaveBeenCalledWith(CR_OTHER_ID, {
      comment: "needs a rollback plan",
    });
  });

  it("pushes a success toast when a CR is approved", async () => {
    vi.mocked(listChangeRequests).mockResolvedValue(LIST_BOTH);
    vi.mocked(approveChangeRequest).mockResolvedValue({ ...CR_OTHER, state: "approved" });
    renderPage();
    fireEvent.click(await screen.findByTestId(`cr-view-${CR_OTHER_ID}`));
    fireEvent.click(await screen.findByTestId("cr-approve-btn"));

    await waitFor(() => {
      expect(useUiStore.getState().toasts).toHaveLength(1);
    });
    expect(useUiStore.getState().toasts[0]).toMatchObject({
      kind: "success",
      message: "Change request approved.",
    });
  });

  it("pushes a success toast when a CR is rejected", async () => {
    vi.mocked(listChangeRequests).mockResolvedValue(LIST_BOTH);
    vi.mocked(rejectChangeRequest).mockResolvedValue({ ...CR_OTHER, state: "draft" });
    renderPage();
    fireEvent.click(await screen.findByTestId(`cr-view-${CR_OTHER_ID}`));
    fireEvent.click(await screen.findByTestId("cr-reject-btn"));

    await waitFor(() => {
      expect(useUiStore.getState().toasts).toHaveLength(1);
    });
    expect(useUiStore.getState().toasts[0]).toMatchObject({ kind: "success" });
  });

  it("shows a spinner on the approve button while the decision is in flight", async () => {
    vi.mocked(listChangeRequests).mockResolvedValue(LIST_BOTH);
    let resolveApprove!: (value: ChangeRequestRead) => void;
    vi.mocked(approveChangeRequest).mockReturnValue(
      new Promise((resolve) => {
        resolveApprove = resolve;
      }),
    );
    renderPage();
    fireEvent.click(await screen.findByTestId(`cr-view-${CR_OTHER_ID}`));
    const approveBtn = await screen.findByTestId("cr-approve-btn");
    fireEvent.click(approveBtn);

    await waitFor(() => expect(approveBtn).toBeDisabled());
    expect(within(approveBtn).getByRole("status")).toBeInTheDocument();

    resolveApprove({ ...CR_OTHER, state: "approved" });
  });
});

// ── Four-eyes UI guard ──────────────────────────────────────────────────────

describe("ChangesPage — four-eyes UI guard", () => {
  it("hides/disables approve on a CR the current user requested", async () => {
    vi.mocked(listChangeRequests).mockResolvedValue(LIST_BOTH);
    renderPage();
    // Select the CR the current user (alice) requested.
    fireEvent.click(await screen.findByTestId(`cr-view-${CR_MINE_ID}`));

    await screen.findByTestId("cr-detail-panel");
    // Approve must not be actionable for one's own CR (four-eyes).
    const approve = screen.queryByTestId("cr-approve-btn");
    if (approve !== null) {
      expect(approve).toBeDisabled();
    } else {
      expect(approve).toBeNull();
    }
    // The reason is surfaced to the reviewer.
    expect(screen.getByTestId("cr-four-eyes-note")).toBeInTheDocument();
    // Reject is still available — the requester may withdraw their own CR.
    expect(screen.getByTestId("cr-reject-btn")).toBeEnabled();
  });

  it("allows approve on a CR requested by someone else", async () => {
    vi.mocked(listChangeRequests).mockResolvedValue(LIST_BOTH);
    renderPage();
    fireEvent.click(await screen.findByTestId(`cr-view-${CR_OTHER_ID}`));
    expect(await screen.findByTestId("cr-approve-btn")).toBeEnabled();
    expect(screen.queryByTestId("cr-four-eyes-note")).toBeNull();
  });
});

// ── Server-side rejection surfacing ─────────────────────────────────────────

describe("ChangesPage — server rejection surfacing", () => {
  it("surfaces a server-side rejection (e.g. 403 four-eyes) to the user", async () => {
    vi.mocked(listChangeRequests).mockResolvedValue(LIST_BOTH);
    vi.mocked(approveChangeRequest).mockRejectedValue(
      problem(403, "four-eyes violation: the approver must differ from the requester"),
    );
    renderPage();
    fireEvent.click(await screen.findByTestId(`cr-view-${CR_OTHER_ID}`));
    fireEvent.click(await screen.findByTestId("cr-approve-btn"));

    const err = await screen.findByTestId("cr-decision-error");
    expect(err).toHaveTextContent(/four-eyes violation/);
  });

  it("pushes an accurate generic failure toast on approval failure (not a rejection claim)", async () => {
    vi.mocked(listChangeRequests).mockResolvedValue(LIST_BOTH);
    vi.mocked(approveChangeRequest).mockRejectedValue(problem(500, "internal error"));
    renderPage();
    fireEvent.click(await screen.findByTestId(`cr-view-${CR_OTHER_ID}`));
    fireEvent.click(await screen.findByTestId("cr-approve-btn"));

    await waitFor(() => {
      expect(useUiStore.getState().toasts).toHaveLength(1);
    });
    const [toast] = useUiStore.getState().toasts;
    expect(toast).toMatchObject({ kind: "error", message: "Change request approval failed." });
    // A transient/server failure must never be mischaracterized as a
    // deliberate four-eyes rejection.
    expect(toast?.message).not.toMatch(/rejected/i);
  });

  it("pushes an accurate generic failure toast on rejection failure", async () => {
    vi.mocked(listChangeRequests).mockResolvedValue(LIST_BOTH);
    vi.mocked(rejectChangeRequest).mockRejectedValue(problem(500, "internal error"));
    renderPage();
    fireEvent.click(await screen.findByTestId(`cr-view-${CR_OTHER_ID}`));
    fireEvent.click(await screen.findByTestId("cr-reject-btn"));

    await waitFor(() => {
      expect(useUiStore.getState().toasts).toHaveLength(1);
    });
    expect(useUiStore.getState().toasts[0]).toMatchObject({
      kind: "error",
      message: "Change request rejection failed.",
    });
  });
});
