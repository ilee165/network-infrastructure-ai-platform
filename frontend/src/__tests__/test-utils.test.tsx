import { screen } from "@testing-library/react";
import { useQueryClient } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

import { mockAuthApi, renderWithQueryClient } from "../test/test-utils";

describe("shared test utilities", () => {
  it("makes every unoverridden API function fail loudly", async () => {
    const factory = mockAuthApi(() => ({ login: vi.fn() }));
    const mocked = await factory();

    expect(() => mocked.getMe()).toThrow(
      "unstubbed API call: ../api/auth.getMe",
    );
  });

  it("merges caller query defaults without restoring retries", () => {
    const { queryClient } = renderWithQueryClient(<div />, {
      queryClientConfig: {
        defaultOptions: {
          queries: { staleTime: 1234 },
        },
      },
    });

    expect(queryClient.getDefaultOptions().queries).toMatchObject({
      retry: false,
      staleTime: 1234,
    });
    expect(queryClient.getDefaultOptions().mutations).toMatchObject({ retry: false });
  });

  it("composes a caller wrapper inside the required QueryClientProvider", () => {
    function OuterWrapper({ children }: { children: ReactNode }) {
      return <section data-testid="outer-wrapper">{children}</section>;
    }
    function QueryClientProbe() {
      const queryClient = useQueryClient();
      return <span data-testid="query-client-probe">{String(queryClient !== null)}</span>;
    }

    renderWithQueryClient(<QueryClientProbe />, { wrapper: OuterWrapper });

    expect(screen.getByTestId("outer-wrapper")).toContainElement(
      screen.getByTestId("query-client-probe"),
    );
  });
});
