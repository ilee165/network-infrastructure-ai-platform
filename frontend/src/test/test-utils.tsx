import {
  QueryClient,
  QueryClientProvider,
  type QueryClientConfig,
} from "@tanstack/react-query";
import {
  render,
  renderHook,
  type RenderHookOptions,
  type RenderHookResult,
  type RenderOptions,
  type RenderResult,
} from "@testing-library/react";
import type { ReactElement, ReactNode } from "react";
import { vi } from "vitest";

type MockOverrides = () => Record<string, unknown>;

function actualSpreadFactory<T extends object>(modulePath: string, overrides: MockOverrides) {
  return async (): Promise<T> => ({
    ...(await vi.importActual<T>(modulePath)),
    ...overrides(),
  });
}

export function mockAuthApi(overrides: MockOverrides = () => ({})) {
  return actualSpreadFactory<typeof import("../api/auth")>("../api/auth", overrides);
}

export function mockChangesApi(overrides: MockOverrides = () => ({})) {
  return actualSpreadFactory<typeof import("../api/changes")>("../api/changes", overrides);
}

export function mockCredentialsApi(overrides: MockOverrides = () => ({})) {
  return actualSpreadFactory<typeof import("../api/credentials")>("../api/credentials", overrides);
}

export function mockIntegrationsApi(overrides: MockOverrides = () => ({})) {
  return actualSpreadFactory<typeof import("../api/integrations")>("../api/integrations", overrides);
}

export function mockAgentsApi(overrides: MockOverrides = () => ({})) {
  return actualSpreadFactory<typeof import("../api/agents")>("../api/agents", overrides);
}

const DEFAULT_QUERY_CLIENT_CONFIG: QueryClientConfig = {
  defaultOptions: {
    queries: { retry: false },
    mutations: { retry: false },
  },
};

function createQueryClient(config: QueryClientConfig = DEFAULT_QUERY_CLIENT_CONFIG): QueryClient {
  return new QueryClient(config);
}

function queryClientWrapper(queryClient: QueryClient) {
  return function QueryClientWrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
  };
}

export function renderWithQueryClient(
  ui: ReactElement,
  options: RenderOptions & { queryClientConfig?: QueryClientConfig } = {},
): RenderResult & { queryClient: QueryClient } {
  const { queryClientConfig, ...renderOptions } = options;
  const queryClient = createQueryClient(queryClientConfig);
  const result = render(ui, {
    wrapper: queryClientWrapper(queryClient),
    ...renderOptions,
  });
  return { ...result, queryClient };
}

export function renderHookWithQueryClient<Result, Props>(
  callback: (initialProps: Props) => Result,
  options: RenderHookOptions<Props> & { queryClientConfig?: QueryClientConfig } = {},
): RenderHookResult<Result, Props> & { queryClient: QueryClient } {
  const { queryClientConfig, ...renderOptions } = options;
  const queryClient = createQueryClient(queryClientConfig);
  const result = renderHook(callback, {
    wrapper: queryClientWrapper(queryClient),
    ...renderOptions,
  });
  return { ...result, queryClient };
}
