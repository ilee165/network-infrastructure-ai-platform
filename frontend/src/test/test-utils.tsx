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
import type { JSXElementConstructor, ReactElement, ReactNode } from "react";
import { vi } from "vitest";

type MockOverrides = () => Record<string, unknown>;

function actualSpreadFactory<T extends object>(modulePath: string, overrides: MockOverrides) {
  return async (): Promise<T> => {
    const actual = await vi.importActual<T>(modulePath);
    const loudDefaults = Object.fromEntries(
      Object.entries(actual).map(([name, value]) => [
        name,
        typeof value === "function"
          ? vi.fn(() => {
              throw new Error(`unstubbed API call: ${modulePath}.${name}`);
            })
          : value,
      ]),
    );
    return { ...loudDefaults, ...overrides() } as T;
  };
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

function createQueryClient(config: QueryClientConfig = {}): QueryClient {
  return new QueryClient({
    ...DEFAULT_QUERY_CLIENT_CONFIG,
    ...config,
    defaultOptions: {
      ...DEFAULT_QUERY_CLIENT_CONFIG.defaultOptions,
      ...config.defaultOptions,
      queries: {
        ...DEFAULT_QUERY_CLIENT_CONFIG.defaultOptions?.queries,
        ...config.defaultOptions?.queries,
      },
      mutations: {
        ...DEFAULT_QUERY_CLIENT_CONFIG.defaultOptions?.mutations,
        ...config.defaultOptions?.mutations,
      },
    },
  });
}

type WrapperComponent = JSXElementConstructor<{ children: ReactNode }>;

function queryClientWrapper(queryClient: QueryClient, OuterWrapper?: WrapperComponent) {
  return function QueryClientWrapper({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>
        {OuterWrapper ? <OuterWrapper>{children}</OuterWrapper> : children}
      </QueryClientProvider>
    );
  };
}

export function renderWithQueryClient(
  ui: ReactElement,
  options: RenderOptions & { queryClientConfig?: QueryClientConfig } = {},
): RenderResult & { queryClient: QueryClient } {
  const { queryClientConfig, wrapper, ...renderOptions } = options;
  const queryClient = createQueryClient(queryClientConfig);
  const result = render(ui, {
    ...renderOptions,
    wrapper: queryClientWrapper(queryClient, wrapper),
  });
  return { ...result, queryClient };
}

export function renderHookWithQueryClient<Result, Props>(
  callback: (initialProps: Props) => Result,
  options: RenderHookOptions<Props> & { queryClientConfig?: QueryClientConfig } = {},
): RenderHookResult<Result, Props> & { queryClient: QueryClient } {
  const { queryClientConfig, wrapper, ...renderOptions } = options;
  const queryClient = createQueryClient(queryClientConfig);
  const result = renderHook(callback, {
    ...renderOptions,
    wrapper: queryClientWrapper(queryClient, wrapper),
  });
  return { ...result, queryClient };
}
