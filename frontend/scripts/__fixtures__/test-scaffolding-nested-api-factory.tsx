vi.mock("../../api/auth", async () =>
  (await import("../../test/test-utils")).mockAuthApi()(),
);
