vi.mock("../api/auth", () => ({}));

// Nearby factory-shaped text must not satisfy the vi.mock callback contract.
mockAuthApi(() => ({}));
