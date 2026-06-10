/**
 * Shared Vitest setup, wired in vite.config.ts (`test.setupFiles`):
 * registers jest-dom matchers on Vitest's expect and unmounts rendered
 * trees between tests (explicit cleanup because `test.globals` is off).
 */

import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

afterEach(() => {
  cleanup();
});
