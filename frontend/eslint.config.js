import js from "@eslint/js";
import jsxA11y from "eslint-plugin-jsx-a11y";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import globals from "globals";
import tseslint from "typescript-eslint";

/**
 * Flat ESLint config (D16): typescript-eslint recommended + react-hooks.
 * "No `any` in committed code" (ADR-0012) is enforced as an error.
 *
 * jsx-a11y's recommended ruleset is scoped to `.tsx` files only (audit W4 UI_UX
 * #5a) and is blocking (error) — a11y regressions fail the lint gate the same
 * as a type error.
 */
export default tseslint.config(
  { ignores: ["dist", "coverage", "node_modules"] },
  {
    files: ["**/*.{ts,tsx}"],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2022,
      globals: { ...globals.browser },
    },
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],
      "@typescript-eslint/no-explicit-any": "error",
    },
  },
  {
    files: ["**/*.tsx"],
    extends: [jsxA11y.flatConfigs.recommended],
  },
);
