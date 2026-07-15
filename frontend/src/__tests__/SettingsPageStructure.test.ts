import { describe, expect, it } from "vitest";

import * as compatibilityFacade from "../pages/SettingsPage";
import * as settings from "../pages/settings";

const PUBLIC_SETTINGS_COMPONENTS = [
  "SettingsPage",
  "SettingsAppearanceSection",
  "SettingsAgentsSection",
  "SettingsAccountSection",
  "SettingsCredentialsSection",
  "SettingsLlmSection",
  "SettingsAccessSection",
  "SettingsIntegrationsSection",
  "SettingsPlatformSection",
] as const;

describe("settings module boundary", () => {
  it.each(PUBLIC_SETTINGS_COMPONENTS)(
    "exposes %s through the compatibility facade and settings barrel",
    (componentName) => {
      expect(typeof compatibilityFacade[componentName]).toBe("function");
      expect(settings[componentName]).toBe(compatibilityFacade[componentName]);
    },
  );
});
