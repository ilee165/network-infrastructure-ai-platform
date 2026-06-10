/// <reference types="vite/client" />

interface ImportMetaEnv {
  /**
   * LLM provider profile shown in the header badge (mirrors the backend's
   * NETOPS_LLM_PROFILE: local | anthropic | openai | azure). Display-only;
   * the backend is the source of truth for which profile actually runs.
   */
  readonly VITE_LLM_PROFILE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
