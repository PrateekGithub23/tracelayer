/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** "1" builds the static, browser-local public demo (no backend). */
  readonly VITE_DEMO?: string;
  /** Where the "Explore demo" link points from the real app's login page. */
  readonly VITE_DEMO_URL?: string;
  /** Public source repository, shown in the demo banner only when set. */
  readonly VITE_REPO_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
