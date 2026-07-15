import { useThemeStore } from "../../stores/theme";
import type { Theme } from "../../stores/theme";

const THEME_OPTIONS: { value: Theme; label: string }[] = [
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
  { value: "system", label: "System" },
];

export function SettingsAppearanceSection() {
  const theme = useThemeStore((state) => state.theme);
  const setTheme = useThemeStore((state) => state.setTheme);

  return (
    <section
      aria-label="Appearance"
      data-testid="settings-appearance"
      className="panel p-4 flex flex-col gap-4"
    >
      <h3 className="font-mono text-xs uppercase tracking-widest text-zinc-500">
        Appearance
      </h3>
      <div className="flex flex-col gap-2">
        <p className="text-xs text-zinc-400">Theme</p>
        <div className="flex gap-2">
          {THEME_OPTIONS.map(({ value, label }) => (
            <button
              key={value}
              type="button"
              onClick={() => setTheme(value)}
              className={[
                "rounded border px-3 py-1.5 text-xs font-medium transition-colors",
                theme === value
                  ? "border-accent bg-accent/10 text-accent"
                  : "border-carbon-700 text-zinc-400 hover:border-carbon-600 hover:text-zinc-200",
              ].join(" ")}
            >
              {label}
            </button>
          ))}
        </div>
      </div>
    </section>
  );
}
