import { useLanguage } from "@/contexts/LanguageContext";
import { VerdictBadge } from "@/components/VerdictBadge";
import type { ProviderResult } from "@/types";

export function ProviderBadges({ providers }: { providers: ProviderResult[] }) {
  const { t } = useLanguage();

  return (
    <div className="grid gap-3 sm:grid-cols-3">
      {providers.map((p) => {
        const pct = Math.round((p.detections / p.total) * 100);
        return (
          <div key={p.name} className="glass-panel rounded-xl p-4">
            <div className="flex items-center justify-between gap-2">
              <span className="text-sm font-semibold">{p.name}</span>
              <VerdictBadge verdict={p.verdict} />
            </div>
            <p className="mt-3 font-mono text-2xl font-bold tabular-nums">
              {p.detections}
              <span className="text-sm text-muted-foreground">/{p.total}</span>
            </p>
            <p className="text-xs text-muted-foreground">{t("detections")}</p>
            <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-secondary">
              <div
                className="h-full rounded-full bg-primary transition-all duration-700"
                style={{ width: `${pct}%` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}
