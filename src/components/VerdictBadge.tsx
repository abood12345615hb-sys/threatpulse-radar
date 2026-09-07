import { useLanguage } from "@/contexts/LanguageContext";
import type { Verdict } from "@/types";
import { cn } from "@/lib/utils";

const styles: Record<Verdict, string> = {
  clean: "border-emerald/40 bg-emerald/10 text-emerald",
  suspicious: "border-amber/40 bg-amber/10 text-amber",
  malicious: "border-crimson/40 bg-crimson/10 text-crimson",
};

export function VerdictBadge({ verdict, className }: { verdict: Verdict; className?: string }) {
  const { t } = useLanguage();
  const label =
    verdict === "clean"
      ? t("verdict_clean")
      : verdict === "suspicious"
        ? t("verdict_suspicious")
        : t("verdict_malicious");

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold",
        styles[verdict],
        className,
      )}
    >
      <span className="size-1.5 rounded-full bg-current" />
      {label}
    </span>
  );
}
