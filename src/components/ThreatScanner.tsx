import { useNavigate } from "@tanstack/react-router";
import { Lock, Radar, Search } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useAuth } from "@/contexts/AuthContext";
import { useLanguage } from "@/contexts/LanguageContext";
import { threatService } from "@/services/threatService";

type Phase = "idle" | "scanning" | "gated";

export function ThreatScanner() {
  const { t } = useLanguage();
  const { user } = useAuth();
  const navigate = useNavigate();
  const [indicator, setIndicator] = useState("");
  const [phase, setPhase] = useState<Phase>("idle");

  const run = async () => {
    const value = indicator.trim();
    if (value.length < 4) {
      toast.error(t("scan_hint"));
      return;
    }
    setPhase("scanning");
    if (user) {
      navigate({ to: "/dashboard", search: { q: value } });
      return;
    }
    await threatService.scan(value);
    setPhase("gated");
  };

  return (
    <div className="glass-panel glow-ring relative overflow-hidden rounded-2xl p-5 sm:p-6">
      <div className="flex flex-col gap-3 sm:flex-row">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute top-1/2 start-3 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={indicator}
            onChange={(e) => setIndicator(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && run()}
            placeholder={t("scan_placeholder")}
            dir="ltr"
            className="h-12 ps-9 font-mono text-sm"
            aria-label={t("indicator")}
          />
        </div>
        <Button size="lg" className="h-12 shrink-0" onClick={run} disabled={phase === "scanning"}>
          <Radar className={phase === "scanning" ? "size-4 animate-radar" : "size-4"} />
          {phase === "scanning" ? t("scanning") : t("scan_cta")}
        </Button>
      </div>
      <p className="mt-2 text-xs text-muted-foreground">{t("scan_hint")}</p>

      {phase === "scanning" && (
        <div className="relative mt-6 flex h-48 items-center justify-center overflow-hidden rounded-xl border border-border bg-background/60">
          <div className="absolute size-40 rounded-full border border-primary/30" />
          <div className="absolute size-28 rounded-full border border-primary/25" />
          <div className="absolute size-14 rounded-full border border-primary/20" />
          <div className="absolute size-40 animate-pulse-ring rounded-full border border-primary/40" />
          <div
            className="absolute size-40 animate-radar rounded-full"
            style={{
              background:
                "conic-gradient(from 0deg, color-mix(in oklab, var(--primary) 45%, transparent), transparent 38%)",
              maskImage: "radial-gradient(circle, black 65%, transparent 70%)",
            }}
          />
          <p className="relative font-mono text-xs uppercase tracking-[0.25em] text-primary">
            {t("scanning")}
          </p>
        </div>
      )}

      {phase === "gated" && (
        <div className="mt-6 rounded-xl border border-primary/40 bg-accent/40 p-5 text-center">
          <Lock className="mx-auto size-6 text-primary" />
          <p className="mt-3 text-sm font-medium">{t("scan_done")}</p>
          <Button
            className="mt-4"
            onClick={() => navigate({ to: "/auth", search: { q: indicator.trim() } })}
          >
            {t("reveal_cta")}
          </Button>
        </div>
      )}
    </div>
  );
}
