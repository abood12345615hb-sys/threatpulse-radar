import { createFileRoute, Link } from "@tanstack/react-router";
import { BellRing, Layers, Radio, ShieldCheck } from "lucide-react";
import { ThreatScanner } from "@/components/ThreatScanner";
import { ThreatGlobe } from "@/components/ThreatGlobe";
import { useLanguage } from "@/contexts/LanguageContext";
import { Button } from "@/components/ui/button";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "ThreatPulse CTI — Scan URLs & IPs for Threats" },
      {
        name: "description",
        content:
          "Aggregate VirusTotal, URLhaus and AbuseIPDB verdicts in one sweep and receive instant WhatsApp alerts for critical detections.",
      },
      { property: "og:title", content: "ThreatPulse CTI — Scan URLs & IPs for Threats" },
      {
        property: "og:description",
        content: "One-sweep OSINT threat scanning with real-time WhatsApp security alerts.",
      },
    ],
  }),
  component: Index,
});

function Index() {
  const { t } = useLanguage();

  const features = [
    { icon: Layers, title: t("feature_1_t"), body: t("feature_1_d") },
    { icon: BellRing, title: t("feature_2_t"), body: t("feature_2_d") },
    { icon: Radio, title: t("feature_3_t"), body: t("feature_3_d") },
  ];

  return (
    <div className="mx-auto w-full max-w-[1200px] px-4 py-12 sm:px-6 sm:py-16">
      <section className="text-center">
        <span className="inline-flex items-center gap-2 rounded-full border border-border bg-card/60 px-3 py-1 text-xs text-muted-foreground">
          <span className="size-1.5 animate-blink rounded-full bg-emerald" />
          {t("hero_badge")}
        </span>
        <h1 className="mt-5 text-balance text-4xl font-bold tracking-tight sm:text-5xl lg:text-6xl">
          {t("hero_title")}
        </h1>
        <p className="mx-auto mt-4 max-w-2xl text-pretty text-sm text-muted-foreground sm:text-base">
          {t("hero_sub")}
        </p>
      </section>

      <section className="mt-10">
        <ThreatScanner />
      </section>

      <section className="glass-panel glow-ring mt-12 rounded-3xl p-6 sm:p-8 relative overflow-hidden border border-cyan-500/20 shadow-2xl">
        <ThreatGlobe />
      </section>

      <section className="mt-14 grid gap-4 md:grid-cols-3">
        {features.map((f) => (
          <div key={f.title} className="glass-panel rounded-2xl p-5 transition-transform hover:-translate-y-1">
            <span className="flex size-10 items-center justify-center rounded-xl bg-accent text-accent-foreground">
              <f.icon className="size-5" />
            </span>
            <h2 className="mt-4 text-base font-semibold">{f.title}</h2>
            <p className="mt-1.5 text-sm text-muted-foreground">{f.body}</p>
          </div>
        ))}
      </section>

      <section className="glass-panel glow-ring mt-14 flex flex-col items-center gap-4 rounded-2xl p-8 text-center">
        <ShieldCheck className="size-8 text-primary" />
        <p className="max-w-xl text-sm text-muted-foreground">{t("wa_value")}</p>
        <Button asChild size="lg">
          <Link to="/auth">{t("register")}</Link>
        </Button>
      </section>
    </div>
  );
}
