import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Copy, Download, Lock, Search, AlertTriangle, Info, Shield, Image as ImageIcon, Activity, Globe } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { ProviderBadges } from "@/components/ProviderBadges";
import { RiskGauge } from "@/components/RiskGauge";
import { ThreatGraph } from "@/components/ThreatGraph";
import { ThreatGlobe } from "@/components/ThreatGlobe";
import { VerdictBadge } from "@/components/VerdictBadge";
import { useAuth } from "@/contexts/AuthContext";
import { useLanguage } from "@/contexts/LanguageContext";
import { buildFallbackScan, threatService } from "@/services/threatService";
import type { ScanResult } from "@/types";

const COUNTRY_COORDS: Record<string, { lat: number; lon: number }> = {
  SA: { lat: 24.7, lon: 46.7 },
  US: { lat: 39.0, lon: -77.5 },
  DE: { lat: 50.1, lon: 8.7 },
  RU: { lat: 55.7, lon: 37.6 },
  NL: { lat: 52.4, lon: 4.9 },
  CN: { lat: 31.2, lon: 121.5 },
  GB: { lat: 51.5, lon: -0.12 },
  FR: { lat: 48.8, lon: 2.35 },
  AE: { lat: 25.2, lon: 55.3 },
  YE: { lat: 15.3, lon: 44.2 },
  JP: { lat: 35.6, lon: 139.6 },
  BR: { lat: -15.8, lon: -47.9 },
};

export const Route = createFileRoute("/dashboard")({
  validateSearch: (search: Record<string, unknown>): { q?: string } => {
    const q = search["q"];
    return typeof q === "string" ? { q } : {};
  },
  head: () => ({
    meta: [
      { title: "Threat Dashboard — ThreatPulse CTI" },
      {
        name: "description",
        content:
          "Risk scores, OSINT provider verdicts, advanced threat analytics and full scan history for your indicators.",
      },
    ],
  }),
  component: DashboardPage,
});

function DashboardPage() {
  const { t, lang } = useLanguage();
  const { user, ready } = useAuth();
  const { q } = Route.useSearch();
  const [filter, setFilter] = useState("");
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  const activeIndicator = q && q.length > 3 ? q : "login-verify-account.tk";

  const scanQuery = useQuery({
    queryKey: ["scan", activeIndicator],
    queryFn: () => threatService.scan(activeIndicator),
    staleTime: 1000 * 60 * 5, // 5 minutes cache
  });

  const history = useQuery({
    queryKey: ["history"],
    queryFn: threatService.history,
  });

  // Automatically refresh history when scan completes
  useEffect(() => {
    if (scanQuery.data) {
      history.refetch();
    }
  }, [scanQuery.data]);

  const active: ScanResult = scanQuery.data ?? (scanQuery.isError ? buildFallbackScan(activeIndicator) : null as any);

  const rows = useMemo(() => {
    const historyList = history.data ?? [];
    const seen = new Set<string>();
    const combined = active ? [active, ...historyList] : historyList;
    const unique = combined.filter((r) => {
      const key = r.indicator.toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    const f = filter.trim().toLowerCase();
    return f ? unique.filter((r) => r.indicator.toLowerCase().includes(f)) : unique;
  }, [active, history.data, filter]);

  const globeNodes = useMemo(() => {
    if (!active) return undefined;
    const coords = COUNTRY_COORDS[active.country] || { lat: 39.0, lon: -77.5 };
    return [
      {
        id: "active-target",
        label: `${active.indicator} (${active.country})`,
        lat: coords.lat,
        lon: coords.lon,
        severity: active.verdict,
      },
      { id: "sa-sensor", label: "Riyadh SOC Gateway", lat: 24.7, lon: 46.7, severity: "clean" as const },
      { id: "de-node", label: "Frankfurt Relay", lat: 50.1, lon: 8.7, severity: "malicious" as const },
      { id: "us-node", label: "US East (Ashburn)", lat: 39.0, lon: -77.5, severity: "clean" as const },
      { id: "ru-node", label: "Moscow C2", lat: 55.7, lon: 37.6, severity: "malicious" as const },
      { id: "cn-node", label: "Shanghai Botnet", lat: 31.2, lon: 121.5, severity: "malicious" as const },
    ];
  }, [active]);

  const copy = async (value: string) => {
    await navigator.clipboard.writeText(value);
    toast.success(t("copied"));
  };

  const exportCsv = () => {
    const csv = [
      ["indicator", "type", "score", "verdict", "country", "asn", "scannedAt"].join(","),
      ...rows.map((r) =>
        [r.indicator, r.type, r.riskScore, r.verdict, r.country, r.asn, r.scannedAt].join(","),
      ),
    ].join("\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "threatpulse-scans.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  if (ready && !user) {
    return (
      <div className="mx-auto flex max-w-md flex-col items-center gap-4 px-4 py-24 text-center">
        <Lock className="size-8 text-primary" />
        <p className="text-sm text-muted-foreground">{t("scan_done")}</p>
        <Button asChild>
          <Link to="/auth">{t("login")}</Link>
        </Button>
      </div>
    );
  }

  return (
    <div className="mx-auto w-full max-w-[1600px] px-4 py-10 sm:px-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">{t("nav_dashboard")}</h1>
          <p className="mt-1 font-mono text-xs text-muted-foreground" dir="ltr">
            {active ? `${active.indicator} · ${active.asn} · ${active.country}` : activeIndicator}
          </p>
        </div>
        <Button asChild variant="default" className="shadow-lg shadow-primary/20">
          <Link to="/">{t("scan_new")}</Link>
        </Button>
      </div>

      {scanQuery.isPending && !active ? (
        <div className="mt-8 rounded-2xl glass-panel p-12 text-center flex flex-col items-center justify-center min-h-[350px]">
          <div className="relative mb-6">
            <div className="size-20 rounded-full border-2 border-primary/30 animate-ping absolute inset-0" />
            <div className="size-20 rounded-full border border-primary/40 flex items-center justify-center bg-primary/10">
              <Activity className="size-8 text-primary animate-pulse" />
            </div>
          </div>
          <h2 className="text-xl font-bold mb-2">
            {lang === "ar" ? "جاري الاتصال بـ VirusTotal وتحليل التهديدات..." : "Querying VirusTotal & Threat Feeds..."}
          </h2>
          <p className="text-sm font-mono text-muted-foreground" dir="ltr">
            {activeIndicator}
          </p>
        </div>
      ) : active ? (
        <>
          {/* 1. القسم العلوي (النتائج الفورية) */}
          <div className="mt-6 grid gap-4 lg:grid-cols-3">
            {/* نقاط الخطر والحالة */}
            <div className="glass-panel rounded-2xl p-5 flex flex-col items-center justify-center relative overflow-hidden">
              <div className="absolute top-3 end-4 flex items-center gap-1.5">
                <span className="relative flex size-2.5">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald opacity-75"></span>
                  <span className="relative inline-flex rounded-full size-2.5 bg-emerald"></span>
                </span>
                <span className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">Live</span>
              </div>
              <RiskGauge score={active.riskScore} verdict={active.verdict} />
            </div>

        {/* نوع التهديد */}
        <div className="glass-panel rounded-2xl p-5 flex flex-col">
          <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
            <AlertTriangle className={`size-4 ${active.verdict === 'clean' ? 'text-emerald' : active.verdict === 'suspicious' ? 'text-amber' : 'text-crimson'}`} /> 
            {lang === 'ar' ? 'تصنيف التهديد' : 'Threat Classification'}
          </h3>
          <div className="flex-1 flex flex-col items-center justify-center text-center">
             <span className="font-semibold text-lg text-foreground mb-1">{active.classification}</span>
             <span className="text-xs font-mono text-muted-foreground bg-muted/30 px-2.5 py-1 rounded-md border border-border mt-2">
                MITRE: {active.mitreTactic}
             </span>
          </div>
        </div>

        {/* التوصيات الفورية */}
        <div className="glass-panel rounded-2xl p-5 flex flex-col">
          <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
            <Info className="size-4 text-primary" /> 
            {lang === 'ar' ? 'التوصيات الفورية' : 'Actionable Recommendations'}
          </h3>
          <ul className="space-y-3 text-sm">
             {active.recommendations?.map((rec, i) => (
               <li key={i} className="flex gap-2.5 items-start">
                  <Shield className="size-4 text-emerald shrink-0 mt-0.5" /> 
                  <span className="text-muted-foreground">{rec}</span>
               </li>
             ))}
          </ul>
        </div>
      </div>

      {/* 2. القسم الأوسط (التحليل المفصل) */}
      <div className="mt-6 grid gap-4 lg:grid-cols-2">
        {/* لقطة الشاشة الآمنة */}
        <section className="glass-panel rounded-2xl p-5 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold flex items-center gap-2">
              <ImageIcon className="size-4" /> 
              {lang === 'ar' ? 'لقطة شاشة آمنة' : 'Sandboxed Screenshot'}
            </h3>
            <span className="text-[10px] uppercase font-mono tracking-widest text-emerald bg-emerald/10 px-2 py-0.5 rounded border border-emerald/20">Isolating Environment</span>
          </div>
          <div className="flex-1 w-full bg-muted/20 rounded-xl border border-border/50 overflow-hidden relative group">
            {active.screenshotUrl ? (
              <>
                 <img src={active.screenshotUrl} alt="Secure Render" className="w-full h-full object-cover blur-[2px] opacity-70 group-hover:blur-none group-hover:opacity-100 transition-all duration-500" />
                 <div className="absolute inset-0 bg-gradient-to-t from-background/80 to-transparent pointer-events-none" />
              </>
            ) : (
              <Skeleton className="absolute inset-0 w-full h-full opacity-20" />
            )}
          </div>
        </section>

        {/* مزودي الاستخبارات */}
        <section className="glass-panel rounded-2xl p-5 flex flex-col justify-center">
          <h3 className="text-sm font-semibold mb-4">{t("providers")}</h3>
          <ProviderBadges providers={active.providers} />
        </section>
      </div>

      {/* 3. القسم السفلي (الرادار ثلاثي الأبعاد والبيانات العميقة) */}
      <div className="mt-6 grid gap-4 lg:grid-cols-3">
        {/* الكرة الأرضية ثلاثية الأبعاد */}
        <section className="glass-panel rounded-2xl p-5 flex flex-col justify-center items-center">
          <ThreatGlobe nodes={globeNodes} />
        </section>

        {/* الرسم البياني لارتباطات التهديد */}
        <section className="glass-panel rounded-2xl p-5 flex flex-col justify-between">
          <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
            <Activity className="size-4" /> 
            {lang === 'ar' ? 'الرسم البياني للتهديدات' : 'Threat Graph'}
          </h3>
          <div className="h-64 bg-muted/5 rounded-xl flex items-center justify-center border border-border/50 overflow-hidden">
             <ThreatGraph indicator={active.indicator} type={active.type} verdict={active.verdict} />
          </div>
        </section>

        {/* معلومات الاستضافة */}
        <section className="glass-panel rounded-2xl p-5 flex flex-col justify-between">
          <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
            <Globe className="size-4" /> 
            {lang === 'ar' ? 'معلومات الاستضافة (WHOIS & SSL)' : 'Infrastructure & WHOIS'}
          </h3>
          <div className="grid grid-cols-2 gap-4 mt-2">
             <div className="space-y-1">
                <p className="text-xs text-muted-foreground">Registrar</p>
                <p className="text-sm font-mono">{active.whois?.registrar}</p>
             </div>
             <div className="space-y-1">
                <p className="text-xs text-muted-foreground">Created / Expires</p>
                <p className="text-sm font-mono">{active.whois?.created} <span className="text-muted-foreground text-xs mx-1">to</span> {active.whois?.expires}</p>
             </div>
             <div className="space-y-1 col-span-2 pt-2 border-t border-border/50">
                <p className="text-xs text-muted-foreground">SSL/TLS Issuer</p>
                <div className="flex items-center gap-2 mt-1">
                   <Shield className={`size-4 ${active.ssl?.valid ? 'text-emerald' : 'text-crimson'}`} />
                   <p className="text-sm font-mono truncate">{active.ssl?.issuer}</p>
                   {active.ssl?.selfSigned && (
                     <span className="text-[10px] text-amber bg-amber/10 border border-amber/20 px-1.5 py-0.5 rounded">Self-Signed</span>
                   )}
                </div>
              </div>
            </div>
          </section>
        </div>
      </>
      ) : null}

      {/* جدول سجل الفحوصات */}
      <section className="glass-panel mt-6 rounded-2xl p-5">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center mb-4">
          <h3 className="text-sm font-semibold">{t("history")}</h3>
          <div className="relative sm:ms-auto sm:w-72">
            <Search className="pointer-events-none absolute top-1/2 start-3 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder={t("filter")}
              className="ps-9 h-9"
            />
          </div>
          {/* Updated Button Hierarchy: Secondary/Outline for Export CSV */}
          <Button variant="outline" size="sm" onClick={exportCsv} className="h-9">
            <Download className="size-4 me-2" />
            {t("export_csv")}
          </Button>
        </div>

        {history.isPending ? (
          <div className="space-y-3 mt-4">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        ) : rows.length === 0 ? (
          <p className="mt-6 text-sm text-muted-foreground">{t("no_results")}</p>
        ) : (
          <>
            <div className="hidden overflow-x-auto md:block">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-start text-xs uppercase tracking-wider text-muted-foreground">
                    <th className="py-3 px-4 text-start font-medium">{t("indicator")}</th>
                    <th className="py-3 px-4 text-start font-medium">{t("score")}</th>
                    <th className="py-3 px-4 text-start font-medium">{t("status")}</th>
                    <th className="py-3 px-4 text-start font-medium">{t("country")}</th>
                    <th className="py-3 px-4 text-start font-medium">{t("when")}</th>
                    <th className="py-3 px-4 text-end" />
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.id} className="border-b border-border/40 hover:bg-muted/40 transition-colors">
                      <td className="py-3 px-4 text-start">
                        <span
                          className="font-mono text-xs font-semibold px-2.5 py-1 rounded bg-muted/40 border border-border/60 inline-block max-w-[320px] truncate"
                          dir="ltr"
                        >
                          {r.indicator}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-start">
                        <span
                          className={`inline-flex items-center justify-center font-mono text-xs font-bold px-2 py-0.5 rounded ${
                            r.riskScore > 70
                              ? "bg-crimson/15 text-crimson border border-crimson/30"
                              : r.riskScore > 30
                              ? "bg-amber/15 text-amber border border-amber/30"
                              : "bg-emerald/15 text-emerald border border-emerald/30"
                          }`}
                        >
                          {r.riskScore}/100
                        </span>
                      </td>
                      <td className="py-3 px-4 text-start">
                        <VerdictBadge verdict={r.verdict} />
                      </td>
                      <td className="py-3 px-4 text-start font-mono text-xs text-muted-foreground">
                        {r.country}
                      </td>
                      <td className="py-3 px-4 text-start text-xs text-muted-foreground" suppressHydrationWarning>
                        {mounted
                          ? new Date(r.scannedAt).toLocaleString(lang === "ar" ? "ar" : "en-GB")
                          : ""}
                      </td>
                      <td className="py-3 px-4 text-end">
                        <Button variant="ghost" size="icon" onClick={() => copy(r.indicator)} className="size-8">
                          <Copy className="size-3.5" />
                          <span className="sr-only">{t("copy")}</span>
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="space-y-3 md:hidden">
              {rows.map((r) => (
                <div key={r.id} className="rounded-xl border border-border bg-card/60 p-3">
                  <p className="truncate font-mono text-xs" dir="ltr">
                    {r.indicator}
                  </p>
                  <div className="mt-2 flex items-center gap-2">
                    <VerdictBadge verdict={r.verdict} />
                    <span className="font-mono text-sm tabular-nums">{r.riskScore}</span>
                    <span className="text-xs text-muted-foreground">{r.country}</span>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="ms-auto"
                      onClick={() => copy(r.indicator)}
                    >
                      <Copy className="size-4" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </section>
    </div>
  );
}
