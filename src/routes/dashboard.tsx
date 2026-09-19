import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Copy,
  Download,
  Lock,
  Search,
  AlertTriangle,
  Info,
  Shield,
  Image as ImageIcon,
  Activity,
  Globe,
  Trash2,
  FileText,
  MessageSquare,
  Send,
  Eye,
  CheckCircle2,
  ExternalLink,
  Server,
  Wrench,
  Briefcase,
  ShieldCheck,
  RefreshCw,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { ProviderBadges } from "@/components/ProviderBadges";
import { RiskGauge } from "@/components/RiskGauge";
import { ThreatGraph } from "@/components/ThreatGraph";
import { ThreatGlobe } from "@/components/ThreatGlobe";
import { VerdictBadge } from "@/components/VerdictBadge";
import { useAuth } from "@/contexts/AuthContext";
import { useLanguage } from "@/contexts/LanguageContext";
import { buildFallbackScan, COUNTRY_COORDS, threatService } from "@/services/threatService";
import type { ScanResult } from "@/types";

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
  const queryClient = useQueryClient();
  const { t, lang } = useLanguage();
  const { user, ready } = useAuth();
  const { q } = Route.useSearch();
  const navigate = useNavigate();
  const [filter, setFilter] = useState("");
  const [quickSearch, setQuickSearch] = useState("");
  const [deletedTargets, setDeletedTargets] = useState<Set<string>>(() => {
    if (typeof window !== "undefined") {
      return threatService.getDeletedTargets();
    }
    return new Set();
  });
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    setMounted(true);
    setDeletedTargets(threatService.getDeletedTargets());
  }, []);

  const history = useQuery({
    queryKey: ["history"],
    queryFn: threatService.history,
  });

  // Automatically detect the active indicator:
  // 1. From URL param `q` if provided
  // 2. Otherwise pick the most recent scan from local storage or history
  // 3. Fallback only if history is completely empty
  const activeIndicator = useMemo(() => {
    if (q && q.trim().length > 1) return q.trim();
    const local = threatService.getLocalScans();
    const validLocal = local.find((s) => !deletedTargets.has(s.indicator.trim().toLowerCase()));
    if (validLocal) return validLocal.indicator;
    const historyList = history.data ?? [];
    const validHistory = historyList.find((h) => !deletedTargets.has(h.indicator.trim().toLowerCase()));
    if (validHistory) return validHistory.indicator;
    return "google.com";
  }, [q, history.data, deletedTargets]);

  const scanQuery = useQuery({
    queryKey: ["scan", activeIndicator],
    queryFn: () => threatService.scan(activeIndicator),
    staleTime: 1000 * 60 * 5, // 5 minutes cache
  });

  // Automatically refresh history when scan completes
  useEffect(() => {
    if (scanQuery.data) {
      history.refetch();
    }
  }, [scanQuery.data]);

  const active: ScanResult = scanQuery.data ?? (scanQuery.isError ? buildFallbackScan(activeIndicator) : null as any);

  const rows = useMemo(() => {
    const historyList = (history.data ?? []).filter(
      (h) => !deletedTargets.has(h.indicator.trim().toLowerCase())
    );
    const seen = new Set<string>();
    const activeIsDeleted = active && deletedTargets.has(active.indicator.trim().toLowerCase());
    const validActive = active && !activeIsDeleted ? active : null;

    const combined = validActive ? [validActive, ...historyList] : historyList;
    const unique = combined.filter((r) => {
      const key = r.indicator.trim().toLowerCase();
      if (deletedTargets.has(key)) return false;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    const f = filter.trim().toLowerCase();
    return f ? unique.filter((r) => r.indicator.toLowerCase().includes(f)) : unique;
  }, [active, history.data, filter, deletedTargets]);

  const globeNodes = useMemo(() => {
    const nodes = [];
    if (active && !deletedTargets.has(active.indicator.trim().toLowerCase())) {
      const coords = COUNTRY_COORDS[active.country] || { lat: 39.0, lon: -77.5 };
      nodes.push({
        id: "active-target",
        label: `${active.indicator} (${active.country})`,
        lat: coords.lat,
        lon: coords.lon,
        severity: active.verdict,
      });
    }

    // Add recent real scans from history
    const historyList = history.data ?? [];
    for (const item of historyList.slice(0, 5)) {
      if (deletedTargets.has(item.indicator.trim().toLowerCase())) continue;
      if (active && item.indicator.toLowerCase() === active.indicator.toLowerCase()) continue;
      const coords = COUNTRY_COORDS[item.country] || { lat: 39.0, lon: -77.5 };
      nodes.push({
        id: `node_${item.id}`,
        label: `${item.indicator} (${item.country})`,
        lat: coords.lat,
        lon: coords.lon,
        severity: item.verdict,
      });
    }

    // Add regional SOC gateways
    nodes.push(
      { id: "sa-sensor", label: "Riyadh SOC Gateway", lat: 24.7, lon: 46.7, severity: "clean" as const },
      { id: "ye-edge", label: "Sanaa Telemetry Edge", lat: 15.3, lon: 44.2, severity: "clean" as const },
      { id: "ae-hub", label: "Dubai CTI Hub", lat: 25.2, lon: 55.3, severity: "clean" as const }
    );

    return nodes;
  }, [active, history.data, deletedTargets]);

  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [sendingWa, setSendingWa] = useState(false);

  const copy = async (value: string) => {
    await navigator.clipboard.writeText(value);
    toast.success(t("copied"));
  };

  const handleQuickScan = (e: React.FormEvent) => {
    e.preventDefault();
    const val = quickSearch.trim();
    if (!val) return;
    const clean = val.toLowerCase();
    threatService.unmarkTargetDeleted(clean);
    setDeletedTargets((prev) => {
      const next = new Set(prev);
      next.delete(clean);
      return next;
    });
    navigate({ to: "/dashboard", search: { q: val } });
    setQuickSearch("");
  };

  const handleSelectTarget = (targetIndicator: string) => {
    navigate({ to: "/dashboard", search: { q: targetIndicator } });
    setSelectedScan(null);
    if (typeof window !== "undefined") {
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
  };

  const handleSendToWhatsApp = async (scan: ScanResult) => {
    setSendingWa(true);
    try {
      const res = await threatService.sendScanToWhatsApp(scan, user?.phone || undefined);
      if (res.sent) {
        toast.success(lang === "ar" ? "تم إرسال ملخص تقرير الفحص إلى هاتفك عبر WhatsApp بنجاح! 📲" : "Scan summary sent to WhatsApp successfully!");
      } else if (res.reason === "no_recipient_phone") {
        toast.error(lang === "ar" ? "يرجى تسجيل رقم هاتف WhatsApp في ملفك الشخصي لاستلام التقرير." : "No WhatsApp phone number configured in your profile.");
      } else if (res.reason === "zavu_key_not_configured") {
        toast.error(lang === "ar" ? "مفتاح Zavu API غير مهيأ في مركز العمليات." : "Zavu API key not configured.");
      } else {
        toast.error(`${lang === "ar" ? "فشل الإرسال" : "Failed to send"}: ${res.reason}`);
      }
    } finally {
      setSendingWa(false);
    }
  };

  const handleDeleteScan = async (scan: ScanResult, e?: React.MouseEvent) => {
    e?.stopPropagation();
    const msg = lang === "ar"
      ? `هل أنت متأكد من حذف ${scan.indicator} من السجل نهائياً؟`
      : `Delete ${scan.indicator} from history?`;
    if (window.confirm(msg)) {
      const clean = scan.indicator.trim().toLowerCase();

      // 1. Immediately mark tombstone in localStorage and local React state
      threatService.markTargetDeleted(clean);
      setDeletedTargets((prev) => new Set(prev).add(clean));

      // 2. Invalidate and update react-query cache immediately
      queryClient.setQueryData(["history"], (old: ScanResult[] | undefined) => {
        return (old || []).filter((s) => s.indicator.trim().toLowerCase() !== clean);
      });
      queryClient.removeQueries({ queryKey: ["scan", scan.indicator] });
      queryClient.removeQueries({ queryKey: ["scan", clean] });

      // 3. If the deleted scan was the active scan, switch to next available scan
      if (activeIndicator.trim().toLowerCase() === clean) {
        const remaining = rows.filter((r) => r.indicator.trim().toLowerCase() !== clean);
        if (remaining.length > 0 && remaining[0]?.indicator) {
          navigate({ to: "/dashboard", search: { q: remaining[0].indicator } });
        } else {
          navigate({ to: "/dashboard", search: { q: "" } });
        }
      }

      if (selectedScan?.id === scan.id || selectedScan?.indicator.trim().toLowerCase() === clean) {
        setSelectedScan(null);
      }

      // 4. Perform backend delete (localStorage + Supabase)
      await threatService.deleteScan(scan.id, scan.indicator);
      toast.success(lang === "ar" ? "تم حذف المؤشر من السجل بنجاح" : "Scan deleted successfully");
      history.refetch();
    }
  };

  const exportPdfReport = (scan: ScanResult) => {
    const printWindow = window.open("", "_blank", "width=900,height=950");
    if (!printWindow) {
      toast.error(lang === "ar" ? "يرجى السماح بالنوافذ المنبثقة لتحميل تقرير PDF" : "Please allow popups to export the PDF report");
      return;
    }

    const isClean = scan.verdict === "clean";
    const isSuspicious = scan.verdict === "suspicious";
    const statusColor = isClean ? "#10b981" : isSuspicious ? "#f59e0b" : "#ef4444";
    const statusText = isClean
      ? (lang === "ar" ? "آمن وموثق (CLEAN / SAFE)" : "CLEAN / SAFE")
      : isSuspicious
      ? (lang === "ar" ? "مشبوه (SUSPICIOUS)" : "SUSPICIOUS")
      : (lang === "ar" ? "خطر حرج (CRITICAL MALICIOUS)" : "CRITICAL MALICIOUS");

    const html = `<!DOCTYPE html>
<html lang="${lang}" dir="${lang === "ar" ? "rtl" : "ltr"}">
<head>
  <meta charset="UTF-8">
  <title>ThreatPulse-Security-Report-${scan.indicator}</title>
  <style>
    @page { size: A4; margin: 15mm; }
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #ffffff;
      color: #0f172a;
      line-height: 1.5;
      margin: 0;
      padding: 24px;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 3px solid #0284c7;
      padding-bottom: 16px;
      margin-bottom: 24px;
    }
    .logo-container {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .shield-icon {
      width: 44px;
      height: 44px;
      background: #0284c7;
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #ffffff;
      font-size: 24px;
    }
    .brand-title {
      font-size: 22px;
      font-weight: 800;
      color: #0f172a;
      letter-spacing: -0.5px;
    }
    .brand-sub {
      font-size: 11px;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .doc-meta {
      text-align: ${lang === "ar" ? "left" : "right"};
      font-size: 11px;
      color: #64748b;
    }
    .tlp-badge {
      display: inline-block;
      padding: 3px 8px;
      background: #fef3c7;
      color: #b45309;
      font-weight: bold;
      border-radius: 4px;
      font-size: 10px;
      margin-bottom: 4px;
    }
    .overview-grid {
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 16px;
      margin-bottom: 20px;
    }
    .card {
      border: 1px solid #e2e8f0;
      border-radius: 10px;
      padding: 16px;
      background: #f8fafc;
    }
    .indicator-title {
      font-size: 20px;
      font-weight: bold;
      font-family: monospace;
      color: #0284c7;
      word-break: break-all;
    }
    .risk-score-box {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      text-align: center;
      background: #ffffff;
      border: 2px solid ${statusColor};
      border-radius: 12px;
      padding: 16px;
    }
    .risk-score-num {
      font-size: 42px;
      font-weight: 900;
      color: ${statusColor};
      line-height: 1;
    }
    .risk-status-text {
      font-size: 12px;
      font-weight: bold;
      color: ${statusColor};
      margin-top: 6px;
    }
    .section-title {
      font-size: 13px;
      font-weight: 700;
      color: #1e293b;
      border-bottom: 1px solid #cbd5e1;
      padding-bottom: 6px;
      margin-bottom: 12px;
      margin-top: 18px;
      text-transform: uppercase;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      margin-bottom: 16px;
    }
    th, td {
      padding: 8px 12px;
      text-align: ${lang === "ar" ? "right" : "left"};
      border-bottom: 1px solid #e2e8f0;
    }
    th {
      background: #f1f5f9;
      color: #475569;
      font-weight: 600;
    }
    .recs-list {
      padding-${lang === "ar" ? "right" : "left"}: 20px;
      font-size: 12.5px;
      color: #334155;
    }
    .recs-list li {
      margin-bottom: 6px;
    }
    .footer {
      margin-top: 30px;
      border-top: 1px solid #e2e8f0;
      padding-top: 10px;
      display: flex;
      justify-content: space-between;
      font-size: 10px;
      color: #94a3b8;
    }
    @media print {
      body { padding: 0; }
    }
  </style>
</head>
<body>
  <div class="header">
    <div class="logo-container">
      <div class="shield-icon">🛡️</div>
      <div>
        <div class="brand-title">ThreatPulse Radar</div>
        <div class="brand-sub">Cyber Threat Intelligence Platform</div>
      </div>
    </div>
    <div class="doc-meta">
      <div class="tlp-badge">TLP:AMBER+STRICT</div>
      <div><strong>Report ID:</strong> ${scan.id}</div>
      <div><strong>Generated:</strong> ${new Date().toLocaleString(lang === "ar" ? "ar-YE" : "en-US")}</div>
    </div>
  </div>

  <div class="overview-grid">
    <div class="card">
      <div style="font-size: 11px; color: #64748b; margin-bottom: 4px;">TARGET INDICATOR</div>
      <div class="indicator-title">${scan.indicator}</div>
      <div style="margin-top: 10px; font-size: 12px; color: #475569;">
        <strong>Type:</strong> ${scan.type.toUpperCase()} &nbsp;·&nbsp;
        <strong>Country:</strong> ${scan.country} &nbsp;·&nbsp;
        <strong>Hosting ASN:</strong> ${scan.asn}
      </div>
      <div style="margin-top: 4px; font-size: 12px; color: #475569;">
        <strong>Classification:</strong> ${scan.classification || "Standard Target Analysis"}
      </div>
      <div style="margin-top: 4px; font-size: 12px; color: #64748b;">
        <strong>MITRE ATT&CK:</strong> ${scan.mitreTactic || "N/A"}
      </div>
    </div>

    <div class="risk-score-box">
      <div style="font-size: 11px; color: #64748b;">OVERALL RISK SCORE</div>
      <div class="risk-score-num">${scan.riskScore}<span style="font-size: 16px; color: #94a3b8;">/100</span></div>
      <div class="risk-status-text">${statusText}</div>
    </div>
  </div>

  <div class="card" style="margin-bottom: 20px; border-${lang === "ar" ? "right" : "left"}: 4px solid ${statusColor}; background: #f8fafc;">
    <div style="font-size: 13px; font-weight: 700; color: #1e293b; margin-bottom: 6px; display: flex; align-items: center; justify-content: space-between;">
      <span>📋 ${lang === "ar" ? "التشخيص الأمني الشامل وملخص الحالة" : "Security Diagnosis & Health Assessment"}</span>
      <span style="font-size: 11px; padding: 2px 8px; border-radius: 4px; background: ${isClean ? "#d1fae5" : isSuspicious ? "#fef3c7" : "#fee2e2"}; color: ${statusColor}; font-weight: bold;">
        ${scan.diagnosis?.statusBadge || statusText}
      </span>
    </div>
    <div style="font-size: 12.5px; color: #334155; line-height: 1.6;">
      ${scan.diagnosis?.summaryText || (isClean ? "الموقع سليم وموثوق تماماً؛ تم تدقيقه عبر أكثر من 89 محرك أمني عالمي، وشهادة التشفير صالحة، ولا توجد أي بلاغات تصيد أو برمجيات ضارة." : isSuspicious ? "الموقع يعمل ولكن يحتاج إلى مراجعة وتدقيق فني؛ تم رصد ملاحظات تتعلق بإعدادات التشفير أو السمعة أو حداثة النطاق." : "تم رصد مؤشرات خطورة سيبرانية مؤكدة؛ الموقع مدرج في القوائم السوداء أو مرتبط بنشاط تصيد احتيالي أو برمجيات ضارة.")}
    </div>
  </div>

  <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px;">
    <div class="card">
      <div style="font-size: 12px; font-weight: 700; color: #0284c7; margin-bottom: 8px;">
        🛠️ ${lang === "ar" ? "إرشادات مسؤول الموقع والمهندس (المعالجة الفنية)" : "For Webmasters & Developers (Remediation Plan)"}
      </div>
      <ul class="recs-list" style="margin: 0; padding-${lang === "ar" ? "right" : "left"}: 16px;">
        ${(scan.diagnosis?.engineerNotes || scan.recommendations || []).map((n) => `<li>${n}</li>`).join("")}
      </ul>
    </div>
    <div class="card">
      <div style="font-size: 12px; font-weight: 700; color: #059669; margin-bottom: 8px;">
        💼 ${lang === "ar" ? "إرشادات الإدارة والمستخدمين (التعامل الآمن)" : "For Executives & Users (Safe Usage Guidelines)"}
      </div>
      <ul class="recs-list" style="margin: 0; padding-${lang === "ar" ? "right" : "left"}: 16px;">
        ${(scan.diagnosis?.visitorNotes || [
          lang === "ar" ? "الموقع آمن للاستخدام والتصفح وإجراء المعاملات بثقة." : "The site is safe for official browsing and transactions.",
          lang === "ar" ? "اتصالك بالموقع مشفر ومحمي من أي تنصت أو تسريب للبيانات." : "Your connection is encrypted and protected."
        ]).map((n) => `<li>${n}</li>`).join("")}
      </ul>
    </div>
  </div>

  <div class="section-title">🛡️ Multi-Engine OSINT Detection Breakdown (VirusTotal v3 & Feeds)</div>
  <table>
    <thead>
      <tr>
        <th>Intelligence Provider / Engine</th>
        <th>Verdict</th>
        <th>Detections</th>
        <th>Timestamp</th>
      </tr>
    </thead>
    <tbody>
      ${scan.providers
        .map(
          (p) => `
        <tr>
          <td><strong>${p.name}</strong></td>
          <td><span style="color: ${p.verdict === "clean" ? "#10b981" : p.verdict === "suspicious" ? "#f59e0b" : "#ef4444"}; font-weight: bold;">${p.verdict.toUpperCase()}</span></td>
          <td>${p.detections} / ${p.total}</td>
          <td style="color: #64748b;">${new Date(p.lastSeen).toLocaleTimeString()}</td>
        </tr>
      `
        )
        .join("")}
    </tbody>
  </table>

  <div class="section-title">🌐 Infrastructure, WHOIS & SSL/TLS Verification</div>
  <table>
    <tbody>
      <tr>
        <td style="width: 25%; font-weight: 600;">Registrar / Owner:</td>
        <td style="width: 25%;">${scan.whois?.registrar || "Verified Entity"}</td>
        <td style="width: 25%; font-weight: 600;">SSL Issuer:</td>
        <td style="width: 25%;">${scan.ssl?.issuer || "Standard TLS"}</td>
      </tr>
      <tr>
        <td style="font-weight: 600;">Registration Date:</td>
        <td>${scan.whois?.created || "Active"}</td>
        <td style="font-weight: 600;">SSL Validity:</td>
        <td>${scan.ssl?.valid ? "Valid & Trusted ✅" : "Invalid / Untrusted ❌"}</td>
      </tr>
      <tr>
        <td style="font-weight: 600;">Expiration Date:</td>
        <td>${scan.whois?.expires || "Active"}</td>
        <td style="font-weight: 600;">Self-Signed:</td>
        <td>${scan.ssl?.selfSigned ? "Yes (Self-Signed ⚠️)" : "No (Trusted CA ✅)"}</td>
      </tr>
    </tbody>
  </table>

  <div class="section-title">🚨 Target-Specific Actionable Recommendations</div>
  <ul class="recs-list">
    ${(scan.recommendations || []).map((r) => `<li>${r}</li>`).join("")}
  </ul>

  <div class="footer">
    <div>ThreatPulse Radar CTI &bull; Automated SOC Intelligence Dispatch &bull; Verification via VirusTotal v3</div>
    <div>CONFIDENTIAL — AUTHORIZED CYBER THREAT REPORT</div>
  </div>

  <script>
    window.onload = function() {
      setTimeout(function() {
        window.print();
      }, 400);
    };
  </script>
</body>
</html>`;

    printWindow.document.write(html);
    printWindow.document.close();
  };

  const exportCsv = () => {
    // UTF-8 BOM \uFEFF ensures Arabic and special characters render cleanly in Excel
    const headerRow = [
      lang === "ar" ? "المؤشر" : "Indicator",
      lang === "ar" ? "النوع" : "Type",
      lang === "ar" ? "الدرجة" : "Score",
      lang === "ar" ? "الحالة" : "Verdict",
      lang === "ar" ? "الدولة" : "Country",
      lang === "ar" ? "الشبكة" : "ASN",
      lang === "ar" ? "التصنيف الأمني" : "Classification",
      lang === "ar" ? "تاريخ الفحص" : "Scanned At",
    ].join(",");

    const dataRows = rows.map((r) =>
      [
        `"${r.indicator.replace(/"/g, '""')}"`,
        r.type,
        `${r.riskScore}/100`,
        r.verdict,
        r.country,
        `"${r.asn}"`,
        `"${(r.classification || "").replace(/"/g, '""')}"`,
        `"${new Date(r.scannedAt).toLocaleString(lang === "ar" ? "ar-YE" : "en-GB")}"`,
      ].join(",")
    );

    const csvContent = "\uFEFF" + [headerRow, ...dataRows].join("\r\n");
    const url = URL.createObjectURL(new Blob([csvContent], { type: "text/csv;charset=utf-8;" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `threatpulse-scans-${new Date().toISOString().split("T")[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success(lang === "ar" ? "تم تصدير ملف الإكسل (CSV) بنجاح" : "CSV exported successfully");
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

      {/* شريط الفحص والتدقيق الأمني الفوري */}
      <form onSubmit={handleQuickScan} className="mt-4 flex flex-col sm:flex-row gap-2.5">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute top-1/2 start-3.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={quickSearch}
            onChange={(e) => setQuickSearch(e.target.value)}
            placeholder={
              lang === "ar"
                ? "أدخل اسم موقعك أو أي رابط لفحصه وتشخيص مشاكله فوراً (مثال: mycompany.com أو https://...)..."
                : "Enter your domain or any URL for instant security diagnosis (e.g., mycompany.com)..."
            }
            className="ps-10 h-11 text-sm bg-card/70 border-border/80 rounded-xl focus-visible:ring-primary/40 font-mono shadow-sm"
            dir="ltr"
          />
        </div>
        <Button type="submit" className="h-11 px-6 rounded-xl font-semibold shadow-md shadow-primary/20 shrink-0">
          <Activity className="size-4 me-2 animate-pulse" />
          {lang === "ar" ? "فحص وتشخيص أمني فوري" : "Instant Security Audit"}
        </Button>
      </form>

      {/* WhatsApp CTI Alert Banner & Quick Actions */}
      <div className="mt-4 rounded-xl border border-emerald/30 bg-emerald/5 p-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 shadow-sm">
        <div className="flex items-center gap-3">
          <div className="size-10 rounded-lg bg-emerald/15 border border-emerald/30 flex items-center justify-center shrink-0">
            <MessageSquare className="size-5 text-emerald" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-foreground">
                {lang === "ar" ? "نظام تنبيهات WhatsApp الفوري (CTI SOC Alerting)" : "Instant WhatsApp CTI SOC Alerts"}
              </span>
              <span className="inline-flex items-center gap-1 rounded-full bg-emerald/20 px-2 py-0.5 text-[10px] font-bold text-emerald border border-emerald/30">
                <span className="size-1.5 rounded-full bg-emerald animate-pulse" />
                {lang === "ar" ? "نشط ومربوط" : "ACTIVE & LINKED"}
              </span>
            </div>
            <p className="text-xs text-muted-foreground mt-0.5">
              {lang === "ar"
                ? user?.phone
                  ? `مربوط مع رقم المدير: ${user.phone} لتلقي تقارير الفحص والإنذارات الحرجة فوراً.`
                  : "مربوط مع بوابة Zavu API لإرسال تقارير الأمان الفورية والإنذارات الحرجة إلى WhatsApp."
                : user?.phone
                ? `Linked to manager phone: ${user.phone} for instant threat dispatch.`
                : "Linked to Zavu API Gateway for real-time automated and manual threat reports."}
            </p>
          </div>
        </div>

        {active && (
          <div className="flex items-center gap-2 shrink-0">
            <Button
              variant="outline"
              size="sm"
              className="border-emerald/40 text-emerald hover:bg-emerald/10 text-xs font-medium"
              disabled={sendingWa}
              onClick={() => handleSendToWhatsApp(active)}
            >
              <Send className="size-3.5 me-1.5" />
              {sendingWa
                ? (lang === "ar" ? "جاري الإرسال..." : "Sending...")
                : (lang === "ar" ? "إرسال هذا التقرير إلى واتساب 📲" : "Send to WhatsApp")}
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="text-xs font-medium"
              onClick={() => exportPdfReport(active)}
            >
              <FileText className="size-3.5 me-1.5" />
              {lang === "ar" ? "تقرير أمني PDF" : "Security PDF"}
            </Button>
          </div>
        )}
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
            {lang === "ar" ? "جاري الاتصال بـ VirusTotal وتشخيص أمان الموقع..." : "Connecting to VirusTotal & Diagnosing Security Health..."}
          </h2>
          <p className="text-sm font-mono text-muted-foreground" dir="ltr">
            {activeIndicator}
          </p>
        </div>
      ) : active ? (
        <>
          {/* 1. بطاقة التشخيص والتقييم الأمني الشامل (Comprehensive Security Health Overview) */}
          <div className="mt-6 rounded-2xl glass-panel p-6 border border-border/80 relative overflow-hidden">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6">
              <div className="space-y-2.5 flex-1">
                <div className="flex flex-wrap items-center gap-2.5">
                  <span className="text-xs font-mono font-bold px-2.5 py-1 rounded-md bg-primary/15 text-primary border border-primary/25 uppercase">
                    {active.type}
                  </span>
                  <h2 className="text-2xl sm:text-3xl font-bold font-mono tracking-tight text-foreground" dir="ltr">
                    {active.indicator}
                  </h2>
                  <span
                    className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold border ${
                      active.verdict === "clean"
                        ? "bg-emerald/15 text-emerald border-emerald/30"
                        : active.verdict === "suspicious"
                        ? "bg-amber/15 text-amber border-amber/30"
                        : "bg-crimson/15 text-crimson border-crimson/30"
                    }`}
                  >
                    <span className="size-2 rounded-full bg-current animate-pulse" />
                    {active.diagnosis?.statusBadge ||
                      (active.verdict === "clean"
                        ? (lang === "ar" ? "فحص معتمد وسليم" : "Certified Safe")
                        : active.verdict === "suspicious"
                        ? (lang === "ar" ? "يحتاج تدقيق وضبط إعدادات" : "Needs Configuration")
                        : (lang === "ar" ? "رصد مؤشرات خطورة" : "High Risk Flagged"))}
                  </span>
                </div>

                <p className="text-sm text-muted-foreground leading-relaxed">
                  {active.diagnosis?.summaryText ||
                    (active.verdict === "clean"
                      ? "الموقع سليم وموثوق تماماً؛ تم تدقيقه عبر أكثر من 89 محرك أمني عالمي، وشهادة التشفير صالحة، ولا توجد أي بلاغات تصيد أو برمجيات ضارة."
                      : active.verdict === "suspicious"
                      ? "الموقع يعمل ولكن يحتاج إلى مراجعة وتدقيق فني؛ تم رصد ملاحظات تتعلق بإعدادات التشفير أو السمعة أو حداثة النطاق."
                      : "تم رصد مؤشرات خطورة سيبرانية مؤكدة؛ الموقع مدرج في القوائم السوداء أو مرتبط بنشاط تصيد احتيالي أو برمجيات ضارة.")}
                </p>

                <div className="flex flex-wrap items-center gap-4 text-xs text-muted-foreground pt-1">
                  <span><strong>{lang === "ar" ? "الدولة:" : "Country:"}</strong> {active.country}</span>
                  <span>&bull;</span>
                  <span><strong>{lang === "ar" ? "السيرفر والشبكة:" : "Hosting ASN:"}</strong> {active.asn}</span>
                  <span>&bull;</span>
                  <span><strong>{lang === "ar" ? "تاريخ التدقيق:" : "Audit Time:"}</strong> {new Date(active.scannedAt).toLocaleTimeString(lang === "ar" ? "ar-YE" : "en-US")}</span>
                </div>
              </div>

              <div className="shrink-0 flex items-center justify-center lg:border-s lg:border-border/60 lg:ps-8">
                <RiskGauge score={active.riskScore} verdict={active.verdict} />
              </div>
            </div>

            {/* 2. أركان التدقيق الأمني الأربعة (The 4 Security Pillars) */}
            <div className="mt-6 pt-6 border-t border-border/60 grid gap-3.5 sm:grid-cols-2 lg:grid-cols-4">
              {/* الركن الأول: شهادة التشفير والأمان */}
              <div className="rounded-xl border border-border/70 bg-card/40 p-3.5 flex flex-col justify-between">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold text-muted-foreground flex items-center gap-1.5">
                    <Lock className="size-3.5 text-primary" />
                    {lang === "ar" ? "شهادة الأمان والتشفير" : "SSL/TLS Security"}
                  </span>
                  <span
                    className={`text-[11px] font-bold px-1.5 py-0.5 rounded ${
                      active.ssl?.valid ? "bg-emerald/15 text-emerald" : "bg-crimson/15 text-crimson"
                    }`}
                  >
                    {active.ssl?.valid ? (lang === "ar" ? "صالحة وموثقة ✅" : "Valid ✅") : (lang === "ar" ? "غير صالحة ❌" : "Untrusted ❌")}
                  </span>
                </div>
                <div>
                  <p className="text-xs font-mono font-medium truncate text-foreground">
                    {active.ssl?.issuer || "Standard TLS Certificate"}
                  </p>
                  <p className="text-[11px] text-muted-foreground mt-1">
                    {lang === "ar" ? "يضمن حماية وتشفير بيانات الزوار وكلمات المرور أثناء النقل." : "Protects in-transit visitor data and credentials."}
                  </p>
                </div>
              </div>

              {/* الركن الثاني: السمعة العالمية ومحركات الفحص */}
              <div className="rounded-xl border border-border/70 bg-card/40 p-3.5 flex flex-col justify-between">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold text-muted-foreground flex items-center gap-1.5">
                    <Shield className="size-3.5 text-primary" />
                    {lang === "ar" ? "السمعة في محركات الفحص" : "Multi-Engine Reputation"}
                  </span>
                  <span
                    className={`text-[11px] font-bold px-1.5 py-0.5 rounded ${
                      active.verdict === "clean"
                        ? "bg-emerald/15 text-emerald"
                        : active.verdict === "suspicious"
                        ? "bg-amber/15 text-amber"
                        : "bg-crimson/15 text-crimson"
                    }`}
                  >
                    {active.providers?.[0]?.detections || 0} / {active.providers?.[0]?.total || 89}
                  </span>
                </div>
                <div>
                  <p className="text-xs font-semibold text-foreground">
                    {active.verdict === "clean"
                      ? (lang === "ar" ? "نظيف في 89+ محرك فحص دولي" : "Clean across 89+ engines")
                      : (lang === "ar" ? "تم رصد بلاغات في بعض المحركات" : "Detections flagged by engines")}
                  </p>
                  <p className="text-[11px] text-muted-foreground mt-1">
                    {lang === "ar" ? "فحص فوري ضد القوائم السوداء وبلاغات الاحتيال الدولية." : "Checked against global threat blacklists and feeds."}
                  </p>
                </div>
              </div>

              {/* الركن الثالث: خادم الاستضافة والبنية التحتية */}
              <div className="rounded-xl border border-border/70 bg-card/40 p-3.5 flex flex-col justify-between">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold text-muted-foreground flex items-center gap-1.5">
                    <Server className="size-3.5 text-primary" />
                    {lang === "ar" ? "خادم ومزود الاستضافة" : "Hosting Infrastructure"}
                  </span>
                  <span className="text-[11px] font-mono text-muted-foreground">
                    {active.country}
                  </span>
                </div>
                <div>
                  <p className="text-xs font-mono font-medium truncate text-foreground">
                    {active.asn}
                  </p>
                  <p className="text-[11px] text-muted-foreground mt-1">
                    {lang === "ar" ? "الجهة المشغلة لسيرفر الموقع وموقعه الجغرافي." : "Hosting ASN provider and server location."}
                  </p>
                </div>
              </div>

              {/* الركن الرابع: ملكية وتسجيل النطاق */}
              <div className="rounded-xl border border-border/70 bg-card/40 p-3.5 flex flex-col justify-between">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold text-muted-foreground flex items-center gap-1.5">
                    <Globe className="size-3.5 text-primary" />
                    {lang === "ar" ? "هوية مالك النطاق" : "Domain Registration"}
                  </span>
                  <span className="text-[11px] font-mono text-muted-foreground">
                    WHOIS
                  </span>
                </div>
                <div>
                  <p className="text-xs font-mono font-medium truncate text-foreground">
                    {active.whois?.registrar || "Verified Entity"}
                  </p>
                  <p className="text-[11px] text-muted-foreground mt-1">
                    {lang === "ar" ? `تاريخ الحجز: ${active.whois?.created || "نشط"}` : `Registered: ${active.whois?.created || "Active"}`}
                  </p>
                </div>
              </div>
            </div>

            {/* 3. خريطة التوصيات وحلول المعالجة المتوازنة (لمسؤول الموقع وللمدير/الزائر) */}
            <div className="mt-6 pt-6 border-t border-border/60 grid gap-4 lg:grid-cols-2">
              {/* قسم مسؤول الموقع والمهندس */}
              <div className="rounded-xl border border-border/70 bg-card/30 p-4">
                <h4 className="text-xs font-bold uppercase tracking-wider text-primary mb-3 flex items-center gap-2">
                  <Wrench className="size-4" />
                  {lang === "ar" ? "لمسؤول الموقع والمهندس (خطوات المعالجة والضبط الفني):" : "For Webmasters & Developers (Remediation Plan):"}
                </h4>
                <ul className="space-y-2.5 text-xs">
                  {(active.diagnosis?.engineerNotes && active.diagnosis.engineerNotes.length > 0
                    ? active.diagnosis.engineerNotes
                    : active.recommendations || []
                  ).map((note, idx) => (
                    <li key={idx} className="flex items-start gap-2.5">
                      <CheckCircle2 className="size-3.5 text-primary shrink-0 mt-0.5" />
                      <span className="text-foreground leading-relaxed">{note}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* قسم المدير والموظف والزائر */}
              <div className="rounded-xl border border-border/70 bg-card/30 p-4">
                <h4 className="text-xs font-bold uppercase tracking-wider text-emerald mb-3 flex items-center gap-2">
                  <Briefcase className="size-4" />
                  {lang === "ar" ? "للمدير والموظف الإداري والعميل (إرشادات الاستخدام والتعامل):" : "For Executives & Users (Safe Usage Guidelines):"}
                </h4>
                <ul className="space-y-2.5 text-xs">
                  {(active.diagnosis?.visitorNotes && active.diagnosis.visitorNotes.length > 0
                    ? active.diagnosis.visitorNotes
                    : [
                        lang === "ar" ? "الموقع آمن تماماً للاستخدام والتصفح وإجراء المعاملات بثقة." : "The site is safe for official browsing and transactions.",
                        lang === "ar" ? "اتصالك بالموقع مشفر ومحمي من أي تنصت أو تسريب للبيانات." : "Your connection is encrypted and protected.",
                      ]
                  ).map((note, idx) => (
                    <li key={idx} className="flex items-start gap-2.5">
                      <ShieldCheck className="size-3.5 text-emerald shrink-0 mt-0.5" />
                      <span className="text-foreground leading-relaxed">{note}</span>
                    </li>
                  ))}
                </ul>
              </div>
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
                 <img
                   src={active.screenshotUrl}
                   alt="Secure Render"
                   className="w-full h-full object-cover blur-[1px] opacity-80 group-hover:blur-none group-hover:opacity-100 transition-all duration-500"
                   onError={(e) => {
                     // Graceful fallback for offline / blocked hosts
                     (e.target as HTMLElement).style.display = "none";
                   }}
                 />
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
             <ThreatGraph
               indicator={active.indicator}
               type={active.type}
               verdict={active.verdict}
               classification={active.classification}
               mitreTactic={active.mitreTactic}
               asn={active.asn}
               country={active.country}
             />
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
                    <th className="py-3 px-4 text-end font-medium">{lang === "ar" ? "الإجراءات" : "Actions"}</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => {
                    const isActive = r.indicator.trim().toLowerCase() === activeIndicator.trim().toLowerCase();
                    return (
                      <tr
                        key={r.id}
                        onClick={() => handleSelectTarget(r.indicator)}
                        className={`border-b border-border/40 transition-colors cursor-pointer group ${
                          isActive
                            ? "bg-primary/10 border-s-4 border-s-primary"
                            : "hover:bg-muted/40"
                        }`}
                      >
                        <td className="py-3 px-4 text-start">
                          <div className="flex items-center gap-2">
                            <span
                              className={`font-mono text-xs font-semibold px-2.5 py-1 rounded border inline-block max-w-[280px] truncate transition-colors ${
                                isActive
                                  ? "bg-primary/20 text-primary border-primary/50"
                                  : "bg-muted/40 border-border/60 group-hover:border-primary/50"
                              }`}
                              dir="ltr"
                            >
                              {r.indicator}
                            </span>
                            {isActive && (
                              <span className="inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-full bg-primary/20 text-primary border border-primary/30 shrink-0">
                                <span className="size-1.5 rounded-full bg-primary animate-pulse" />
                                {lang === "ar" ? "الهدف النشط" : "Active"}
                              </span>
                            )}
                          </div>
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
                        <td className="py-3 px-4 text-end" onClick={(e) => e.stopPropagation()}>
                          <div className="flex items-center justify-end gap-1">
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => handleSelectTarget(r.indicator)}
                              className={`size-8 ${isActive ? "text-primary bg-primary/10" : "hover:text-primary"}`}
                              title={lang === "ar" ? "فحص وتحليل هذا الموقع في اللوحة كاملة" : "Analyze in Dashboard"}
                            >
                              <Activity className="size-4" />
                              <span className="sr-only">Analyze</span>
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => setSelectedScan(r)}
                              className="size-8 hover:text-primary"
                              title={lang === "ar" ? "عرض تفاصيل الفحص كاملة" : "View scan details"}
                            >
                              <Eye className="size-4" />
                              <span className="sr-only">Details</span>
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => exportPdfReport(r)}
                              className="size-8 hover:text-primary"
                              title={lang === "ar" ? "تحميل تقرير أمني PDF مع الشعار والتوصيات" : "Export Security PDF Report"}
                            >
                              <FileText className="size-4" />
                              <span className="sr-only">PDF</span>
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => handleSendToWhatsApp(r)}
                              className="size-8 hover:text-emerald"
                              title={lang === "ar" ? "إرسال ملخص التقرير إلى واتساب" : "Send report to WhatsApp"}
                            >
                              <Send className="size-3.5" />
                              <span className="sr-only">WhatsApp</span>
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => copy(r.indicator)}
                              className="size-8"
                              title={t("copy")}
                            >
                              <Copy className="size-3.5" />
                              <span className="sr-only">{t("copy")}</span>
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={(e) => handleDeleteScan(r, e)}
                              className="size-8 text-muted-foreground hover:text-destructive hover:bg-destructive/10"
                              title={lang === "ar" ? "حذف نهائي من السجل" : "Delete scan"}
                            >
                              <Trash2 className="size-4" />
                              <span className="sr-only">Delete</span>
                            </Button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <div className="space-y-3 md:hidden">
              {rows.map((r) => {
                const isActive = r.indicator.trim().toLowerCase() === activeIndicator.trim().toLowerCase();
                return (
                  <div
                    key={r.id}
                    onClick={() => handleSelectTarget(r.indicator)}
                    className={`rounded-xl border p-3.5 cursor-pointer transition-colors ${
                      isActive
                        ? "border-primary/60 bg-primary/5 shadow-sm"
                        : "border-border bg-card/60 hover:border-primary/40"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-1.5 truncate">
                        <p className="truncate font-mono text-xs font-semibold text-primary" dir="ltr">
                          {r.indicator}
                        </p>
                        {isActive && (
                          <span className="text-[10px] font-bold px-1.5 py-0.2 rounded bg-primary/20 text-primary border border-primary/30 shrink-0">
                            {lang === "ar" ? "النشط" : "Active"}
                          </span>
                        )}
                      </div>
                      <span
                        className={`font-mono text-xs font-bold px-2 py-0.5 rounded shrink-0 ${
                          r.riskScore > 70
                            ? "bg-crimson/15 text-crimson"
                            : r.riskScore > 30
                            ? "bg-amber/15 text-amber"
                            : "bg-emerald/15 text-emerald"
                        }`}
                      >
                        {r.riskScore}/100
                      </span>
                    </div>
                    <div className="mt-2.5 flex items-center gap-2">
                      <VerdictBadge verdict={r.verdict} />
                      <span className="text-xs text-muted-foreground">{r.country}</span>
                      <div className="ms-auto flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-8 text-primary"
                          onClick={() => handleSelectTarget(r.indicator)}
                          title={lang === "ar" ? "فحص في اللوحة" : "Analyze"}
                        >
                          <Activity className="size-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-8 text-muted-foreground hover:text-foreground"
                          onClick={() => setSelectedScan(r)}
                          title={lang === "ar" ? "عرض التفاصيل" : "Details"}
                        >
                          <Eye className="size-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-8 text-emerald"
                          onClick={() => handleSendToWhatsApp(r)}
                          title="WhatsApp"
                        >
                          <Send className="size-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-8"
                          onClick={() => exportPdfReport(r)}
                          title="PDF"
                        >
                          <FileText className="size-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-8 text-destructive"
                          onClick={(e) => handleDeleteScan(r, e)}
                          title="Delete"
                        >
                          <Trash2 className="size-4" />
                        </Button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </>
        )}
      </section>

      {/* نافذة التفاصيل المنبثقة لكل موقع / فحص */}
      <Dialog open={Boolean(selectedScan)} onOpenChange={(open) => !open && setSelectedScan(null)}>
        {selectedScan && (
          <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto p-6">
            <DialogHeader className="border-b border-border pb-4">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold px-2 py-0.5 rounded bg-primary/10 text-primary border border-primary/20 uppercase">
                      {selectedScan.type}
                    </span>
                    <DialogTitle className="text-xl font-bold font-mono text-foreground" dir="ltr">
                      {selectedScan.indicator}
                    </DialogTitle>
                  </div>
                  <DialogDescription className="mt-1 text-xs text-muted-foreground flex items-center gap-2">
                    <span>{selectedScan.country}</span>
                    <span>&bull;</span>
                    <span>{selectedScan.asn}</span>
                    <span>&bull;</span>
                    <span>{new Date(selectedScan.scannedAt).toLocaleString(lang === "ar" ? "ar-YE" : "en-GB")}</span>
                  </DialogDescription>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <VerdictBadge verdict={selectedScan.verdict} />
                  <span
                    className={`font-mono text-sm font-bold px-2.5 py-1 rounded-md ${
                      selectedScan.riskScore > 70
                        ? "bg-crimson/15 text-crimson border border-crimson/30"
                        : selectedScan.riskScore > 30
                        ? "bg-amber/15 text-amber border border-amber/30"
                        : "bg-emerald/15 text-emerald border border-emerald/30"
                    }`}
                  >
                    {selectedScan.riskScore}/100
                  </span>
                </div>
              </div>
            </DialogHeader>

            <div className="space-y-6 pt-4">
              {/* تصنيف التهديد و MITRE */}
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="rounded-xl border border-border/70 bg-card/50 p-4">
                  <p className="text-xs font-semibold text-muted-foreground mb-1">
                    {lang === "ar" ? "تصنيف التهديد" : "Threat Classification"}
                  </p>
                  <p className="text-base font-bold text-foreground">
                    {selectedScan.classification || "Standard Target Analysis"}
                  </p>
                </div>
                <div className="rounded-xl border border-border/70 bg-card/50 p-4">
                  <p className="text-xs font-semibold text-muted-foreground mb-1">
                    {lang === "ar" ? "تكتيك MITRE ATT&CK" : "MITRE ATT&CK Tactic"}
                  </p>
                  <p className="text-sm font-mono font-medium text-foreground">
                    {selectedScan.mitreTactic || "Reconnaissance / Initial Access"}
                  </p>
                </div>
              </div>

              {/* لقطة الشاشة الآمنة إن وجدت */}
              {selectedScan.screenshotUrl && (
                <div className="rounded-xl border border-border/70 overflow-hidden bg-muted/20">
                  <div className="px-4 py-2 bg-muted/40 border-b border-border text-xs font-semibold flex items-center justify-between">
                    <span className="flex items-center gap-1.5">
                      <ImageIcon className="size-3.5" />
                      {lang === "ar" ? "لقطة الشاشة الآمنة في بيئة معزولة" : "Sandboxed Screenshot"}
                    </span>
                    <span className="text-[10px] text-emerald font-mono">Isolated Render</span>
                  </div>
                  <div className="max-h-60 overflow-hidden bg-background flex items-center justify-center">
                    <img
                      src={selectedScan.screenshotUrl}
                      alt={selectedScan.indicator}
                      className="w-full object-cover max-h-60 hover:scale-105 transition-transform duration-300"
                      onError={(e) => {
                        (e.target as HTMLElement).style.display = "none";
                      }}
                    />
                  </div>
                </div>
              )}

              {/* محركات الفحص والاستخبارات Multi-Engine */}
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
                  <Shield className="size-3.5 text-primary" />
                  {lang === "ar" ? "محركات الفحص العالمية (VirusTotal v3 & OSINT)" : "Detection Engines"}
                </h4>
                <div className="grid gap-2 sm:grid-cols-2">
                  {selectedScan.providers.map((p) => (
                    <div
                      key={p.name}
                      className="flex items-center justify-between rounded-lg border border-border/60 bg-muted/20 px-3 py-2 text-xs"
                    >
                      <span className="font-semibold">{p.name}</span>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-muted-foreground">
                          {p.detections}/{p.total}
                        </span>
                        <span
                          className={`font-semibold uppercase text-[11px] px-1.5 py-0.5 rounded ${
                            p.verdict === "clean"
                              ? "bg-emerald/15 text-emerald"
                              : p.verdict === "suspicious"
                              ? "bg-amber/15 text-amber"
                              : "bg-crimson/15 text-crimson"
                          }`}
                        >
                          {p.verdict}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* تفاصيل WHOIS و SSL */}
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
                  <Globe className="size-3.5 text-primary" />
                  {lang === "ar" ? "بيانات النطاق والشهادة الرقمية" : "Infrastructure & Certificates"}
                </h4>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                  <div className="rounded-lg border border-border/60 bg-muted/20 p-2.5">
                    <span className="text-[10px] text-muted-foreground block">Registrar</span>
                    <span className="font-semibold font-mono truncate block mt-0.5">
                      {selectedScan.whois?.registrar || "Verified"}
                    </span>
                  </div>
                  <div className="rounded-lg border border-border/60 bg-muted/20 p-2.5">
                    <span className="text-[10px] text-muted-foreground block">SSL Issuer</span>
                    <span className="font-semibold font-mono truncate block mt-0.5">
                      {selectedScan.ssl?.issuer || "Trusted TLS"}
                    </span>
                  </div>
                  <div className="rounded-lg border border-border/60 bg-muted/20 p-2.5">
                    <span className="text-[10px] text-muted-foreground block">Registration</span>
                    <span className="font-mono truncate block mt-0.5">
                      {selectedScan.whois?.created || "Active"}
                    </span>
                  </div>
                  <div className="rounded-lg border border-border/60 bg-muted/20 p-2.5">
                    <span className="text-[10px] text-muted-foreground block">SSL Status</span>
                    <span className="font-semibold block mt-0.5 text-emerald">
                      {selectedScan.ssl?.valid ? "Valid ✅" : "Untrusted ❌"}
                    </span>
                  </div>
                </div>
              </div>

              {/* التوصيات الفورية الخاصة بهذا الموقع تحديداً */}
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
                  <AlertTriangle className="size-3.5 text-amber" />
                  {lang === "ar"
                    ? `توصيات أمنية مخصصة لـ (${selectedScan.indicator})`
                    : `Actionable Recommendations for (${selectedScan.indicator})`}
                </h4>
                <div className="rounded-xl border border-border/70 bg-card/40 p-3.5 space-y-2">
                  {selectedScan.recommendations && selectedScan.recommendations.length > 0 ? (
                    selectedScan.recommendations.map((rec, i) => (
                      <div key={i} className="flex items-start gap-2.5 text-xs">
                        <CheckCircle2 className="size-4 text-emerald shrink-0 mt-0.5" />
                        <span className="text-foreground leading-relaxed">{rec}</span>
                      </div>
                    ))
                  ) : (
                    <p className="text-xs text-muted-foreground">
                      {lang === "ar" ? "لا توجد توصيات إضافية مطلوبة." : "No specific recommendations required."}
                    </p>
                  )}
                </div>
              </div>

              {/* أزرار الإجراءات في أسفل النافذة */}
              <div className="flex flex-wrap items-center justify-between gap-2 pt-4 border-t border-border">
                <div className="flex items-center gap-2">
                  <Button
                    variant="default"
                    size="sm"
                    className="bg-emerald hover:bg-emerald/90 text-white font-medium text-xs shadow-md"
                    disabled={sendingWa}
                    onClick={() => handleSendToWhatsApp(selectedScan)}
                  >
                    <Send className="size-3.5 me-1.5" />
                    {sendingWa
                      ? (lang === "ar" ? "جاري الإرسال..." : "Sending...")
                      : (lang === "ar" ? "إرسال إلى WhatsApp 📲" : "Send to WhatsApp")}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    className="text-xs font-medium"
                    onClick={() => exportPdfReport(selectedScan)}
                  >
                    <FileText className="size-3.5 me-1.5" />
                    {lang === "ar" ? "تحميل تقرير أمني PDF" : "Export PDF Report"}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    className="text-xs font-medium"
                    onClick={() => {
                      setSelectedScan(null);
                      navigate({ to: "/dashboard", search: { q: selectedScan.indicator } });
                    }}
                  >
                    <ExternalLink className="size-3.5 me-1.5" />
                    {lang === "ar" ? "فتح في شاشة التحليل" : "Analyze in Dashboard"}
                  </Button>
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    variant="destructive"
                    size="sm"
                    className="text-xs font-medium"
                    onClick={() => handleDeleteScan(selectedScan)}
                  >
                    <Trash2 className="size-3.5 me-1.5" />
                    {lang === "ar" ? "حذف من السجل" : "Delete"}
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-xs"
                    onClick={() => setSelectedScan(null)}
                  >
                    {lang === "ar" ? "إغلاق" : "Close"}
                  </Button>
                </div>
              </div>
            </div>
          </DialogContent>
        )}
      </Dialog>
    </div>
  );
}
