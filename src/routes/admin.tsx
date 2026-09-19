import { createFileRoute, Link } from "@tanstack/react-router";
import {
  AlertTriangle,
  CheckCircle2,
  KeyRound,
  Lock,
  MessageCircle,
  Radio,
  Send,
  ShieldAlert,
  Siren,
  Terminal,
  Users,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useAuth } from "@/contexts/AuthContext";
import { useLanguage } from "@/contexts/LanguageContext";
import { threatService } from "@/services/threatService";
import type { LogEntry } from "@/types";

import { supabase } from "@/lib/supabase";

export const Route = createFileRoute("/admin")({
  head: () => ({
    meta: [
      { title: "SOC Admin — ThreatPulse CTI" },
      { name: "description", content: "SOC operations console: live threat log stream, WhatsApp alert gateway status, API keys and user management." },
    ],
  }),
  component: AdminPage,
});

const levelStyle: Record<LogEntry["level"], string> = {
  info: "text-muted-foreground",
  warn: "text-amber",
  critical: "text-crimson",
};

function AdminPage() {
  const { t } = useLanguage();
  const { user, ready } = useAuth();
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [integrations, setIntegrations] = useState<{ id: string; name: string; api_key: string | null }[]>([]);
  const [users, setUsers] = useState<any[]>([]);
  const streamRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (user?.role === "admin") {
      // Fetch integrations
      supabase.from("integrations").select("*").order("name").then(({ data }) => {
        if (data) setIntegrations(data);
      });
      // Fetch users (profiles)
      supabase.from("profiles").select("*").then(({ data }) => {
         if (data) setUsers(data);
      });
    }

    // Load initial real SOC logs
    threatService.getLiveSocLogs().then((realLogs) => {
      setLogs(realLogs);
    });

    // Realtime subscription for incoming live scans
    const channel = supabase
      .channel("admin-live-scans")
      .on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "scans" },
        (payload) => {
          const scan = payload.new as any;
          const level: LogEntry["level"] =
            scan.status === "malicious"
              ? "critical"
              : scan.status === "suspicious"
              ? "warn"
              : "info";
          const newEntry: LogEntry = {
            id: `rt_${scan.id}_${Date.now()}`,
            time: scan.created_at || new Date().toISOString(),
            level,
            source: "VirusTotal Live",
            message: `Live Scan Event: ${scan.target} analyzed (Risk: ${scan.risk_score}/100 - ${String(scan.status).toUpperCase()})`,
          };
          setLogs((prev) => [...prev.slice(-40), newEntry]);
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [user]);

  useEffect(() => {
    streamRef.current?.scrollTo({ top: streamRef.current.scrollHeight, behavior: "smooth" });
  }, [logs]);

  const saveIntegration = async (id: string, key: string) => {
    const isActive = key.trim().length > 0;
    const { error } = await supabase
      .from("integrations")
      .update({ api_key: key.trim(), is_active: isActive })
      .eq("id", id);

    if (error) {
       toast.error(error.message);
    } else {
       setIntegrations(prev => prev.map(x => x.id === id ? { ...x, is_active: isActive } : x));
       toast.success(t("save") + " " + "successful");
    }
  };

  // Emergency Alert Broadcast State
  const [emergencyTitle, setEmergencyTitle] = useState("رصد هجوم سيبراني طارئ (Critical Security Incident)");
  const [emergencyIndicator, setEmergencyIndicator] = useState("");
  const [emergencySeverity, setEmergencySeverity] = useState<"critical" | "high">("critical");
  const [emergencyDesc, setEmergencyDesc] = useState(
    "تم رصد نشاط هجومي عدائي يستهدف خوادم المنظومة. يرجى تفعيل بروتوكول العزل ومراجعة سجلات الجلسات فوراً."
  );
  const [emergencyRecs, setEmergencyRecs] = useState("حظر المؤشر في جدار الحماية فوراً, تفعيل التحقق بخطوتين 2FA, عزل الأجهزة المشبوهة");
  const [emergencyTarget, setEmergencyTarget] = useState<"all" | "self">("all");
  const [broadcasting, setBroadcasting] = useState(false);

  const emergencyTemplates = [
    {
      label: "🔴 هجوم فدية نشط (Ransomware)",
      title: "رصد هجوم برمجيات فدية نشط (Ransomware Outbreak)",
      indicator: "c2-ransom-payload.darknet",
      severity: "critical" as const,
      desc: "تم رصد محاولات تشفير خبيثة وتواصل مع خوادم فدية خارجية. يرجى عزل نقاط النهاية والتحقق من النسخ الاحتياطية فوراً.",
      recs: "عزل الخوادم المتضررة فوراً, تعطيل مشاركة الملفات SMB, التحقق من سلامة النسخ الاحتياطية",
    },
    {
      label: "🛑 اختراق C2 Server",
      title: "رصد اتصال نشط مع خادم تحكم C2 خبيث",
      indicator: "185.220.101.44",
      severity: "critical" as const,
      desc: "اكتشاف تدفق بيانات غير مصرح به نحو عنوان C2 معروف بتسريب البيانات. يرجى حظر المنفذ وفحص حركة الشبكة فوراً.",
      recs: "حظر عنوان IP في جدار الحماية, إيقاف الجلسات النشطة فوراً, فحص حركة بيانات DNS",
    },
    {
      label: "⚠️ حملة تصيد جماعية (Phishing)",
      title: "حملة تصيد احتيالي تستهدف بيانات الحسابات",
      indicator: "secure-login-verify-account.tk",
      severity: "high" as const,
      desc: "رصد رسائل ونطاقات تصيد احتيالي تحاكي بوابة تسجيل الدخول لسرقة بيانات الاعتماد. يرجى تنبيه المستخدمين بعدم التفاعل.",
      recs: "حظر النطاق في نظام حماية البريد, تفعيل 2FA لجميع الحسابات, إعادة ضبط كلمات المرور المشتبه بها",
    },
    {
      label: "⚡ ثغرة Zero-Day حرجة",
      title: "تنبيه استغلال ثغرة أمنية غير معلنة (Zero-Day Exploit)",
      indicator: "CVE-2026-EMERGENCY",
      severity: "critical" as const,
      desc: "رصد محاولات تنفيذ كود عن بُعد RCE تستهدف خوادم المنظومة عبر ثغرة غير معلنة. يرجى تطبيق التدابير المؤقتة فوراً.",
      recs: "إيقاف المنافذ والخدمات غير الضرورية, تفعيل نظام كشف التسلل IDS/IPS, مراجعة مسارات الصلاحيات",
    },
  ];

  const applyTemplate = (tmpl: (typeof emergencyTemplates)[0]) => {
    setEmergencyTitle(tmpl.title);
    setEmergencyIndicator(tmpl.indicator);
    setEmergencySeverity(tmpl.severity);
    setEmergencyDesc(tmpl.desc);
    setEmergencyRecs(tmpl.recs);
    toast.info(`تم تطبيق نموذج: ${tmpl.label}`);
  };

  const handleBroadcastEmergency = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!emergencyTitle.trim() || !emergencyDesc.trim()) {
      toast.error("يرجى كتابة عنوان ووصف الحالة الطارئة.");
      return;
    }

    setBroadcasting(true);
    try {
      const recsArray = emergencyRecs
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);

      const targetPhone = emergencyTarget === "self" ? user?.phone : undefined;

      const res = await threatService.broadcastEmergencyAlert({
        title: emergencyTitle,
        indicator: emergencyIndicator.trim() || undefined,
        severity: emergencySeverity,
        description: emergencyDesc,
        recommendations: recsArray,
        directPhone: targetPhone,
      });

      if (res.sent) {
        toast.success(
          `🚨 تم بث الإنذار الطارئ بنجاح عبر WhatsApp إلى ${res.count} ${
            emergencyTarget === "self" ? "هاتفك كمدير" : "محلل ومستخدم"
          }!`
        );
        // Add entry to live SOC logs
        setLogs((prev) => [
          ...prev,
          {
            id: `log-${Date.now()}`,
            time: new Date().toISOString(),
            level: "critical",
            source: "SOC Admin",
            message: `Emergency broadcast dispatched: "${emergencyTitle}" (${res.count}/${res.total} WhatsApp delivered)`,
          },
        ]);
      } else {
        if (res.reason === "no_recipient_phone") {
          toast.error("لا يوجد أي رقم هاتف مفعل لاستلام التنبيهات.");
        } else if (res.reason === "zavu_key_not_configured") {
          toast.error("مفتاح Zavu غير مهيأ بعد. يرجى إدخال المفتاح وحفظه أولاً.");
        } else {
          toast.error(`فشل بث التنبيه: ${res.reason}`);
        }
      }
    } finally {
      setBroadcasting(false);
    }
  };

  const activeSubscribersCount = users.filter(
    (u) => u.whatsapp_alerts_enabled && u.whatsapp_number
  ).length;

  const [testingWa, setTestingWa] = useState(false);

  const testWhatsAppAlert = async () => {
    setTestingWa(true);
    try {
      const sampleScan = {
        id: "test-emergency",
        indicator: "185.220.101.44",
        type: "ip" as const,
        riskScore: 88,
        verdict: "malicious" as const,
        scannedAt: new Date().toISOString(),
        country: "DE",
        asn: "AS201814",
        categories: ["c2-server", "malware"],
        providers: [],
        classification: "Command & Control (C2) Server / Test",
        mitreTactic: "T1071 - Application Layer Protocol",
        recommendations: [
          "حظر العنوان فوراً في جدار الحماية وعزل الأجهزة المتصلة.",
          "تحليل تدفق حركة الشبكة لكشف تسريب البيانات.",
        ],
      };
      const res = await threatService.dispatchWhatsAppAlert(sampleScan, user?.phone || undefined);
      if (res.sent) {
        toast.success("تم إرسال التنبيه الأمني التجريبي عبر WhatsApp بنجاح! 📲");
        setLogs((prev) => [
          ...prev,
          {
            id: `test-log-${Date.now()}`,
            time: new Date().toISOString(),
            level: "warn",
            source: "SOC Diagnostics",
            message: `Diagnostic alert dispatched: Test IOC incident sent to admin phone (${user?.phone || "registered admin"})`,
          },
        ]);
      } else if (res.reason === "zavu_key_not_configured") {
        toast.error("مفتاح Zavu غير مهيأ بعد. يرجى إدخال المفتاح وحفظه أولاً.");
      } else if (res.reason === "no_recipient_phone") {
        toast.error("رقم هاتفك كمدير غير مفعل للتنبيهات في ملفك الشخصي.");
      } else {
        toast.error(`فشل الإرسال: ${res.reason}`);
      }
    } finally {
      setTestingWa(false);
    }
  };

  if (ready && (!user || user.role !== "admin")) {
    return (
      <div className="mx-auto flex max-w-md flex-col items-center gap-4 px-4 py-24 text-center">
        <Lock className="size-8 text-primary" />
        <p className="text-sm text-muted-foreground">{t("admin_only")}</p>
        <Button asChild>
          <Link to="/">{t("nav_home")}</Link>
        </Button>
      </div>
    );
  }

  return (
    <div className="mx-auto w-full max-w-[1600px] px-4 py-10 sm:px-6">
      <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">{t("nav_admin")}</h1>

      <div className="mt-6 grid gap-4 xl:grid-cols-[1.4fr_1fr]">
        <section className="glass-panel rounded-2xl p-5">
          <div className="flex items-center gap-2">
            <Terminal className="size-4 text-primary" />
            <p className="text-sm font-semibold">{t("live_log")}</p>
            <span className="ms-auto size-2 animate-blink rounded-full bg-emerald" />
          </div>
          <div
            ref={streamRef}
            dir="ltr"
            className="scanline mt-4 h-80 overflow-y-auto rounded-xl border border-border bg-background/70 p-3 font-mono text-xs leading-relaxed"
          >
            {logs.length === 0 && <p className="text-muted-foreground">booting sensors…</p>}
            {logs.map((l) => (
              <p key={l.id} className={levelStyle[l.level]}>
                <span className="text-muted-foreground">
                  [{new Date(l.time).toLocaleTimeString("en-GB")}]
                </span>{" "}
                <span className="uppercase">{l.level}</span> {l.source} — {l.message}
              </p>
            ))}
          </div>
        </section>

        <div className="space-y-4">
          <section className="glass-panel rounded-2xl p-5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <MessageCircle className="size-4 text-emerald" />
                <p className="text-sm font-semibold">بوابة تنبيهات Zavu WhatsApp</p>
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={testWhatsAppAlert}
                disabled={testingWa}
                className="text-xs h-8"
              >
                {testingWa ? "جاري الإرسال..." : "إرسال تنبيه تجريبي 📲"}
              </Button>
            </div>
            <div className="mt-4 flex items-end gap-3">
              <CheckCircle2 className="size-5 text-emerald" />
              <div>
                <p className="font-mono text-xl font-bold text-emerald">Active & Armed</p>
                <p className="text-xs text-muted-foreground">إرسال تلقائي عند رصد تهديد حرج (Risk &gt; 70)</p>
              </div>
            </div>
          </section>

          <section className="glass-panel rounded-2xl p-5">
            <div className="flex items-center gap-2">
              <KeyRound className="size-4 text-primary" />
              <p className="text-sm font-semibold">{t("api_keys")}</p>
            </div>
            <div className="mt-4 space-y-4">
              {integrations.map((integ: any) => (
                <div key={integ.id} className="space-y-1.5 flex flex-col p-3 rounded-xl border border-border bg-card/40">
                  <div className="flex items-center justify-between">
                    <Label htmlFor={integ.id} className="font-semibold text-sm">{integ.name}</Label>
                    <span className={`text-[10px] px-2 py-0.5 rounded-full border ${integ.api_key ? 'bg-emerald/10 border-emerald/30 text-emerald' : 'bg-muted border-border text-muted-foreground'}`}>
                      {integ.api_key ? "Connected" : "Not Set"}
                    </span>
                  </div>
                  <div className="flex gap-2 mt-1">
                    <Input
                      id={integ.id}
                      dir="ltr"
                      type="password"
                      placeholder="Enter API key or token..."
                      value={integ.api_key || ""}
                      onChange={(e) => setIntegrations(p => p.map(x => x.id === integ.id ? { ...x, api_key: e.target.value } : x))}
                    />
                    <Button variant="outline" size="sm" onClick={() => saveIntegration(integ.id, integ.api_key || "")}>
                      {t("save")}
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          </section>
        </div>
      </div>

      {/* 🚨 مركز بث الحالات الطارئة عبر WhatsApp */}
      <section className="glass-panel mt-6 rounded-2xl border border-crimson/30 p-6 bg-gradient-to-b from-crimson/5 to-transparent">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border/60 pb-4">
          <div className="flex items-center gap-3">
            <div className="flex size-11 items-center justify-center rounded-xl bg-crimson/15 text-crimson ring-1 ring-crimson/30">
              <Siren className="size-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold tracking-tight text-foreground">
                  مركز بث الحالات الطارئة عبر WhatsApp
                </h2>
                <span className="rounded-full border border-crimson/40 bg-crimson/15 px-2.5 py-0.5 text-[11px] font-semibold text-crimson">
                  Emergency SOC Dispatcher
                </span>
              </div>
              <p className="text-xs text-muted-foreground mt-0.5">
                إرسال إنذار أمني فوري ومباشر إلى هواتف جميع المحللين والمستخدمين المفعّلين للتنبيهات عند رصد حادث طارئ
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 rounded-xl border border-border bg-card/60 px-3.5 py-2 text-xs">
            <Users className="size-4 text-emerald" />
            <span className="text-muted-foreground">المشتركون الجاهزون للاستلام:</span>
            <span className="font-mono font-bold text-emerald text-sm">{activeSubscribersCount} مشترك</span>
          </div>
        </div>

        {/* النماذج السريعة للطوارئ */}
        <div className="mt-4">
          <p className="text-xs font-medium text-muted-foreground mb-2 flex items-center gap-1.5">
            <Radio className="size-3.5 text-primary" />
            نماذج طوارئ سريعة جاهزة (انقر لتعبئة التنبيه فوراً):
          </p>
          <div className="flex flex-wrap gap-2">
            {emergencyTemplates.map((tmpl) => (
              <button
                key={tmpl.label}
                type="button"
                onClick={() => applyTemplate(tmpl)}
                className="rounded-lg border border-border bg-secondary/50 px-3 py-1.5 text-xs font-medium text-foreground transition-all hover:border-primary/50 hover:bg-secondary cursor-pointer"
              >
                {tmpl.label}
              </button>
            ))}
          </div>
        </div>

        {/* نموذج البث */}
        <form onSubmit={handleBroadcastEmergency} className="mt-5 space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-1.5">
              <Label className="text-xs font-semibold">عنوان الحالة الطارئة (Incident Title) *</Label>
              <Input
                value={emergencyTitle}
                onChange={(e) => setEmergencyTitle(e.target.value)}
                placeholder="مثال: رصد هجوم فدية نشط..."
                required
                className="bg-background/60"
              />
            </div>

            <div className="space-y-1.5">
              <Label className="text-xs font-semibold">المؤشر أو الهدف المشبوه (Indicator - IP / Domain / Hash)</Label>
              <Input
                dir="ltr"
                value={emergencyIndicator}
                onChange={(e) => setEmergencyIndicator(e.target.value)}
                placeholder="مثال: 185.220.101.44 أو malware-domain.com"
                className="bg-background/60 font-mono text-xs"
              />
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-1.5">
              <Label className="text-xs font-semibold">مستوى خطورة الحالة (Severity Level)</Label>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setEmergencySeverity("critical")}
                  className={`flex-1 rounded-lg border px-3 py-2 text-xs font-semibold transition-all cursor-pointer ${
                    emergencySeverity === "critical"
                      ? "border-crimson bg-crimson/15 text-crimson ring-1 ring-crimson/40"
                      : "border-border bg-card/40 text-muted-foreground hover:bg-card/70"
                  }`}
                >
                  🔴 حرج جداً (Critical Incident)
                </button>
                <button
                  type="button"
                  onClick={() => setEmergencySeverity("high")}
                  className={`flex-1 rounded-lg border px-3 py-2 text-xs font-semibold transition-all cursor-pointer ${
                    emergencySeverity === "high"
                      ? "border-amber bg-amber/15 text-amber ring-1 ring-amber/40"
                      : "border-border bg-card/40 text-muted-foreground hover:bg-card/70"
                  }`}
                >
                  🟠 مرتفع (High Risk)
                </button>
              </div>
            </div>

            <div className="space-y-1.5">
              <Label className="text-xs font-semibold">وجهة الإرسال (Target Audience)</Label>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => setEmergencyTarget("all")}
                  className={`flex-1 rounded-lg border px-3 py-2 text-xs font-semibold transition-all cursor-pointer ${
                    emergencyTarget === "all"
                      ? "border-primary bg-primary/15 text-primary ring-1 ring-primary/40"
                      : "border-border bg-card/40 text-muted-foreground hover:bg-card/70"
                  }`}
                >
                  📡 بث للجميع ({activeSubscribersCount} مشترك)
                </button>
                <button
                  type="button"
                  onClick={() => setEmergencyTarget("self")}
                  className={`flex-1 rounded-lg border px-3 py-2 text-xs font-semibold transition-all cursor-pointer ${
                    emergencyTarget === "self"
                      ? "border-primary bg-primary/15 text-primary ring-1 ring-primary/40"
                      : "border-border bg-card/40 text-muted-foreground hover:bg-card/70"
                  }`}
                >
                  🎯 لهاتفي كمدير فقط (تجربة)
                </button>
              </div>
            </div>
          </div>

          <div className="space-y-1.5">
            <Label className="text-xs font-semibold">تفاصيل الحالة الطارئة وتوجيهات الاستجابة *</Label>
            <Textarea
              rows={3}
              value={emergencyDesc}
              onChange={(e) => setEmergencyDesc(e.target.value)}
              placeholder="اكتب تفاصيل التهديد والإرشادات التي ستصل للجميع على الواتساب..."
              required
              className="bg-background/60 text-sm leading-relaxed"
            />
          </div>

          <div className="space-y-1.5">
            <Label className="text-xs font-semibold">التوصيات الدفاعية السريعة (افصل بينها بفاصلة)</Label>
            <Input
              value={emergencyRecs}
              onChange={(e) => setEmergencyRecs(e.target.value)}
              placeholder="عزل الخوادم فوراً, حظر عنوان IP, تفعيل التحقق بخطوتين"
              className="bg-background/60 text-xs"
            />
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
            <p className="text-[11px] text-muted-foreground flex items-center gap-1.5">
              <ShieldAlert className="size-3.5 text-crimson" />
              سيتم إرسال الإنذار بشكل فوري عبر بوابة Zavu WhatsApp بصيغة مشفرة وواضحة لجميع الهواتف المحددة.
            </p>

            <Button
              type="submit"
              disabled={broadcasting}
              className="bg-crimson text-white hover:bg-crimson/90 font-bold px-6 py-2.5 gap-2 shadow-lg shadow-crimson/20 cursor-pointer text-sm"
            >
              {broadcasting ? (
                <>
                  <span className="size-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
                  جاري البث والاتصال...
                </>
              ) : (
                <>
                  <Send className="size-4" />
                  {emergencyTarget === "all"
                    ? `🚨 بث التنبيه الطارئ لجميع المشتركين (${activeSubscribersCount})`
                    : "📲 إرسال التنبيه الطارئ لهاتفي"}
                </>
              )}
            </Button>
          </div>
        </form>
      </section>

      <section className="glass-panel mt-6 rounded-2xl p-5">
        <p className="text-sm font-semibold">{t("users_mgmt")}</p>
        <div className="mt-4 space-y-2">
          {users.map((u) => (
            <div
              key={u.id}
              className="flex flex-wrap items-center gap-3 rounded-xl border border-border bg-card/60 p-3"
            >
              <div className="min-w-0">
                <p className="truncate text-sm font-medium">{u.full_name}</p>
                <p className="truncate font-mono text-xs text-muted-foreground" dir="ltr">
                  {u.whatsapp_number}
                </p>
              </div>
              <span className="rounded-full border border-border bg-secondary px-2.5 py-0.5 text-xs">
                {t("role")}: {u.role}
              </span>
              <span
                className={
                  u.whatsapp_alerts_enabled
                    ? "rounded-full border border-emerald/40 bg-emerald/10 px-2.5 py-0.5 text-xs text-emerald"
                    : "rounded-full border border-crimson/40 bg-crimson/10 px-2.5 py-0.5 text-xs text-crimson"
                }
              >
                {u.whatsapp_alerts_enabled ? "Alerts ON" : "Alerts OFF"}
              </span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
