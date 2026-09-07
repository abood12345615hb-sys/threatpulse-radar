import { createFileRoute, Link } from "@tanstack/react-router";
import { CheckCircle2, KeyRound, Lock, MessageCircle, Terminal } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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

    const id = window.setInterval(() => {
      setLogs((prev) => [...prev.slice(-40), threatService.nextLogEntry()]);
    }, 1800);
    return () => window.clearInterval(id);
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

  const [testingWa, setTestingWa] = useState(false);

  const testWhatsAppAlert = async () => {
    setTestingWa(true);
    try {
      const sampleScan = {
        id: "test",
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
      const res = await threatService.dispatchWhatsAppAlert(sampleScan);
      if (res.sent) {
        toast.success("تم إرسال التنبيه الأمني إلى هاتفك عبر Zavu بنجاح! 📲");
      } else if (res.reason === "zavu_key_not_configured") {
        toast.error("مفتاح Zavu غير مهيأ بعد. يرجى إدخال المفتاح في الأسفل وحفظه أولاً.");
      } else if (res.reason === "no_recipient_phone") {
        toast.error("رقم الهاتف غير مفعل للتنبيهات في ملفك الشخصي.");
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

      <section className="glass-panel mt-4 rounded-2xl p-5">
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
