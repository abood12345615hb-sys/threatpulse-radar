import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { MessageCircle, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { useAuth } from "@/contexts/AuthContext";
import { useLanguage } from "@/contexts/LanguageContext";
import { COUNTRY_CODES } from "@/services/authService";

export const Route = createFileRoute("/auth")({
  validateSearch: (search: Record<string, unknown>): { q?: string } => {
    const q = search["q"];
    return typeof q === "string" ? { q } : {};
  },
  head: () => ({
    meta: [
      { title: "Sign in — ThreatPulse CTI" },
      {
        name: "description",
        content:
          "Create a ThreatPulse CTI account to unlock full OSINT reports and WhatsApp security alerts.",
      },
      { property: "og:title", content: "Sign in — ThreatPulse CTI" },
      {
        property: "og:description",
        content: "Unlock full threat reports and automated WhatsApp alerts.",
      },
    ],
  }),
  component: AuthPage,
});

function AuthPage() {
  const { t } = useLanguage();
  const { login, register, pending } = useAuth();
  const navigate = useNavigate();
  const { q } = Route.useSearch();

  const [mode, setMode] = useState<"login" | "register">("register");
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [dialCode, setDialCode] = useState("+966");
  const [phone, setPhone] = useState("");
  const [whatsappAlerts, setWhatsappAlerts] = useState(true);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.includes("@")) {
      toast.error(t("invalid_email"));
      return;
    }

    if (mode === "register") {
      const isStrong = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*.,]).{8,}$/.test(password);
      if (!isStrong) {
        toast.error(t("password_weak"));
        return;
      }
    } else if (password.length < 6) {
      toast.error(t("password_short"));
      return;
    }
    try {
      if (mode === "login") {
        await login(email, password);
      } else {
        const nameWords = fullName.trim().split(/\s+/);
        if (nameWords.length < 3) {
          toast.error(t("name_length_error"));
          return;
        }

        const requiredPhoneLength = ["+20", "+1", "+44", "+49"].includes(dialCode) ? 10 : 9;
        if (phone.replace(/[^\d]/g, "").length !== requiredPhoneLength) {
          toast.error(requiredPhoneLength === 10 ? t("phone_length_error_10") : t("phone_length_error_9"));
          return;
        }

        await register({ fullName, email, password, dialCode, phone, whatsappAlerts });
      }
      toast.success(t("welcome_user") + " " + email);
      navigate({ to: "/dashboard", search: q ? { q } : {} });
    } catch (error: any) {
      const msg = error.message?.toLowerCase() || "";
      if (msg.includes("user already registered")) {
        toast.error(t("email_in_use"));
      } else if (msg.includes("phone already registered")) {
        toast.error(t("phone_in_use"));
      } else if (msg.includes("rate limit")) {
        toast.error(t("rate_limit"));
      } else {
        toast.error(error.message || t("auth_failed"));
      }
    }
  };

  return (
    <div className="mx-auto grid w-full max-w-[1100px] gap-8 px-4 py-12 sm:px-6 lg:grid-cols-2 lg:items-center">
      <div className="glass-panel glow-ring order-2 rounded-2xl p-6 sm:p-8 lg:order-1">
        <h1 className="text-2xl font-bold tracking-tight">
          {mode === "login" ? t("auth_login_title") : t("auth_register_title")}
        </h1>

        <form onSubmit={submit} className="mt-6 space-y-4">
          {mode === "register" && (
            <div className="space-y-1.5">
              <Label htmlFor="fullName">{t("full_name")}</Label>
              <Input id="fullName" value={fullName} onChange={(e) => setFullName(e.target.value)} />
            </div>
          )}

          <div className="space-y-1.5">
            <Label htmlFor="email">{t("email")}</Label>
            <Input
              id="email"
              type="email"
              dir="ltr"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="password">{t("password")}</Label>
            <Input
              id="password"
              type="password"
              dir="ltr"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            {mode === "register" && (
              <p className="text-[11px] text-muted-foreground mt-1">
                {t("password_hint")}
              </p>
            )}
          </div>

          {mode === "register" && (
            <>
              <div className="grid grid-cols-[9rem_1fr] gap-2">
                <div className="space-y-1.5">
                  <Label htmlFor="dial">{t("country_code")}</Label>
                  <select
                    id="dial"
                    dir="ltr"
                    value={dialCode}
                    onChange={(e) => setDialCode(e.target.value)}
                    className="h-9 w-full rounded-md border border-input bg-background px-2 text-sm"
                  >
                    {COUNTRY_CODES.map((c) => (
                      <option key={c.code} value={c.dial}>
                        {c.dial} {c.code}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="phone">{t("phone")}</Label>
                  <Input
                    id="phone"
                    dir="ltr"
                    inputMode="tel"
                    value={phone}
                    onChange={(e) => setPhone(e.target.value.replace(/[^\d]/g, ""))}
                  />
                  <p className="text-[11px] text-muted-foreground mt-1">
                    {["+20", "+1", "+44", "+49"].includes(dialCode) ? t("phone_hint_10") : t("phone_hint_9")}
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-4 rounded-xl border border-primary/30 bg-accent/30 p-4">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-emerald/20">
                  <MessageCircle className="size-5 text-emerald" />
                </div>
                <div className="flex-1 space-y-1.5">
                  <Label htmlFor="wa" className="text-sm font-semibold cursor-pointer">
                    {t("wa_optin")}
                  </Label>
                  <p className="text-[11px] text-muted-foreground leading-relaxed">{t("wa_value")}</p>
                </div>
                <div className="shrink-0 mt-1">
                  <Switch id="wa" dir="ltr" checked={whatsappAlerts} onCheckedChange={setWhatsappAlerts} />
                </div>
              </div>
            </>
          )}

          <Button type="submit" size="lg" className="w-full" disabled={pending}>
            {mode === "login" ? t("login") : t("register")}
          </Button>
        </form>

        <button
          type="button"
          onClick={() => setMode((p) => (p === "login" ? "register" : "login"))}
          className="mt-4 w-full text-center text-sm text-muted-foreground hover:text-foreground"
        >
          {mode === "login" ? t("no_account") : t("have_account")}
        </button>
      </div>

      <div className="order-1 lg:order-2">
        <span className="inline-flex items-center gap-2 rounded-full border border-border px-3 py-1 text-xs text-muted-foreground">
          <ShieldCheck className="size-3.5 text-primary" />
          {t("hero_badge")}
        </span>
        <h2 className="mt-4 text-3xl font-bold tracking-tight sm:text-4xl">{t("hero_title")}</h2>
        <p className="mt-3 text-sm text-muted-foreground">{t("hero_sub")}</p>
        {q && (
          <p className="mt-6 rounded-xl border border-border bg-card/60 p-4 font-mono text-xs" dir="ltr">
            {q}
          </p>
        )}
      </div>
    </div>
  );
}
