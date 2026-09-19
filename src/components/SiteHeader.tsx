import { Link, useNavigate } from "@tanstack/react-router";
import { Activity, Globe2, LogOut, Menu, MessageSquare, Moon, ShieldAlert, Sun } from "lucide-react";
import { useState } from "react";
import { useLanguage } from "@/contexts/LanguageContext";
import { useTheme } from "@/contexts/ThemeContext";
import { useAuth } from "@/contexts/AuthContext";
import { Button } from "@/components/ui/button";

export function SiteHeader() {
  const { t, lang, toggleLang } = useLanguage();
  const { theme, toggleTheme } = useTheme();
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);

  const allLinks = [
    { to: "/", label: t("nav_home"), adminOnly: false },
    { to: "/dashboard", label: t("nav_dashboard"), adminOnly: false },
    { to: "/admin", label: t("nav_admin"), adminOnly: true },
  ];

  const links = allLinks.filter(l => !l.adminOnly || user?.role === "admin");

  return (
    <header className="sticky top-0 z-50 border-b border-border/70 bg-background/80 backdrop-blur-xl">
      <div className="mx-auto flex h-16 w-full max-w-[1600px] items-center gap-3 px-4 sm:px-6">
        <Link to="/" className="flex items-center gap-2">
          <span className="glow-ring flex size-9 items-center justify-center rounded-xl bg-accent text-accent-foreground">
            <ShieldAlert className="size-5" />
          </span>
          <span className="text-base font-semibold tracking-tight">{t("brand")}</span>
        </Link>

        <nav className="ms-6 hidden items-center gap-1 md:flex">
          {links.map((l) => (
            <Link
              key={l.to}
              to={l.to}
              activeProps={{ className: "bg-secondary text-foreground" }}
              className="rounded-lg px-3 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-secondary hover:text-foreground"
            >
              {l.label}
            </Link>
          ))}
        </nav>

        <div className="ms-auto flex items-center gap-1.5">
          <span className="hidden items-center gap-1.5 rounded-full border border-border px-2.5 py-1 text-xs text-muted-foreground lg:inline-flex">
            <Activity className="size-3.5 text-emerald" />
            <span className="size-1.5 animate-blink rounded-full bg-emerald" />
            SOC live
          </span>
          <Link
            to="/dashboard"
            className="hidden items-center gap-1.5 rounded-full border border-emerald/30 bg-emerald/10 px-2.5 py-1 text-xs font-medium text-emerald transition hover:bg-emerald/20 sm:inline-flex"
            title={lang === "ar" ? "تنبيهات واتساب الفورية مفعلة ومربوطة" : "Instant WhatsApp Alerts Active"}
          >
            <MessageSquare className="size-3.5" />
            <span>WhatsApp Alerts</span>
          </Link>
          <Button variant="ghost" size="icon" onClick={toggleLang} aria-label="Switch language">
            <Globe2 className="size-4" />
            <span className="sr-only">{lang}</span>
          </Button>
          <Button variant="ghost" size="icon" onClick={toggleTheme} aria-label={t("theme")}>
            {theme === "dark" ? <Sun className="size-4" /> : <Moon className="size-4" />}
          </Button>
          {user ? (
            <div className="flex items-center gap-3">
              <div className="hidden sm:flex flex-col items-end">
                <span className="text-sm font-medium leading-none">{user.fullName}</span>
                <span className="text-[10px] text-muted-foreground uppercase tracking-widest mt-0.5">
                  Role: {user.role}
                </span>
              </div>
              <Button
                variant="outline"
                size="sm"
                className="hidden sm:inline-flex"
                onClick={async () => {
                  await logout();
                  navigate({ to: "/" });
                }}
              >
                <LogOut className="size-4 me-2" />
                {t("logout")}
              </Button>
            </div>
          ) : (
            <Button asChild size="sm" className="hidden sm:inline-flex">
              <Link to="/auth">{t("nav_auth")}</Link>
            </Button>
          )}
          <Button
            variant="ghost"
            size="icon"
            className="md:hidden"
            onClick={() => setOpen((p) => !p)}
            aria-label="Menu"
          >
            <Menu className="size-5" />
          </Button>
        </div>
      </div>

      {open && (
        <div className="border-t border-border bg-card px-4 py-3 md:hidden">
          <div className="flex flex-col gap-1">
            {links.map((l) => (
              <Link
                key={l.to}
                to={l.to}
                onClick={() => setOpen(false)}
                className="rounded-lg px-3 py-2.5 text-sm font-medium text-muted-foreground hover:bg-secondary hover:text-foreground"
              >
                {l.label}
              </Link>
            ))}
            {user ? (
              <Button
                variant="outline"
                className="mt-2"
                onClick={async () => {
                  await logout();
                  setOpen(false);
                  navigate({ to: "/" });
                }}
              >
                {t("logout")}
              </Button>
            ) : (
              <Button asChild className="mt-2">
                <Link to="/auth" onClick={() => setOpen(false)}>
                  {t("nav_auth")}
                </Link>
              </Button>
            )}
          </div>
        </div>
      )}
    </header>
  );
}
