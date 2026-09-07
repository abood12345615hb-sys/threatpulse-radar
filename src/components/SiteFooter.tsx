import { Link } from "@tanstack/react-router";
import { ShieldAlert } from "lucide-react";
import { useLanguage } from "@/contexts/LanguageContext";

export function SiteFooter() {
  const { t } = useLanguage();

  return (
    <footer className="border-t border-border/70 bg-card/40">
      <div className="mx-auto flex w-full max-w-[1600px] flex-col gap-4 px-4 py-8 sm:flex-row sm:items-center sm:px-6">
        <div className="flex items-center gap-2">
          <span className="flex size-8 items-center justify-center rounded-lg bg-accent text-accent-foreground">
            <ShieldAlert className="size-4" />
          </span>
          <span className="text-sm font-semibold">{t("brand")}</span>
        </div>
        <nav className="flex flex-wrap items-center gap-4 text-sm text-muted-foreground sm:ms-auto">
          <Link to="/" className="hover:text-foreground">
            {t("nav_home")}
          </Link>
          <Link to="/dashboard" className="hover:text-foreground">
            {t("nav_dashboard")}
          </Link>
          <Link to="/admin" className="hover:text-foreground">
            {t("nav_admin")}
          </Link>
        </nav>
      </div>
    </footer>
  );
}
