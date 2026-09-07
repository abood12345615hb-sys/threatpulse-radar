import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";

export type Lang = "en" | "ar";

const dict = {
  brand: { en: "ThreatPulse CTI", ar: "ثريت بالس" },
  nav_home: { en: "Home", ar: "الرئيسية" },
  nav_dashboard: { en: "Dashboard", ar: "لوحة التحكم" },
  nav_admin: { en: "SOC Admin", ar: "مركز العمليات" },
  nav_auth: { en: "Sign in", ar: "تسجيل الدخول" },
  logout: { en: "Sign out", ar: "خروج" },
  hero_badge: { en: "Live OSINT aggregation", ar: "تجميع مصادر مفتوحة حي" },
  hero_title: { en: "Threat intelligence at the speed of attack", ar: "استخبارات تهديدات بسرعة الهجوم" },
  hero_sub: {
    en: "Scan any URL or IP against VirusTotal, URLhaus and AbuseIPDB in one sweep — and get critical findings on WhatsApp the moment they land.",
    ar: "افحص أي رابط أو عنوان IP عبر VirusTotal و URLhaus و AbuseIPDB في مسح واحد — واستلم النتائج الحرجة على واتساب لحظة رصدها.",
  },
  scan_placeholder: { en: "https://suspicious-site.com or 185.220.101.44", ar: "https://موقع-مشتبه.com أو 185.220.101.44" },
  scan_cta: { en: "Scan Threat", ar: "فحص التهديد" },
  scanning: { en: "Sweeping sources…", ar: "جاري مسح المصادر…" },
  scan_done: { en: "Sweep complete — sign in to reveal the full OSINT breakdown.", ar: "اكتمل المسح — سجّل الدخول لعرض التحليل الكامل." },
  reveal_cta: { en: "Reveal full report", ar: "عرض التقرير الكامل" },
  scan_hint: { en: "Try a URL, domain or IPv4 address", ar: "جرّب رابطاً أو نطاقاً أو عنوان IPv4" },
  feature_1_t: { en: "Multi-source aggregation", ar: "تجميع متعدد المصادر" },
  feature_1_d: { en: "Normalized verdicts from every major OSINT feed in a single risk score.", ar: "أحكام موحّدة من كل المصادر المفتوحة في درجة خطر واحدة." },
  feature_2_t: { en: "WhatsApp instant alerts", ar: "تنبيهات واتساب الفورية" },
  feature_2_d: { en: "Critical detections pushed straight to your phone, 24/7.", ar: "التهديدات الحرجة تُرسل مباشرة إلى هاتفك على مدار الساعة." },
  feature_3_t: { en: "Real-time SOC feeds", ar: "تغذية مركز العمليات لحظياً" },
  feature_3_d: { en: "Streaming sensor telemetry with analyst-grade enrichment.", ar: "تدفق بيانات المجسّات مع إثراء بمستوى المحللين." },
  auth_login_title: { en: "Welcome back, analyst", ar: "مرحباً بعودتك" },
  auth_register_title: { en: "Create your CTI account", ar: "أنشئ حسابك" },
  full_name: { en: "Full name", ar: "الاسم الكامل" },
  email: { en: "Email", ar: "البريد الإلكتروني" },
  password: { en: "Password", ar: "كلمة المرور" },
  phone: { en: "Phone number", ar: "رقم الهاتف" },
  country_code: { en: "Country code", ar: "رمز الدولة" },
  wa_optin: { en: "Enable WhatsApp security alerts", ar: "تفعيل تنبيهات واتساب الأمنية" },
  wa_value: {
    en: "Register your WhatsApp number to receive instant, real-time automated security alerts when critical threats are detected.",
    ar: "سجّل رقم هاتفك لتفعيل التنبيهات الفورية عبر واتساب عند رصد تهديدات حرجة.",
  },
  register: { en: "Create account", ar: "إنشاء حساب" },
  login: { en: "Sign in", ar: "تسجيل الدخول" },
  have_account: { en: "Already have an account?", ar: "لديك حساب بالفعل؟" },
  no_account: { en: "New to ThreatPulse?", ar: "جديد على المنصة؟" },
  risk_score: { en: "Risk score", ar: "درجة الخطر" },
  verdict_clean: { en: "Clean", ar: "سليم" },
  verdict_suspicious: { en: "Suspicious", ar: "مشتبه" },
  verdict_malicious: { en: "Malicious", ar: "خطير" },
  providers: { en: "OSINT providers", ar: "مصادر الاستخبارات" },
  detections: { en: "detections", ar: "كشوفات" },
  analytics: { en: "3D threat analytics", ar: "تحليلات ثلاثية الأبعاد" },
  volume: { en: "Threat volume", ar: "حجم التهديدات" },
  globe: { en: "Global node activity", ar: "نشاط العقد العالمي" },
  history: { en: "Scan history", ar: "سجل الفحوصات" },
  filter: { en: "Filter indicators", ar: "تصفية المؤشرات" },
  export_csv: { en: "Export CSV", ar: "تصدير CSV" },
  copy: { en: "Copy", ar: "نسخ" },
  copied: { en: "Copied to clipboard", ar: "تم النسخ" },
  indicator: { en: "Indicator", ar: "المؤشر" },
  score: { en: "Score", ar: "الدرجة" },
  country: { en: "Origin", ar: "المصدر" },
  when: { en: "Seen", ar: "التوقيت" },
  scan_new: { en: "New scan", ar: "فحص جديد" },
  live_log: { en: "Live threat log", ar: "سجل التهديدات الحي" },
  wa_monitor: { en: "WhatsApp Alert Service: Active & Connected", ar: "خدمة تنبيهات واتساب: نشطة ومتصلة" },
  wa_sent: { en: "Alerts dispatched today", ar: "تنبيهات أُرسلت اليوم" },
  api_keys: { en: "API keys configuration", ar: "إعداد مفاتيح API" },
  users_mgmt: { en: "User management", ar: "إدارة المستخدمين" },
  save: { en: "Save", ar: "حفظ" },
  role: { en: "Role", ar: "الدور" },
  status: { en: "Status", ar: "الحالة" },
  active: { en: "Active", ar: "نشط" },
  suspended: { en: "Suspended", ar: "موقوف" },
  categories: { en: "Categories", ar: "التصنيفات" },
  welcome_user: { en: "Signed in as", ar: "مسجّل بصفة" },
  admin_only: { en: "Admin access required", ar: "مطلوب صلاحية مسؤول" },
  theme: { en: "Theme", ar: "المظهر" },
  no_results: { en: "No indicators match your filter.", ar: "لا توجد مؤشرات مطابقة." },
  invalid_email: { en: "Invalid email address", ar: "البريد الإلكتروني غير صالح" },
  invalid_email_or_password: { en: "Invalid email or short password", ar: "البريد الإلكتروني غير صالح أو كلمة المرور قصيرة" },
  name_length_error: { en: "Please enter your full three-part name.", ar: "يرجى إدخال الاسم الثلاثي على الأقل." },
  phone_length_error_10: { en: "Phone must be 10 digits for this country code.", ar: "يجب أن يتكون رقم الهاتف من 10 أرقام لهذا الرمز." },
  phone_length_error_9: { en: "Phone must be 9 digits for this country code.", ar: "يجب أن يتكون رقم الهاتف من 9 أرقام لهذا الرمز." },
  phone_hint_10: { en: "10 digits required", ar: "مطلوب 10 أرقام" },
  phone_hint_9: { en: "9 digits required", ar: "مطلوب 9 أرقام" },
  password_weak: { en: "Weak password. Must be 8+ chars with uppercase, lowercase, number, and special char (!@#$%).", ar: "كلمة المرور ضعيفة. يجب أن تحتوي على 8 أحرف على الأقل، حرف كبير، حرف صغير، رقم، ورمز خاص (!@#$%)." },
  password_short: { en: "Password is too short", ar: "كلمة المرور قصيرة جداً" },
  password_hint: { en: "At least 8 chars, 1 uppercase, 1 lowercase, 1 number, and 1 special char (@ or #).", ar: "يجب أن تتكون من 8 أحرف على الأقل، وتحتوي على حرف إنجليزي كبير وصغير، ورقم، ورمز خاص مثل @ أو #." },
  email_in_use: { en: "Email already registered! Please sign in.", ar: "هذا البريد الإلكتروني مسجل مسبقاً! الرجاء تسجيل الدخول." },
  phone_in_use: { en: "Phone number already registered to another account!", ar: "رقم الهاتف هذا مسجل مسبقاً لحساب آخر!" },
  rate_limit: { en: "Too many attempts. Please try again later.", ar: "لقد تجاوزت الحد المسموح من المحاولات. يرجى المحاولة لاحقاً." },
  auth_failed: { en: "Authentication failed", ar: "فشلت عملية المصادقة" },
} as const;

export type TKey = keyof typeof dict;

interface LanguageValue {
  lang: Lang;
  dir: "ltr" | "rtl";
  setLang: (l: Lang) => void;
  toggleLang: () => void;
  t: (key: TKey) => string;
}

const LanguageContext = createContext<LanguageValue | null>(null);

export function LanguageProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>("en");

  useEffect(() => {
    const stored = window.localStorage.getItem("threatpulse.lang") as Lang | null;
    if (stored === "ar" || stored === "en") setLangState(stored);
  }, []);

  useEffect(() => {
    const dir = lang === "ar" ? "rtl" : "ltr";
    document.documentElement.setAttribute("dir", dir);
    document.documentElement.setAttribute("lang", lang);
    window.localStorage.setItem("threatpulse.lang", lang);
  }, [lang]);

  const t = useCallback((key: TKey) => dict[key][lang], [lang]);

  return (
    <LanguageContext.Provider
      value={{
        lang,
        dir: lang === "ar" ? "rtl" : "ltr",
        setLang: setLangState,
        toggleLang: () => setLangState((p) => (p === "en" ? "ar" : "en")),
        t,
      }}
    >
      {children}
    </LanguageContext.Provider>
  );
}

export function useLanguage() {
  const ctx = useContext(LanguageContext);
  if (!ctx) throw new Error("useLanguage must be used within LanguageProvider");
  return ctx;
}
