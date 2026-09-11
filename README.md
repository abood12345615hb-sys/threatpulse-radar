# ThreatPulse Sentinel

Build a production-ready, fully responsive, and interactive Cyber Threat Intelligence (CTI) web application called "ThreatPulse CTI". 



The platform must adopt an elite Cyber SOC Dark Mode theme (with a High-Tech Light mode switch), 3D data visualizations, smooth micro-interactions, full Arabic (RTL) & English (LTR) bilingual support, and a complete user-conversion funnel including Phone/WhatsApp registration for automated security alerts.



---



### 🛠️ 1. Technical Stack & Architecture

- **Framework:** Next.js (App Router) / React with TypeScript.

- **Styling:** Tailwind CSS with Lucide React icons.

- **Animations & 3D:** Framer Motion (or lightweight CSS animations) and Three.js / Canvas / Recharts for 3D analytical charts.

- **State Management & Modular Services:** Clean separation of concerns with context providers (`LanguageContext`, `ThemeContext`, `AuthContext`) and modular mock API services (`threatService.ts`, `authService.ts`) ready for Supabase integration.



---



### 🎨 2. Visual Design System & Themes

- **Theme Modes:**

  - **Cyber Dark Mode (Default):** Deep Slate/Void background (`#080C14` / `#0D1527`), glowing neon accents (Cyan `#00F0FF`, Crimson `#FF0055`, Emerald `#10B981`), and frosted glassmorphism borders (`border-slate-700/40`).

  - **Clean High-Tech Light Mode:** Crisp light background (`#F8FAFC`), subtle ambient shadows, clean slate borders, and electric blue/emerald accents.

- **Typography:** Monospace font for IOCs/IPs/URLs (`JetBrains Mono` / `Fira Code`) and clean sans-serif for UI (`Inter` for English, `Cairo` or `Tajawal` for Arabic).



---



### 🔄 3. Visitor Journey & WhatsApp Alert Onboarding

- **Interactive Scanner on Home Page:** 

  - An input field to paste URLs or IP addresses.

  - Clicking "Scan Threat / فحص التهديد" triggers a dynamic 360° glowing Radar Sweep animation.

- **Gated Conversion / Auth Gateway:**

  - Once the radar scan completes (after ~2 seconds), prompt or redirect the user to the Authentication / Registration Gateway to reveal the full OSINT breakdown.

- **Registration Form with WhatsApp Integration:**

  - Form Fields: Full Name, Email, Password, and **Phone Number with Country Code Selector & WhatsApp Alert Opt-In checkbox**.

  - Value Proposition Callout: *"Register your WhatsApp number to receive instant, real-time automated security alerts when critical threats are detected."* / *"سجّل رقم هاتفك لتفعيل التنبيهات الفورية عبر واتساب عند رصد تهديدات حرجة."*

  - Seamless toggle between Login and Register.



---



### 📊 4. 3D Analytics & Core Dashboard Views



#### A. Public Landing Page (`/`)

- Cyber hero banner with live grid background.

- URL/IP indicator search bar with glowing sweep animation.

- Feature highlight cards (Multi-source Aggregation, WhatsApp Instant Alerts, Real-time SOC feeds).



#### B. User Dashboard & Scan Results (`/dashboard`)

- **Animated Risk Gauge (0–100):** Visual speedometer shifting colors dynamically (0–30 Green, 31–70 Orange, 71–100 Crimson).

- **Aggregated OSINT Provider Badges:** Status breakdowns for VirusTotal, URLhaus, and AbuseIPDB.

- **3D Threat Analytics:** 3D bar/area charts visualizing threat volume and an interactive rotating 3D globe/node visualizer.

- **Scan History Table:** Filterable table with quick-copy IOC tools and export options (collapses into responsive cards on mobile).



#### C. Admin SOC Panel (`/admin`)

- Live simulated threat log terminal with flashing realtime indicators.

- WhatsApp Alert Monitor status card: *"WhatsApp Alert Service: Active & Connected"*.

- API keys configuration and user management controls.



---



### 🌐 5. Internationalization (i18n) & Multi-Device Responsiveness

- **Bidirectional Support:** Full instant switching between English (LTR) and Arabic (RTL), properly mirroring icons, navigation drawers, layout columns, and text alignment.

- **Responsive Breakpoints:** Optimized for Mobile (375px+), Tablets (768px+), and Desktop/Ultrawide displays with collapsible sidebars and touch-friendly targets.



---



### 🚀 6. Execution Instructions for Manus

1. Scaffold the folder structure cleanly (`components/`, `contexts/`, `services/`, `types/`, `styles/`).

2. Implement mock API latency simulations to mimic real-world asynchronous threat scanning.

3. Build responsive layouts first, apply styling and animations, and test RTL/LTR and Dark/Light toggles across all pages.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```
