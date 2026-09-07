import { useEffect, useState } from "react";
import { useLanguage } from "@/contexts/LanguageContext";
import { VerdictBadge } from "@/components/VerdictBadge";
import type { Verdict } from "@/types";

function colorFor(score: number) {
  if (score <= 30) return "var(--emerald)";
  if (score <= 70) return "var(--amber)";
  return "var(--crimson)";
}

export function RiskGauge({ score, verdict }: { score: number; verdict: Verdict }) {
  const { t } = useLanguage();
  const [animated, setAnimated] = useState(0);

  useEffect(() => {
    setAnimated(0);
    const id = window.setTimeout(() => setAnimated(score), 120);
    return () => window.clearTimeout(id);
  }, [score]);

  const radius = 78;
  const circumference = Math.PI * radius;
  const offset = circumference * (1 - animated / 100);
  const color = colorFor(score);

  return (
    <div className="flex flex-col items-center">
      <svg viewBox="0 0 200 118" className="w-full max-w-[280px]" role="img" aria-label={t("risk_score")}>
        <path
          d="M 22 104 A 78 78 0 0 1 178 104"
          fill="none"
          stroke="var(--border)"
          strokeWidth="14"
          strokeLinecap="round"
        />
        <path
          d="M 22 104 A 78 78 0 0 1 178 104"
          fill="none"
          stroke={color}
          strokeWidth="14"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 1.1s cubic-bezier(.22,1,.36,1), stroke .4s" }}
        />
        <line
          x1="100"
          y1="104"
          x2="100"
          y2="40"
          stroke={color}
          strokeWidth="3"
          strokeLinecap="round"
          style={{
            transformOrigin: "100px 104px",
            transform: `rotate(${-90 + (animated / 100) * 180}deg)`,
            transition: "transform 1.1s cubic-bezier(.22,1,.36,1)",
          }}
        />
        <circle cx="100" cy="104" r="6" fill={color} />
      </svg>
      <div className="-mt-4 text-center">
        <div className="font-mono text-4xl font-bold tabular-nums" style={{ color }}>
          {Math.round(animated)}
        </div>
        <p className="mt-1 text-xs uppercase tracking-widest text-muted-foreground">{t("risk_score")}</p>
        <VerdictBadge verdict={verdict} className="mt-3" />
      </div>
    </div>
  );
}
