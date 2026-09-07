import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useLanguage } from "@/contexts/LanguageContext";
import type { ThreatVolumePoint } from "@/types";

const tooltipStyle = {
  background: "var(--popover)",
  border: "1px solid var(--border)",
  borderRadius: "10px",
  color: "var(--popover-foreground)",
  fontSize: "12px",
};

export function ThreatVolumeChart({ data }: { data: ThreatVolumePoint[] }) {
  const { t, dir } = useLanguage();

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <div>
        <p className="mb-3 text-sm font-semibold">{t("volume")}</p>
        <div className="h-64 [perspective:900px]">
          <div className="h-full transition-transform duration-500 [transform:rotateX(14deg)_rotateZ(-1deg)] hover:[transform:rotateX(4deg)]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data} barGap={2}>
                <CartesianGrid stroke="var(--border)" vertical={false} />
                <XAxis
                  dataKey="label"
                  reversed={dir === "rtl"}
                  stroke="var(--muted-foreground)"
                  fontSize={11}
                />
                <YAxis
                  orientation={dir === "rtl" ? "right" : "left"}
                  stroke="var(--muted-foreground)"
                  fontSize={11}
                />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "var(--secondary)" }} />
                <Bar dataKey="malicious" stackId="a" fill="var(--crimson)" radius={[0, 0, 0, 0]} />
                <Bar dataKey="suspicious" stackId="a" fill="var(--amber)" />
                <Bar dataKey="clean" stackId="a" fill="var(--emerald)" radius={[6, 6, 0, 0]}>
                  {data.map((d) => (
                    <Cell key={d.label} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div>
        <p className="mb-3 text-sm font-semibold">{t("analytics")}</p>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data}>
              <defs>
                <linearGradient id="areaMal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--crimson)" stopOpacity={0.65} />
                  <stop offset="100%" stopColor="var(--crimson)" stopOpacity={0.04} />
                </linearGradient>
                <linearGradient id="areaSus" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--cyber)" stopOpacity={0.5} />
                  <stop offset="100%" stopColor="var(--cyber)" stopOpacity={0.03} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="var(--border)" vertical={false} />
              <XAxis dataKey="label" reversed={dir === "rtl"} stroke="var(--muted-foreground)" fontSize={11} />
              <YAxis orientation={dir === "rtl" ? "right" : "left"} stroke="var(--muted-foreground)" fontSize={11} />
              <Tooltip contentStyle={tooltipStyle} />
              <Area
                type="monotone"
                dataKey="malicious"
                stroke="var(--crimson)"
                strokeWidth={2}
                fill="url(#areaMal)"
              />
              <Area
                type="monotone"
                dataKey="suspicious"
                stroke="var(--cyber)"
                strokeWidth={2}
                fill="url(#areaSus)"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
