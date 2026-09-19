import { Globe, Server, FileWarning, Link as LinkIcon, Cpu, ShieldCheck, CheckCircle } from "lucide-react";
import type { Verdict } from "@/types";

interface ThreatGraphProps {
  indicator: string;
  type: "url" | "ip" | "domain";
  verdict: Verdict;
  classification?: string | undefined;
  mitreTactic?: string | undefined;
  asn?: string | undefined;
  country?: string | undefined;
}

export function ThreatGraph({
  indicator,
  type,
  verdict,
  classification,
  mitreTactic,
  asn,
  country,
}: ThreatGraphProps) {
  // Colors based on verdict
  const isClean = verdict === "clean";
  const isSuspicious = verdict === "suspicious";

  const mainColor = isClean
    ? "text-emerald border-emerald"
    : isSuspicious
    ? "text-amber border-amber"
    : "text-crimson border-crimson";
  const mainBg = isClean
    ? "bg-emerald/10"
    : isSuspicious
    ? "bg-amber/10"
    : "bg-crimson/10";

  // Dynamic labels
  const node1Label = isClean
    ? "Safe Baseline"
    : classification
    ? classification.split(":")[0]?.trim() || classification.slice(0, 18)
    : "Threat Payload";

  const node2Label = isClean
    ? "DNS Verified"
    : mitreTactic && mitreTactic !== "N/A"
    ? mitreTactic.split(" - ")[0]?.trim() || "C2 Vector"
    : "Attack Surface";

  const node3Label = asn ? `${asn}${country ? ` (${country})` : ""}` : country || "AS15169";

  return (
    <div className="relative w-full h-full min-h-[250px] flex items-center justify-center p-4">
      {/* Background Grid & SVG Connections */}
      <svg className="absolute inset-0 w-full h-full pointer-events-none" style={{ zIndex: 0 }}>
        <defs>
          <linearGradient id="line-grad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="currentColor" stopOpacity="0.2" className={mainColor.split(" ")[0]} />
            <stop offset="100%" stopColor="currentColor" stopOpacity="0.8" className={mainColor.split(" ")[0]} />
          </linearGradient>
        </defs>

        {/* Line from Center to Top Right */}
        <path d="M 50% 50% L 75% 25%" stroke="url(#line-grad)" strokeWidth="2" strokeDasharray="4 4" className="animate-pulse" />

        {/* Line from Center to Bottom Right */}
        <path d="M 50% 50% L 75% 75%" stroke="url(#line-grad)" strokeWidth="2" strokeDasharray="4 4" className="animate-pulse" style={{ animationDelay: "200ms" }} />

        {/* Line from Center to Left */}
        <path d="M 50% 50% L 25% 50%" stroke="url(#line-grad)" strokeWidth="2" strokeDasharray="4 4" className="animate-pulse" style={{ animationDelay: "400ms" }} />
      </svg>

      {/* Nodes Container */}
      <div className="relative z-10 w-full h-full flex items-center justify-center">
        {/* Central Node (The Scanned Indicator) */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 flex flex-col items-center justify-center">
          <div className={`size-16 rounded-full border-2 ${mainColor} ${mainBg} flex items-center justify-center relative shadow-[0_0_15px_rgba(var(--color-crimson),0.2)]`}>
            <span className="absolute inset-0 rounded-full border-2 border-inherit animate-ping opacity-20"></span>
            {type === "ip" ? <Server className="size-6" /> : type === "url" ? <LinkIcon className="size-6" /> : <Globe className="size-6" />}
          </div>
          <span className="mt-2 text-xs font-mono font-semibold bg-background/80 px-2 py-0.5 rounded border border-border truncate max-w-[140px]" title={indicator}>
            {indicator}
          </span>
        </div>

        {/* Node 1: Threat / Safety Status (Top Right) */}
        <div className="absolute top-[15%] left-[70%] flex flex-col items-center justify-center hover:scale-110 transition-transform cursor-crosshair">
          <div className={`size-10 rounded-full border ${isClean ? "border-emerald/50 bg-emerald/10 text-emerald" : "border-crimson/50 bg-crimson/10 text-crimson"} flex items-center justify-center`}>
            {isClean ? <ShieldCheck className="size-4" /> : <FileWarning className="size-4" />}
          </div>
          <span className="mt-1 text-[10px] text-muted-foreground bg-background/80 px-1.5 py-0.5 rounded border border-border/50 truncate max-w-[110px]" title={node1Label}>
            {node1Label}
          </span>
        </div>

        {/* Node 2: Infrastructure / MITRE Tactic (Bottom Right) */}
        <div className="absolute top-[70%] left-[70%] flex flex-col items-center justify-center hover:scale-110 transition-transform cursor-crosshair">
          <div className={`size-10 rounded-full border ${isClean ? "border-emerald/50 bg-emerald/10 text-emerald" : "border-amber/50 bg-amber/10 text-amber"} flex items-center justify-center`}>
            {isClean ? <CheckCircle className="size-4" /> : <Cpu className="size-4" />}
          </div>
          <span className="mt-1 text-[10px] text-muted-foreground bg-background/80 px-1.5 py-0.5 rounded border border-border/50 truncate max-w-[110px]" title={node2Label}>
            {node2Label}
          </span>
        </div>

        {/* Node 3: Real ASN / Geolocation (Left) */}
        <div className="absolute top-[40%] left-[15%] flex flex-col items-center justify-center hover:scale-110 transition-transform cursor-crosshair">
          <div className="size-10 rounded-full border border-cyber/50 bg-cyber/10 flex items-center justify-center text-cyber">
            <Server className="size-4" />
          </div>
          <span className="mt-1 text-[10px] text-muted-foreground bg-background/80 px-1.5 py-0.5 rounded border border-border/50 truncate max-w-[120px]" title={node3Label}>
            {node3Label}
          </span>
        </div>
      </div>

      {/* Help tooltip / Legend button */}
      <div className="absolute top-2 end-2 z-20 group">
        <div className="flex items-center gap-1 text-[10px] text-muted-foreground/80 bg-background/80 hover:bg-background border border-border/60 px-2 py-1 rounded-md cursor-help transition-colors">
          <span className="size-1.5 rounded-full bg-primary animate-pulse" />
          <span>مخطط الارتباطات</span>
        </div>
        <div className="absolute end-0 top-full mt-1.5 hidden group-hover:block w-64 p-3 rounded-xl bg-popover text-popover-foreground border border-border shadow-xl text-xs space-y-1.5 z-50 animate-in fade-in zoom-in-95">
          <p className="font-semibold text-foreground border-b border-border/50 pb-1 text-[11px]">خريطة الارتباطات السيبرانية (Cyber Topology):</p>
          <div className="flex items-center gap-2 text-[10px]">
            <span className="size-2 rounded-full bg-primary" />
            <span><strong>العقدة المركزية:</strong> الهدف المفحوص</span>
          </div>
          <div className="flex items-center gap-2 text-[10px]">
            <span className="size-2 rounded-full bg-crimson" />
            <span><strong>العقدة العلوية:</strong> الحمولة / التصنيف الأمني</span>
          </div>
          <div className="flex items-center gap-2 text-[10px]">
            <span className="size-2 rounded-full bg-amber" />
            <span><strong>العقدة السفلية:</strong> تكتيك MITRE / قناة C2</span>
          </div>
          <div className="flex items-center gap-2 text-[10px]">
            <span className="size-2 rounded-full bg-cyber" />
            <span><strong>العقدة الجانبية:</strong> شبكة الاستضافة والـ ASN</span>
          </div>
        </div>
      </div>
    </div>
  );
}
