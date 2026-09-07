import { Globe, Server, FileWarning, Link as LinkIcon, Cpu } from "lucide-react";
import type { Verdict } from "@/types";
import { useLanguage } from "@/contexts/LanguageContext";

interface ThreatGraphProps {
  indicator: string;
  type: "url" | "ip" | "domain";
  verdict: Verdict;
}

export function ThreatGraph({ indicator, type, verdict }: ThreatGraphProps) {
  const { lang } = useLanguage();
  
  // Colors based on verdict
  const mainColor = verdict === 'clean' ? 'text-emerald border-emerald' : verdict === 'suspicious' ? 'text-amber border-amber' : 'text-crimson border-crimson';
  const mainBg = verdict === 'clean' ? 'bg-emerald/10' : verdict === 'suspicious' ? 'bg-amber/10' : 'bg-crimson/10';

  return (
    <div className="relative w-full h-full min-h-[250px] flex items-center justify-center p-4">
      {/* Background Grid & SVG Connections */}
      <svg className="absolute inset-0 w-full h-full pointer-events-none" style={{ zIndex: 0 }}>
         <defs>
           <linearGradient id="line-grad" x1="0%" y1="0%" x2="100%" y2="0%">
             <stop offset="0%" stopColor="currentColor" stopOpacity="0.2" className={mainColor.split(' ')[0]} />
             <stop offset="100%" stopColor="currentColor" stopOpacity="0.8" className={mainColor.split(' ')[0]} />
           </linearGradient>
         </defs>
         
         {/* Line from Center to Top Right (Malware Payload) */}
         <path d="M 50% 50% L 75% 25%" stroke="url(#line-grad)" strokeWidth="2" strokeDasharray="4 4" className="animate-pulse" />
         
         {/* Line from Center to Bottom Right (C2 Server) */}
         <path d="M 50% 50% L 75% 75%" stroke="url(#line-grad)" strokeWidth="2" strokeDasharray="4 4" className="animate-pulse" style={{ animationDelay: '200ms' }} />
         
         {/* Line from Center to Left (Resolved IP) */}
         <path d="M 50% 50% L 25% 50%" stroke="url(#line-grad)" strokeWidth="2" strokeDasharray="4 4" className="animate-pulse" style={{ animationDelay: '400ms' }} />
      </svg>

      {/* Nodes Container */}
      <div className="relative z-10 w-full h-full flex items-center justify-center">
        
        {/* Central Node (The Indicator) */}
        <div className={`absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 flex flex-col items-center justify-center`}>
           <div className={`size-16 rounded-full border-2 ${mainColor} ${mainBg} flex items-center justify-center relative shadow-[0_0_15px_rgba(var(--color-crimson),0.2)]`}>
              <span className={`absolute inset-0 rounded-full border-2 border-inherit animate-ping opacity-20`}></span>
              {type === 'ip' ? <Server className="size-6" /> : type === 'url' ? <LinkIcon className="size-6" /> : <Globe className="size-6" />}
           </div>
           <span className="mt-2 text-xs font-mono font-semibold bg-background/80 px-2 py-0.5 rounded border border-border truncate max-w-[120px]">
             {indicator}
           </span>
        </div>

        {/* Node 1: Payload (Top Right) */}
        <div className="absolute top-[15%] left-[70%] flex flex-col items-center justify-center hover:scale-110 transition-transform cursor-crosshair">
           <div className="size-10 rounded-full border border-crimson/50 bg-crimson/10 flex items-center justify-center text-crimson">
              <FileWarning className="size-4" />
           </div>
           <span className="mt-1 text-[10px] text-muted-foreground bg-background/80 px-1 rounded">Trojan.Win32</span>
        </div>

        {/* Node 2: C2 Server (Bottom Right) */}
        <div className="absolute top-[70%] left-[70%] flex flex-col items-center justify-center hover:scale-110 transition-transform cursor-crosshair">
           <div className="size-10 rounded-full border border-amber/50 bg-amber/10 flex items-center justify-center text-amber">
              <Cpu className="size-4" />
           </div>
           <span className="mt-1 text-[10px] text-muted-foreground bg-background/80 px-1 rounded">C2 Command</span>
        </div>

        {/* Node 3: Resolved IP / Subdomain (Left) */}
        <div className="absolute top-[40%] left-[15%] flex flex-col items-center justify-center hover:scale-110 transition-transform cursor-crosshair">
           <div className="size-10 rounded-full border border-emerald/50 bg-emerald/10 flex items-center justify-center text-emerald">
              <Server className="size-4" />
           </div>
           <span className="mt-1 text-[10px] text-muted-foreground bg-background/80 px-1 rounded">104.21.33.x</span>
        </div>

      </div>
    </div>
  );
}
