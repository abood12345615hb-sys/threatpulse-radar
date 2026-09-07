import { useEffect, useRef, useState, useMemo } from "react";
import { useLanguage } from "@/contexts/LanguageContext";
import type { GlobeNode } from "@/types";

const severityColor: Record<GlobeNode["severity"], string> = {
  clean: "#10B981",
  suspicious: "#F59E0B",
  malicious: "#FF0055",
};

// Procedural continent landmass dot matrix for cyber globe
function generateContinentDots(): Array<{ lat: number; lon: number }> {
  const dots: Array<{ lat: number; lon: number }> = [];
  const regions = [
    // North America
    { minLat: 20, maxLat: 60, minLon: -125, maxLon: -70, count: 65 },
    // South America
    { minLat: -50, maxLat: 10, minLon: -75, maxLon: -40, count: 40 },
    // Europe
    { minLat: 36, maxLat: 65, minLon: -10, maxLon: 38, count: 55 },
    // Africa
    { minLat: -32, maxLat: 34, minLon: -15, maxLon: 45, count: 60 },
    // Middle East & Arabian Peninsula
    { minLat: 14, maxLat: 36, minLon: 34, maxLon: 58, count: 35 },
    // Asia & East Asia
    { minLat: 12, maxLat: 62, minLon: 60, maxLon: 135, count: 85 },
    // Australia & Oceania
    { minLat: -38, maxLat: -14, minLon: 115, maxLon: 152, count: 30 },
  ];

  regions.forEach((r) => {
    for (let i = 0; i < r.count; i++) {
      const lat = r.minLat + Math.random() * (r.maxLat - r.minLat);
      const lon = r.minLon + Math.random() * (r.maxLon - r.minLon);
      dots.push({ lat, lon });
    }
  });

  return dots;
}

export function ThreatGlobe({
  nodes,
  interactive = true,
}: {
  nodes?: GlobeNode[];
  interactive?: boolean;
}) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const { t, lang } = useLanguage();

  const [hoveredNode, setHoveredNode] = useState<GlobeNode | null>(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });

  // Default active telemetry nodes if none provided
  const activeNodes: GlobeNode[] = useMemo(() => {
    if (nodes && nodes.length > 0) return nodes;
    return [
      { id: "sa-1", label: "Riyadh SOC Gateway", lat: 24.7, lon: 46.7, severity: "clean" },
      { id: "us-1", label: "US East (Ashburn)", lat: 39.0, lon: -77.5, severity: "clean" },
      { id: "de-1", label: "Frankfurt Relay", lat: 50.1, lon: 8.7, severity: "malicious" },
      { id: "ru-1", label: "Moscow C2 Node", lat: 55.7, lon: 37.6, severity: "malicious" },
      { id: "nl-1", label: "Amsterdam Tor Exit", lat: 52.4, lon: 4.9, severity: "suspicious" },
      { id: "cn-1", label: "Shanghai Botnet", lat: 31.2, lon: 121.5, severity: "malicious" },
      { id: "ae-1", label: "Dubai Sensor", lat: 25.2, lon: 55.3, severity: "clean" },
      { id: "ye-1", label: "Sanaa Telemetry Edge", lat: 15.3, lon: 44.2, severity: "clean" },
    ];
  }, [nodes]);

  const continentDots = useMemo(() => generateContinentDots(), []);

  // Drag interaction state
  const isDragging = useRef(false);
  const lastMousePos = useRef({ x: 0, y: 0 });
  const rotRef = useRef({ yaw: 0, pitch: 0.15 });
  const autoRotateSpeed = useRef(0.005);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let raf = 0;
    let beamPhase = 0;

    // Projected nodes cache for hover detection
    let projectedNodes: Array<{
      node: GlobeNode;
      x: number;
      y: number;
      radius: number;
      visible: boolean;
    }> = [];

    const draw = () => {
      const dpr = window.devicePixelRatio || 1;
      const size = canvas.clientWidth;
      canvas.width = size * dpr;
      canvas.height = size * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, size, size);

      const cx = size / 2;
      const cy = size / 2;
      const r = size * 0.38;

      if (!isDragging.current) {
        rotRef.current.yaw += autoRotateSpeed.current;
      }

      const { yaw, pitch } = rotRef.current;

      // 3D Rotation Matrix projection
      const project = (latDeg: number, lonDeg: number, altitude = 1) => {
        const lat = (latDeg * Math.PI) / 180;
        const lon = (lonDeg * Math.PI) / 180 + yaw;

        // Spherical to 3D Cartesian
        let x = Math.cos(lat) * Math.sin(lon);
        let y = -Math.sin(lat);
        let z = Math.cos(lat) * Math.cos(lon);

        // Pitch tilt (X-axis rotation)
        const cosP = Math.cos(pitch);
        const sinP = Math.sin(pitch);
        const yRot = y * cosP - z * sinP;
        const zRot = y * sinP + z * cosP;

        return {
          px: cx + x * r * altitude,
          py: cy + yRot * r * altitude,
          pz: zRot,
          visible: zRot > -0.15,
          scale: Math.max(0.2, (zRot + 1) / 2),
        };
      };

      // 1. Outer Cyber Glow (Atmosphere)
      const glowGrad = ctx.createRadialGradient(cx, cy, r * 0.85, cx, cy, r * 1.25);
      glowGrad.addColorStop(0, "rgba(0, 240, 255, 0.15)");
      glowGrad.addColorStop(0.5, "rgba(0, 180, 255, 0.05)");
      glowGrad.addColorStop(1, "rgba(0, 0, 0, 0)");
      ctx.beginPath();
      ctx.arc(cx, cy, r * 1.25, 0, Math.PI * 2);
      ctx.fillStyle = glowGrad;
      ctx.fill();

      // 2. Dark Cyber Sphere Core
      const sphereGrad = ctx.createRadialGradient(cx - r * 0.35, cy - r * 0.35, r * 0.1, cx, cy, r);
      sphereGrad.addColorStop(0, "rgba(10, 26, 47, 0.85)");
      sphereGrad.addColorStop(0.7, "rgba(4, 13, 26, 0.95)");
      sphereGrad.addColorStop(1, "rgba(2, 6, 14, 0.98)");
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.fillStyle = sphereGrad;
      ctx.fill();

      // 3. Grid Rings (Cyber Latitude / Longitude)
      ctx.lineWidth = 1;
      ctx.strokeStyle = "rgba(0, 240, 255, 0.12)";
      for (let lat = -60; lat <= 60; lat += 30) {
        ctx.beginPath();
        let first = true;
        for (let lon = 0; lon <= 360; lon += 10) {
          const pt = project(lat, lon);
          if (pt.visible) {
            if (first) {
              ctx.moveTo(pt.px, pt.py);
              first = false;
            } else {
              ctx.lineTo(pt.px, pt.py);
            }
          } else {
            first = true;
          }
        }
        ctx.stroke();
      }

      // Outer bounding neon ring
      ctx.strokeStyle = "rgba(0, 240, 255, 0.35)";
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.stroke();

      // 4. Continents Dot Matrix
      continentDots.forEach((dot) => {
        const pt = project(dot.lat, dot.lon);
        if (pt.visible) {
          ctx.beginPath();
          ctx.arc(pt.px, pt.py, 1.2 * pt.scale, 0, Math.PI * 2);
          ctx.fillStyle = `rgba(0, 240, 255, ${0.15 + pt.scale * 0.45})`;
          ctx.fill();
        }
      });

      // 5. Cyber Attack Arcs (Laser Beams connecting nodes)
      beamPhase = (beamPhase + 0.012) % 1;
      const maliciousNodes = activeNodes.filter((n) => n.severity === "malicious");
      const targetNodes = activeNodes.filter((n) => n.severity !== "malicious");

      if (maliciousNodes.length > 0 && targetNodes.length > 0) {
        maliciousNodes.slice(0, 3).forEach((src, idx) => {
          const dst = targetNodes[idx % targetNodes.length]!;
          const p1 = project(src.lat, src.lon);
          const p2 = project(dst.lat, dst.lon);

          if (p1.visible || p2.visible) {
            // Midpoint elevated in 3D
            const midLat = (src.lat + dst.lat) / 2;
            const midLon = (src.lon + dst.lon) / 2;
            const mid = project(midLat, midLon, 1.35);

            // Draw glowing curved trajectory
            ctx.beginPath();
            ctx.moveTo(p1.px, p1.py);
            ctx.quadraticCurveTo(mid.px, mid.py, p2.px, p2.py);
            ctx.strokeStyle = "rgba(255, 0, 85, 0.28)";
            ctx.lineWidth = 1.5;
            ctx.stroke();

            // Traveling Attack Light Pulse (Laser Bullet)
            const t = (beamPhase + idx * 0.33) % 1;
            const invT = 1 - t;
            // Quadratic Bezier formula
            const bx = invT * invT * p1.px + 2 * invT * t * mid.px + t * t * p2.px;
            const by = invT * invT * p1.py + 2 * invT * t * mid.py + t * t * p2.py;

            ctx.beginPath();
            ctx.arc(bx, by, 3, 0, Math.PI * 2);
            ctx.fillStyle = "#FF0055";
            ctx.shadowColor = "#FF0055";
            ctx.shadowBlur = 8;
            ctx.fill();
            ctx.shadowBlur = 0; // reset
          }
        });
      }

      // 6. Active Threat Nodes with Multi-Ring Radar Pulses
      const now = Date.now() * 0.003;
      projectedNodes = [];

      activeNodes.forEach((n) => {
        const pt = project(n.lat, n.lon);
        if (!pt.visible) return;

        const color = severityColor[n.severity];
        const pulse = (Math.sin(now + hash(n.id)) + 1) / 2;

        // Store for hover detection
        projectedNodes.push({
          node: n,
          x: pt.px,
          y: pt.py,
          radius: 12 * pt.scale,
          visible: pt.visible,
        });

        // Pulsing radar ping wave
        ctx.beginPath();
        ctx.arc(pt.px, pt.py, (6 + pulse * 14) * pt.scale, 0, Math.PI * 2);
        ctx.strokeStyle = color + Math.round((1 - pulse) * 180).toString(16).padStart(2, "0");
        ctx.lineWidth = 1.2;
        ctx.stroke();

        // Secondary ring
        ctx.beginPath();
        ctx.arc(pt.px, pt.py, 4.5 * pt.scale, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();

        // Core bright center
        ctx.beginPath();
        ctx.arc(pt.px, pt.py, 1.8 * pt.scale, 0, Math.PI * 2);
        ctx.fillStyle = "#FFFFFF";
        ctx.fill();
      });

      raf = requestAnimationFrame(draw);
    };

    raf = requestAnimationFrame(draw);

    // Mouse & Touch interaction handlers
    const onMouseDown = (e: MouseEvent) => {
      if (!interactive) return;
      isDragging.current = true;
      lastMousePos.current = { x: e.clientX, y: e.clientY };
    };

    const onMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;

      if (isDragging.current) {
        const dx = e.clientX - lastMousePos.current.x;
        const dy = e.clientY - lastMousePos.current.y;
        rotRef.current.yaw += dx * 0.008;
        rotRef.current.pitch = Math.max(-0.6, Math.min(0.6, rotRef.current.pitch + dy * 0.008));
        lastMousePos.current = { x: e.clientX, y: e.clientY };
      }

      // Hover collision detection
      const hovered = projectedNodes.find((pn) => {
        const dist = Math.hypot(pn.x - mouseX, pn.y - mouseY);
        return dist < pn.radius;
      });

      if (hovered) {
        setHoveredNode(hovered.node);
        setTooltipPos({ x: hovered.x, y: hovered.y });
      } else if (!isDragging.current) {
        setHoveredNode(null);
      }
    };

    const onMouseUp = () => {
      isDragging.current = false;
    };

    const onMouseLeave = () => {
      isDragging.current = false;
      setHoveredNode(null);
    };

    canvas.addEventListener("mousedown", onMouseDown);
    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
    canvas.addEventListener("mouseleave", onMouseLeave);

    return () => {
      cancelAnimationFrame(raf);
      canvas.removeEventListener("mousedown", onMouseDown);
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mouseup", onMouseUp);
      canvas.removeEventListener("mouseleave", onMouseLeave);
    };
  }, [activeNodes, continentDots, interactive]);

  function hash(str: string): number {
    let h = 0;
    for (let i = 0; i < str.length; i++) h = (h << 5) - h + str.charCodeAt(i);
    return Math.abs(h);
  }

  return (
    <div ref={containerRef} className="relative flex flex-col items-center">
      {/* Title & Live Status Indicator */}
      <div className="flex w-full items-center justify-between px-2 mb-2">
        <div className="flex items-center gap-2">
          <span className="relative flex size-2.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full size-2.5 bg-cyan-400"></span>
          </span>
          <span className="text-xs font-semibold uppercase tracking-wider text-cyan-400">
            {lang === "ar" ? "رادار التهديدات العالمي الحي (3D Globe)" : "Live 3D Threat Telemetry"}
          </span>
        </div>
        <span className="text-[10px] font-mono text-muted-foreground">
          {lang === "ar" ? "اسحب للتدوير 3D" : "Drag to Rotate 3D"}
        </span>
      </div>

      {/* 3D Canvas with Glowing Cyber Horizon */}
      <div className="relative w-full max-w-[480px] aspect-square flex items-center justify-center cursor-grab active:cursor-grabbing">
        <canvas ref={canvasRef} className="w-full h-full" />

        {/* Interactive Futuristic HUD Tooltip */}
        {hoveredNode && (
          <div
            className="absolute z-20 pointer-events-none -translate-x-1/2 -translate-y-full mb-3 rounded-lg border border-cyan-500/50 bg-black/85 px-3 py-2 text-xs font-mono shadow-xl backdrop-blur-md transition-all"
            style={{ left: tooltipPos.x, top: tooltipPos.y }}
          >
            <div className="flex items-center gap-2 mb-1">
              <span
                className="size-2 rounded-full"
                style={{ backgroundColor: severityColor[hoveredNode.severity] }}
              />
              <span className="font-bold text-foreground">{hoveredNode.label}</span>
            </div>
            <div className="text-[10px] text-muted-foreground flex justify-between gap-4">
              <span>LAT: {hoveredNode.lat.toFixed(1)}°</span>
              <span>LON: {hoveredNode.lon.toFixed(1)}°</span>
            </div>
            <div className="mt-1 text-[10px] uppercase font-bold" style={{ color: severityColor[hoveredNode.severity] }}>
              STATUS: {hoveredNode.severity}
            </div>
          </div>
        )}
      </div>

      {/* Nodes Legend Footer */}
      <div className="mt-3 flex flex-wrap justify-center gap-3 font-mono text-[11px]">
        {activeNodes.slice(0, 5).map((n) => (
          <span
            key={n.id}
            className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full border border-border/60 bg-card/60"
          >
            <span
              className="size-1.5 rounded-full"
              style={{ background: severityColor[n.severity] }}
            />
            <span className="truncate max-w-[120px]">{n.label}</span>
          </span>
        ))}
      </div>
    </div>
  );
}
