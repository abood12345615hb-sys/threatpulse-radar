export type Verdict = "clean" | "suspicious" | "malicious";

export interface ProviderResult {
  name: "VirusTotal" | "URLhaus" | "AbuseIPDB";
  verdict: Verdict;
  detections: number;
  total: number;
  lastSeen: string;
}

export interface ScanResult {
  id: string;
  indicator: string;
  type: "url" | "ip" | "domain";
  riskScore: number;
  verdict: Verdict;
  scannedAt: string;
  country: string;
  asn: string;
  categories: string[];
  providers: ProviderResult[];
  classification?: string;
  mitreTactic?: string;
  recommendations?: string[];
  screenshotUrl?: string;
  whois?: { registrar: string; created: string; expires: string; };
  ssl?: { issuer: string; valid: boolean; selfSigned: boolean; };
}

export interface ThreatVolumePoint {
  label: string;
  malicious: number;
  suspicious: number;
  clean: number;
}

export interface GlobeNode {
  id: string;
  label: string;
  lat: number;
  lon: number;
  severity: Verdict;
}

export interface LogEntry {
  id: string;
  time: string;
  level: "info" | "warn" | "critical";
  source: string;
  message: string;
}

export interface User {
  id: string;
  fullName: string;
  email: string;
  phone: string;
  whatsappAlerts: boolean;
  role: "analyst" | "admin";
}
