import type { TechnicalFindingRow } from "@/types";
import { technicalSeverityLevels } from "@/lib/technical-dashboard/severity-config";

export interface CvssEpssPoint { x: number; y: number; findingId: string; provenance: string; }

export function groupBySeverityForScatter(findings: TechnicalFindingRow[]): { key: string; points: CvssEpssPoint[] }[] {
  return technicalSeverityLevels.map((key) => ({ key, points: findings.filter((finding) => finding.severity === key && (finding.model_cvss_score ?? finding.cvss_score) != null && (finding.model_epss_score ?? finding.epss_score) != null).map((finding) => ({ x: (finding.model_cvss_score ?? finding.cvss_score) as number, y: (finding.model_epss_score ?? finding.epss_score) as number, findingId: finding.finding_id, provenance: finding.cvss_origin === "scanner" && finding.epss_origin === "threat_intel" ? "Observed" : "Presentation estimate" })), }));
}
