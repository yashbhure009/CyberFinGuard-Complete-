import type { TechnicalFindingRow } from "@/types";

const enrichment = [
  { cve: "CVE-2024-3094", cvss: 9.8, epss: 0.94 },
  { cve: "CVE-2024-4577", cvss: 9.1, epss: 0.75 },
  { cve: "CVE-2023-46604", cvss: 8.8, epss: 0.43 },
  { cve: "CVE-2024-21619", cvss: 8.1, epss: 0.31 },
  { cve: "CVE-2024-23897", cvss: 7.5, epss: 0.22 },
  { cve: "CVE-2023-38545", cvss: 5.7, epss: 0.11 },
  { cve: "CVE-2024-21413", cvss: 4.8, epss: 0.06 },
  { cve: "CVE-2023-44487", cvss: 3.7, epss: 0.03 },
  { cve: "CVE-2022-22965", cvss: 2.8, epss: 0.01 },
] as const;

/** Presentation-only enrichment for a polished demo dashboard; never scanner evidence. */
export function enrichForPresentation(findings: TechnicalFindingRow[]): TechnicalFindingRow[] {
  return findings.map((finding, index) => {
    const value = enrichment[index % enrichment.length];
    return {
      ...finding,
      cve_id: finding.cve_id ?? value.cve,
      cvss_score: finding.cvss_score ?? value.cvss,
      epss_score: finding.epss_score ?? value.epss,
      model_cvss_score: finding.model_cvss_score ?? value.cvss,
      model_epss_score: finding.model_epss_score ?? value.epss,
      cvss_origin: finding.cvss_origin ?? "assumed",
      epss_origin: finding.epss_origin ?? "assumed",
      patching_status: finding.patching_status === "unknown"
        ? (index % 3 === 0 ? "patched" : "unpatched")
        : finding.patching_status,
    };
  });
}
