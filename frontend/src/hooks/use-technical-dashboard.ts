"use client";

import { useEffect, useState } from "react";
import type { TechnicalDashboardSummary, TechnicalFindingRow } from "@/types";
import { getTechnicalDashboardData } from "@/lib/api";

const emptySummary: TechnicalDashboardSummary = { total_findings: 0, critical_findings: 0, high_findings: 0, low_findings: 0, info_findings: 0, mfa_edr_coverage_percent: null };

export function useTechnicalDashboardData(): { summary: TechnicalDashboardSummary; findings: TechnicalFindingRow[]; isLoading: boolean; error: string | null } {
  const [isLoading, setIsLoading] = useState(true);
  const [summary, setSummary] = useState<TechnicalDashboardSummary>(emptySummary);
  const [findings, setFindings] = useState<TechnicalFindingRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let active = true;
    const refresh = () => getTechnicalDashboardData().then((data) => { if (active) { setSummary(data.summary); setFindings(data.findings); setError(null); } })
      .catch((cause) => { if (active) setError(cause instanceof Error ? cause.message : "Unable to load findings."); })
      .finally(() => { if (active) setIsLoading(false); });
    void refresh();
    const timer = window.setInterval(() => { void refresh(); }, 5000);
    return () => { active = false; window.clearInterval(timer); };
  }, []);
  return { summary, findings, isLoading, error };
}
