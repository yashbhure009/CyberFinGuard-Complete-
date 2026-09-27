"use client";

import { useEffect, useState } from "react";
import { getComplianceSummary, getExecutiveDashboardData } from "@/lib/api";
import type { AssetFinancialExposure, ComplianceSummary, ExecutiveDashboardSummary, MitigationRecommendation } from "@/types";

export function useExecutiveDashboardData(): {
  summary: ExecutiveDashboardSummary;
  assetExposures: AssetFinancialExposure[];
  recommendations: MitigationRecommendation[];
  complianceSummary: ComplianceSummary | null;
  isLoading: boolean;
  error: string | null;
} {
  const [complianceSummary, setComplianceSummary] = useState<ComplianceSummary | null>(null);
  const [assetExposures, setAssetExposures] = useState<AssetFinancialExposure[]>([]);
  const [recommendations, setRecommendations] = useState<MitigationRecommendation[]>([]);
  const [summary, setSummary] = useState<ExecutiveDashboardSummary>({ total_ale: null, total_estimated_var: null, total_recommended_investment: null, average_roi: null, critical_assets: 0, compliance_coverage_percent: null, enterprise_risk_score: null });
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    const refresh = () => Promise.all([getExecutiveDashboardData(), getComplianceSummary()])
      .then(([dashboard, compliance]) => { if (active) { setAssetExposures(dashboard.assetExposures); setRecommendations(dashboard.recommendations); setComplianceSummary(compliance); setSummary({ ...dashboard.summary, compliance_coverage_percent: compliance.total_findings ? compliance.frameworks.reduce((sum, item) => sum + (item.coverage_percent ?? 0), 0) / compliance.frameworks.length : null }); setError(null); } })
      .catch((requestError) => { if (active) setError(requestError instanceof Error ? requestError.message : "Unable to load compliance coverage."); })
      .finally(() => { if (active) setIsLoading(false); });
    void refresh();
    const timer = window.setInterval(() => { void refresh(); }, 5000);
    return () => { active = false; window.clearInterval(timer); };
  }, []);

  return { summary, assetExposures, recommendations, complianceSummary, isLoading, error };
}
