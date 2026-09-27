"use client";

import { useEffect, useState } from "react";
import type { MitigationRecommendation, RiskQuantificationSummary, TechnicalFindingRow } from "@/types";
import { getRiskAnalysisData } from "@/lib/api";

export function useRiskAnalysisData(assetIds?: string[]): { summary: RiskQuantificationSummary; recommendations: MitigationRecommendation[]; recommendationsSource: "database"; findings: TechnicalFindingRow[]; assumptions: string[]; modelStatus: string; isLoading: boolean; error: string | null } {
  const [isLoading, setIsLoading] = useState(true);
  const [summary, setSummary] = useState<RiskQuantificationSummary>({ asset_name: "No asset selected", criticality: null, asset_value: null, business_unit: null });
  const [findings, setFindings] = useState<TechnicalFindingRow[]>([]);
  const [recommendations, setRecommendations] = useState<MitigationRecommendation[]>([]);
  const [assumptions, setAssumptions] = useState<string[]>([]);
  const [modelStatus, setModelStatus] = useState("pending");
  const [error, setError] = useState<string | null>(null);
  const recommendationsSource = "database" as const;
  useEffect(() => {
    let active = true;
    const refresh = () => getRiskAnalysisData(assetIds).then((data) => { if (active) { setSummary(data.summary); setFindings(data.findings); setRecommendations(data.recommendations); setAssumptions(data.assumptions); setModelStatus(data.model_status); setError(null); } })
      .catch((cause) => { if (active) setError(cause instanceof Error ? cause.message : "Unable to load risk analysis."); })
      .finally(() => { if (active) setIsLoading(false); });
    void refresh();
    const timer = window.setInterval(() => { void refresh(); }, 5000);
    return () => { active = false; window.clearInterval(timer); };
  }, [assetIds?.join(",")]);
  return { summary, recommendations, recommendationsSource, findings, assumptions, modelStatus, isLoading, error };
}
