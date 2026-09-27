"use client";

import { useState } from "react";
import { AppShell } from "@/components/layout/app-shell";
import { ExecutiveDashboard } from "@/components/executive/executive-dashboard";
import { InvestmentRiskReductionCurveChart } from "@/components/executive/investment-risk-reduction-curve-chart";
import { InvestmentOptimization } from "@/components/executive/investment-optimization";
import { useExecutiveDashboardData } from "@/hooks/use-executive-dashboard";
import { mockUser } from "@/lib/mock-data";

export default function ExecutiveDashboardPage() {
  const { summary, assetExposures, recommendations, complianceSummary, isLoading, error } = useExecutiveDashboardData();
  const [selectedBusinessUnit, setSelectedBusinessUnit] = useState<string | null>(null);
  return <AppShell user={mockUser} title="Executive Dashboard" eyebrow="Business risk & financial exposure"><section className="executive-dashboard-shell">{error && <p className="error-text">Dashboard data unavailable: {error}</p>}{isLoading && <p className="executive-loading">Loading live dashboard data…</p>}<InvestmentRiskReductionCurveChart recommendations={recommendations} /><InvestmentOptimization recommendations={recommendations} summary={summary} /><ExecutiveDashboard summary={summary} assetExposures={assetExposures} recommendations={recommendations} complianceSummary={complianceSummary} selectedBusinessUnit={selectedBusinessUnit} onBusinessUnitSelect={(businessUnit) => setSelectedBusinessUnit(businessUnit || null)} /></section></AppShell>;
}
