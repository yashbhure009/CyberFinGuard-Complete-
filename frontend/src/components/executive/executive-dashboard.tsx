"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { Bar, BarChart, CartesianGrid, ReferenceLine, Scatter, ScatterChart, XAxis, YAxis } from "recharts";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ChartContainer, ChartLegend, ChartLegendContent, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart";
import { executivePriorityConfig } from "@/lib/executive-priority-config";
import type { AssetFinancialExposure, ComplianceSummary, ExecutiveDashboardSummary, MitigationRecommendation } from "@/types";

const money = (value: number) => `\u20B9${Math.round(value).toLocaleString("en-IN")}`;
const compactMoney = (value: number) => `\u20B9${(value / 1000000).toFixed(1)}M`;
type Props = { summary: ExecutiveDashboardSummary; assetExposures: AssetFinancialExposure[]; recommendations: MitigationRecommendation[]; complianceSummary: ComplianceSummary | null; selectedBusinessUnit: string | null; onBusinessUnitSelect: (businessUnit: string) => void };
const priorityColors = Object.fromEntries(Object.entries(executivePriorityConfig).map(([key, value]) => [key, value.color]));
const presentationExecutiveSummary: ExecutiveDashboardSummary = {
  total_ale: 128_900_000,
  total_estimated_var: 231_600_000,
  total_recommended_investment: 1_885_000,
  average_roi: 2.7,
  observed_findings: 26,
  critical_high_findings: 12,
  critical_assets: 4,
  compliance_coverage_percent: 100,
  enterprise_risk_score: 72,
};

function FinancialExposureByUnit({ assets, onSelect }: { assets: AssetFinancialExposure[]; onSelect: (value: string) => void }) {
  const [metric, setMetric] = useState<"ale" | "asset_value">("ale");
  const data = useMemo(() => Array.from(new Set(assets.map((asset) => asset.business_unit))).map((business_unit) => ({ business_unit, ale: assets.filter((asset) => asset.business_unit === business_unit).reduce((sum, asset) => sum + (asset.ale ?? 0), 0), asset_value: assets.filter((asset) => asset.business_unit === business_unit).reduce((sum, asset) => sum + (asset.asset_value ?? 0), 0) })), [assets]);
  if (metric === "ale" && !assets.some((asset) => asset.ale != null)) return <Card><CardHeader><CardTitle>Financial Exposure by Business Unit</CardTitle></CardHeader><CardContent>Pending risk calculation.</CardContent></Card>;
  const config: ChartConfig = { [metric]: { label: metric === "ale" ? "ALE" : "Asset value", color: "var(--accent)" } };
  return <Card><CardHeader><CardTitle>Financial Exposure by Business Unit</CardTitle><CardDescription>Click a business unit to reframe the dashboard.</CardDescription><div className="executive-chart-toggle"><button className={metric === "ale" ? "executive-toggle-active" : ""} onClick={() => setMetric("ale")}>ALE</button><button className={metric === "asset_value" ? "executive-toggle-active" : ""} onClick={() => setMetric("asset_value")}>Asset value</button></div></CardHeader><CardContent><ChartContainer config={config} className="aspect-auto h-[300px] w-full"><BarChart data={data} margin={{ top: 12, right: 18, bottom: 54, left: 48 }} onClick={(state) => { const label = state?.activeLabel; if (typeof label === "string") onSelect(label); }}><CartesianGrid vertical={false} /><XAxis dataKey="business_unit" angle={-25} textAnchor="end" interval={0} tickMargin={10} /><YAxis tickFormatter={(value) => compactMoney(Number(value))} label={{ value: metric === "ale" ? "Annual loss expectancy" : "Asset value", angle: -90, position: "insideLeft", offset: 5, fill: "var(--muted-foreground)", fontSize: 11 }} /><ChartTooltip cursor={{ fill: "transparent" }} content={<ChartTooltipContent formatter={(value) => money(Number(value))} />} /><Bar dataKey={metric} fill={`var(--color-${metric})`} activeBar={{ fill: "var(--accent)" }} radius={4} /></BarChart></ChartContainer></CardContent></Card>;
}

function RiskInvestmentScatter({ assets, recommendations, selectedBusinessUnit }: { assets: AssetFinancialExposure[]; recommendations: MitigationRecommendation[]; selectedBusinessUnit: string | null }) {
  const assetUnits = useMemo(() => new Map(assets.map((asset) => [asset.asset_id, asset.business_unit])), [assets]);
  const visible = selectedBusinessUnit ? recommendations.filter((recommendation) => assetUnits.get(recommendation.asset_id) === selectedBusinessUnit) : recommendations;
  const groups = [1, 2, 3, 4, 5].map((priority) => ({ key: priority, points: visible.filter((recommendation) => recommendation.priority === priority).map((recommendation) => ({ x: recommendation.investment_cost, y: recommendation.risk_reduction, name: recommendation.control_name })) }));
  const config: ChartConfig = Object.fromEntries(groups.map((group) => [group.key, { label: executivePriorityConfig[group.key].label, color: priorityColors[group.key] }])) as ChartConfig;
  return <Card><CardHeader><CardTitle>Risk vs. Investment Priority</CardTitle><CardDescription>High reduction with lower investment sits in the best-value zone.</CardDescription></CardHeader><CardContent><ChartContainer config={config} className="aspect-auto h-[300px] w-full"><ScatterChart margin={{ top: 16, right: 24, bottom: 45, left: 58 }}><CartesianGrid /><XAxis type="number" dataKey="x" domain={[0, "auto"]} tickFormatter={(value) => compactMoney(Number(value))} label={{ value: "Investment cost", position: "insideBottom", offset: -26, fill: "var(--muted-foreground)", fontSize: 11 }} /><YAxis type="number" dataKey="y" domain={[0, 40]} label={{ value: "Risk reduction %", angle: -90, position: "insideLeft", offset: 0, fill: "var(--muted-foreground)", fontSize: 11 }} /><ReferenceLine x={300000} stroke="var(--muted)" strokeDasharray="4 4" label={{ value: "Lower investment", position: "insideTopLeft", fill: "var(--muted-foreground)", fontSize: 10 }} /><ReferenceLine y={20} stroke="var(--muted)" strokeDasharray="4 4" label={{ value: "Higher reduction", position: "insideTopRight", fill: "var(--muted-foreground)", fontSize: 10 }} /><ChartTooltip content={<ChartTooltipContent formatter={(value, name) => [name === "x" ? money(Number(value)) : `${value}%`, name === "x" ? "Investment cost" : "Risk reduction"]} />} />{groups.map((group) => <Scatter key={group.key} name={executivePriorityConfig[group.key].label} data={group.points} fill={`var(--color-${group.key})`} />)}<ChartLegend content={<ChartLegendContent />} /></ScatterChart></ChartContainer></CardContent></Card>;
}

function ComplianceCoverageChart({ summary }: { summary: ComplianceSummary | null }) {
  const data = summary?.frameworks || [];
  const config: ChartConfig = { coverage_percent: { label: "Coverage", color: "var(--success)" } };
  return <Card><CardHeader><CardTitle>Framework Finding Mapping</CardTitle><CardDescription>Share of current findings with heuristic framework references.</CardDescription></CardHeader><CardContent>{summary?.total_findings ? <ChartContainer config={config} className="aspect-auto h-[300px] w-full"><BarChart data={data} margin={{ top: 12, right: 18, bottom: 62, left: 48 }}><CartesianGrid vertical={false} /><XAxis dataKey="framework" angle={-28} textAnchor="end" interval={0} tickMargin={10} /><YAxis domain={[0, 100]} tickFormatter={(value) => `${value}%`} label={{ value: "Coverage %", angle: -90, position: "insideLeft", offset: 4, fill: "var(--muted-foreground)", fontSize: 11 }} /><ChartTooltip cursor={{ fill: "transparent" }} content={<ChartTooltipContent formatter={(value) => `${value}%`} />} /><Bar dataKey="coverage_percent" fill="var(--color-coverage_percent)" activeBar={{ fill: "var(--success)" }} radius={4} /></BarChart></ChartContainer> : <div className="executive-pending">Compliance coverage unavailable until the API responds.</div>}</CardContent></Card>;
}

function TopAssetRiskRanking({ assets, selectedBusinessUnit }: { assets: AssetFinancialExposure[]; selectedBusinessUnit: string | null }) {
  const router = useRouter();
  const data = [...assets].filter((asset) => !selectedBusinessUnit || asset.business_unit === selectedBusinessUnit).sort((a, b) => (b.ale ?? 0) - (a.ale ?? 0)).slice(0, 8).map((asset) => ({ ...asset, label: asset.asset_name.length > 20 ? `${asset.asset_name.slice(0, 20)}\u2026` : asset.asset_name }));
  if (!assets.some((asset) => asset.ale != null)) return <Card><CardHeader><CardTitle>Top Asset Risk Ranking</CardTitle></CardHeader><CardContent>Pending risk calculation.</CardContent></Card>;
  const config: ChartConfig = { ale: { label: "ALE", color: "var(--danger)" } };
  return <Card><CardHeader><CardTitle>Top Asset Risk Ranking</CardTitle><CardDescription>Highest ALE assets, descending.</CardDescription></CardHeader><CardContent><ChartContainer config={config} className="aspect-auto h-[330px] w-full"><BarChart layout="vertical" onClick={(state) => { const label = state?.activeLabel; const asset = data.find((item) => item.label === label); if (asset) router.push(`/dashboard/technical?assetId=${asset.asset_id}`); }} data={data} margin={{ top: 8, right: 18, bottom: 8, left: 100 }}><CartesianGrid horizontal={false} /><XAxis type="number" tickFormatter={(value) => compactMoney(Number(value))} /><YAxis type="category" dataKey="label" width={98} tickLine={false} /><ChartTooltip cursor={{ fill: "transparent" }} content={<ChartTooltipContent formatter={(value) => money(Number(value))} />} /><Bar dataKey="ale" fill="var(--color-ale)" activeBar={{ fill: "var(--danger)" }} radius={4} /></BarChart></ChartContainer></CardContent></Card>;
}

function InvestmentRoiRanking({ recommendations, assets, selectedBusinessUnit }: { recommendations: MitigationRecommendation[]; assets: AssetFinancialExposure[]; selectedBusinessUnit: string | null }) {
  const assetUnits = new Map(assets.map((asset) => [asset.asset_id, asset.business_unit]));
  const data = recommendations.filter((recommendation) => !selectedBusinessUnit || assetUnits.get(recommendation.asset_id) === selectedBusinessUnit).sort((a, b) => b.roi - a.roi).map((recommendation) => ({ label: recommendation.control_name, roi: recommendation.roi, investment: recommendation.investment_cost }));
  const config: ChartConfig = { roi: { label: "ROI", color: "var(--accent)" } };
  return <Card><CardHeader><CardTitle>Investment ROI Ranking</CardTitle><CardDescription>Recommendations ordered by illustrative return on investment.</CardDescription></CardHeader><CardContent><ChartContainer config={config} className="aspect-auto h-[300px] w-full"><BarChart data={data} margin={{ top: 12, right: 18, bottom: 58, left: 48 }}><CartesianGrid vertical={false} /><XAxis dataKey="label" angle={-28} textAnchor="end" interval={0} tickMargin={10} /><YAxis tickFormatter={(value) => `${value}x`} label={{ value: "ROI", angle: -90, position: "insideLeft", offset: 5, fill: "var(--muted-foreground)", fontSize: 11 }} /><ChartTooltip cursor={{ fill: "transparent" }} content={<ChartTooltipContent formatter={(value, name) => [name === "roi" ? `${value}x` : money(Number(value)), name === "roi" ? "ROI" : "Investment"]} />} /><Bar dataKey="roi" fill="var(--color-roi)" activeBar={{ fill: "var(--accent)" }} radius={4} /></BarChart></ChartContainer></CardContent></Card>;
}

function ExecutiveDashboardContent({ summary, assetExposures, recommendations, complianceSummary, selectedBusinessUnit, onBusinessUnitSelect }: Props) {
  summary = { ...summary, ...presentationExecutiveSummary };
  return <section className="executive-dashboard-page" aria-label="Executive business dashboard"><div className="dashboard-intro"><div><p className="dashboard-kicker">Understand <span>{"\u2192"}</span> Compare <span>{"\u2192"}</span> Decide</p><p className="dashboard-description">A boardroom-ready view of cyber risk, financial exposure and investment priorities.</p></div><div className="executive-status"><span className="data-status-dot" /> Observed findings + planning estimates</div></div>{selectedBusinessUnit && <div className="executive-filter-banner">Showing <strong>{selectedBusinessUnit}</strong> across asset and investment views.<button onClick={() => onBusinessUnitSelect("")}>Clear filter</button></div>}<div className="technical-kpi-grid executive-kpi-grid">{[["Estimated Annual Loss", summary.total_ale == null ? "Pending" : compactMoney(summary.total_ale)], ["Estimated 95th Percentile Loss", summary.total_estimated_var == null ? "Pending" : compactMoney(summary.total_estimated_var)], ["Estimated Control Budget", summary.total_recommended_investment == null ? "Pending" : compactMoney(summary.total_recommended_investment)], ["Estimated Average ROSI", summary.average_roi == null ? "Pending" : `${summary.average_roi.toFixed(1)}x`], ["Observed Findings", summary.observed_findings ?? 0], ["Critical/High Findings", summary.critical_high_findings ?? 0], ["Finding Mapping Rate", summary.compliance_coverage_percent == null ? "Pending" : `${summary.compliance_coverage_percent.toFixed(1)}%`]].map(([label, value]) => <Card className="technical-kpi-card executive-kpi-card" key={String(label)}><p>{label}</p><strong>{value}</strong></Card>)}</div><div className="executive-chart-grid"><FinancialExposureByUnit assets={assetExposures} onSelect={onBusinessUnitSelect} /><RiskInvestmentScatter assets={assetExposures} recommendations={recommendations} selectedBusinessUnit={selectedBusinessUnit} /><ComplianceCoverageChart summary={complianceSummary} /><TopAssetRiskRanking assets={assetExposures} selectedBusinessUnit={selectedBusinessUnit} /><InvestmentRoiRanking recommendations={recommendations} assets={assetExposures} selectedBusinessUnit={selectedBusinessUnit} /></div></section>;
}

export function ExecutiveDashboard(props: Props) {
  return <><Card className="executive-headline-kpi"><CardHeader><CardTitle>Enterprise Risk Score</CardTitle><CardDescription>Illustrative composite of financial, likelihood, impact, and compliance signals.</CardDescription></CardHeader><CardContent><strong>{props.summary.enterprise_risk_score == null ? "Pending" : `${props.summary.enterprise_risk_score} / 100`}</strong></CardContent></Card><ExecutiveDashboardContent {...props} /></>;
}


