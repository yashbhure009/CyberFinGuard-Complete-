"use client";

import { useEffect, useState } from "react";
import { AppShell } from "@/components/layout/app-shell";
import { MitigationRecommendationsPanel } from "@/components/risk-analysis/mitigation-recommendations-panel";
import { RiskQuantificationPanel } from "@/components/risk-analysis/risk-quantification-panel";
import { useRiskAnalysisData } from "@/hooks/use-risk-analysis";
import { mockUser } from "@/lib/mock-data";
import { downloadSummaryPdf } from "@/lib/api";

export default function RiskAnalysisPage() {
  const [assetIds, setAssetIds] = useState<string[] | undefined>();
  const [downloadError, setDownloadError] = useState("");
  useEffect(() => { const value = new URLSearchParams(window.location.search).get("assetIds"); setAssetIds(value?.split(",").filter(Boolean)); }, []);
  const { summary, recommendations, recommendationsSource, findings, assumptions, modelStatus, isLoading, error } = useRiskAnalysisData(assetIds);
  async function download() { setDownloadError(""); try { await downloadSummaryPdf(); } catch (cause) { setDownloadError(cause instanceof Error ? cause.message : "Download failed."); } }
  return <AppShell user={mockUser} title="Risk Quantification Workspace" eyebrow="Financial cyber risk analysis"><section className="risk-analysis-page"><div className="risk-analysis-intro"><p className="dashboard-kicker">Quantify <span>{"\u2192"}</span> Prioritize <span>{"\u2192"}</span> Act</p><p className="dashboard-description">Translate current technical exposure into financial context and practical mitigation priorities.</p></div>{error && <p className="error-text">{error}</p>}{isLoading ? <div className="risk-loading app-card">Loading risk analysis{"\u2026"}</div> : <div className="risk-analysis-grid"><RiskQuantificationPanel summary={summary} findings={findings} assumptions={assumptions} /><MitigationRecommendationsPanel recommendations={recommendations} source={recommendationsSource} /></div>}{!isLoading && <><section className="app-card model-results"><h2>Model finding breakdown</h2>{summary.model_results?.length ? <div className="model-results-list">{summary.model_results.map((item) => <article key={item.finding_id}><strong>{item.source}: {item.title}</strong><span>Incident probability: {(item.likelihood.incident_probability * 100).toFixed(1)}%</span><span>Expected loss: INR {item.monte_carlo.eal_inr.toLocaleString("en-IN")}</span><span>VaR 95: INR {item.monte_carlo.var_95_inr.toLocaleString("en-IN")}</span></article>)}</div> : <p>Pending risk calculation.</p>}</section><button className="primary-button" onClick={download} disabled={modelStatus === "pending"}>Download Summary PDF</button>{downloadError && <p className="error-text">{downloadError}</p>}</>}</section></AppShell>;
}

