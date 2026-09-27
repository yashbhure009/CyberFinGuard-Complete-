import type {
  BusinessContext,
  CloudIntegration,
  IAMIntegration,
  NetworkTarget,
  WebsiteTarget,
  TechnicalDashboardSummary,
  TechnicalFindingRow,
  ComplianceSummary,
  ComplianceFindingMapping,
} from "@/types";

const API_BASE_URL = (process.env.NEXT_PUBLIC_API_BASE_URL ?? "").replace(/\/$/, "");

interface AssetResponse {
  assetId: string;
  unmappedFields: string[];
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      headers: { "Content-Type": "application/json", ...options?.headers },
    });
  } catch {
    throw new Error("Backend API is not reachable. Start it with: python -m backend.live_api (port 8000).\n");
  }
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    const detail = body?.detail;
    const message = Array.isArray(detail)
      ? detail.map((issue: { msg?: string }) => issue.msg).filter(Boolean).join(", ")
      : detail;
    if (response.status === 404) {
      throw new Error(`Backend route ${path} was not found. Restart the API with: python -m backend.live_api`);
    }
    throw new Error(message || `Request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

const postAsset = (path: string, body: unknown) => request<AssetResponse>(path, {
  method: "POST",
  body: JSON.stringify(body),
});

export async function saveWebsiteTarget(target: WebsiteTarget): Promise<WebsiteTarget> {
  const asset = await postAsset("/api/assets/website", { url: target.url });
  return { ...target, scanStatus: "idle", assetId: asset.assetId, unmappedFields: asset.unmappedFields };
}

export async function saveNetworkTarget(target: NetworkTarget): Promise<NetworkTarget> {
  const asset = await postAsset("/api/assets/network", target);
  return { ...target, assetId: asset.assetId, unmappedFields: asset.unmappedFields };
}

export async function saveCloudIntegration(integration: CloudIntegration): Promise<CloudIntegration> {
  const asset = await postAsset("/api/assets/cloud", { provider: integration.provider, fields: integration.fields });
  return { ...integration, status: "configured", assetId: asset.assetId, unmappedFields: asset.unmappedFields };
}

export async function saveKeycloakIntegration(integration: IAMIntegration): Promise<IAMIntegration> {
  const asset = await postAsset("/api/assets/iam", {
    url: integration.url,
    realm: integration.realm,
    clientId: integration.clientId,
    clientSecret: integration.clientSecret,
  });
  return {
    url: integration.url,
    realm: integration.realm,
    clientId: integration.clientId,
    status: "configured",
    assetId: asset.assetId,
    unmappedFields: asset.unmappedFields,
  };
}

export async function saveBusinessContext(context: BusinessContext): Promise<BusinessContext> {
  const asset = await postAsset("/api/assets/business-context", context);
  return { ...context, assetId: asset.assetId, unmappedFields: asset.unmappedFields };
}

export async function getTechnicalDashboardData(): Promise<{ summary: TechnicalDashboardSummary; findings: TechnicalFindingRow[] }> {
  return request("/api/dashboard/technical");
}

export async function runAssessmentScan(): Promise<{ status: string }> {
  return request("/api/scan/run", { method: "POST" });
}

export async function getScanStatus(): Promise<{ status: "idle" | "running" | "complete" | "failed"; stage: string; error?: string; findings_count?: number; target_url?: string }> {
  return request("/api/scan/status");
}

export async function getAssessmentConfig(): Promise<{ target_url: string | null; asset_id: string | null; business: Record<string, string | number | null>; impact: Record<string, string | number> | null }> {
  return request("/api/assessment/config");
}

export type ModelPreview = { asset: { asset_name: string }; impact: Record<string, string | number>; scan_finding_count: number; controls: Record<string, string> | null; issues: Array<{ finding_id: string; source: string; title: string; payload: { likelihood: Record<string, string | number> }; provenance: Record<string, string> }> };

export async function getModelPreview(): Promise<ModelPreview> { return request("/api/assessment/model-preview"); }
export async function submitAssessment(controls: { mfa: string; waf: string; edr: string }): Promise<number> {
  const result = await request<{ assessment_id: number }>("/api/assessment/submit", { method: "POST", body: JSON.stringify({ controls }) });
  return result.assessment_id;
}
export async function getAssessmentStatus(id: number): Promise<{ status: "pending" | "complete" | "failed"; error?: string }> {
  return request(`/api/assessment/status/${id}`, { cache: "no-store" });
}

export async function getRiskAnalysisData(assetIds?: string[]): Promise<{ summary: import("@/types").RiskQuantificationSummary; findings: TechnicalFindingRow[]; recommendations: import("@/types").MitigationRecommendation[]; assumptions: string[]; model_status: string; impact_inputs: Record<string, string | number> | null }> {
  return request(`/api/risk-analysis${assetIds?.length ? `?assetIds=${encodeURIComponent(assetIds.join(","))}` : ""}`);
}

export async function downloadSummaryPdf(): Promise<void> {
  const result = await fetch(`${API_BASE_URL}/api/assessment/summary.pdf`);
  if (!result.ok) throw new Error("Save an assessment before downloading its PDF.");
  const blob = await result.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "cyberfinguard-risk-summary.pdf";
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export async function getExecutiveDashboardData(): Promise<{ summary: import("@/types").ExecutiveDashboardSummary; assetExposures: import("@/types").AssetFinancialExposure[]; recommendations: import("@/types").MitigationRecommendation[] }> {
  return request("/api/dashboard/executive");
}

export type AssistantMode = "ask" | "simulate";
export type AssistantQueryPayload = {
  mode: AssistantMode;
  question: string;
  scenario?: { type: string; params: Record<string, unknown> };
};
export type AssistantAskResponse = { answer: string; groundedIn: string[] };
export type AssistantSimulationResponse = {
  scenarioSummary: string;
  baselineAle: number | null;
  simulatedAle: number | null;
  deltaPercent: number | null;
  assumptions: string[];
  isIllustrative: true;
};

export async function queryAssistant(mode: AssistantMode, payload: Omit<AssistantQueryPayload, "mode">): Promise<AssistantAskResponse | AssistantSimulationResponse> {
  return request(`/api/assistant/query`, { method: "POST", body: JSON.stringify({ mode, ...payload }) });
}

export async function getComplianceSummary(): Promise<ComplianceSummary> {
  return request("/api/compliance/summary");
}

export async function getComplianceFindings(): Promise<{ findings: ComplianceFindingMapping[]; total_findings: number }> {
  return request("/api/compliance/findings");
}
