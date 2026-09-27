export type UserRole = "CISO" | "CFO";

export interface User {
  id: string;
  email: string;
  name: string;
  role: UserRole;
}

export type AssessmentStatus = "draft" | "in_progress" | "ready" | "analyzing" | "complete";

export interface Assessment {
  id: string;
  userId: string;
  organizationName: string;
  status: AssessmentStatus;
  completedSteps: number[];
  createdAt: string;
  updatedAt: string;
}

export interface WebsiteTarget {
  url: string;
  scanStatus: "idle" | "scanning" | "complete" | "failed";
  endpointsAnalyzed?: number;
  findingsDiscovered?: number;
  lastScannedAt?: string;
  assetId?: string;
  unmappedFields?: string[];
}

export interface NetworkTarget {
  ipAddress: string;
  port: number;
  assetId?: string;
  unmappedFields?: string[];
}

export type CloudProvider = "AWS" | "Azure" | "GCP";

export interface CloudIntegration {
  provider: CloudProvider;
  fields: Record<string, string>;
  status: "configured" | "pending";
  assetId?: string;
  unmappedFields?: string[];
}

export interface IAMIntegration {
  url: string;
  realm: string;
  clientId: string;
  status: "configured" | "pending";
  clientSecret?: string;
  assetId?: string;
  unmappedFields?: string[];
}

export interface BusinessContext {
  assetName: string;
  assetType: string;
  businessUnit: string;
  assetOwner: string;
  businessValue: number;
  operationalCriticality: number;
  dataSensitivity: string;
  serviceDependency?: string;
  downtimeCostPerHour?: number;
  regulatoryExposure?: number;
  recoveryCost?: number;
  revenueDependency?: number;
  assetCriticality: number;
  impact: Record<string, string | number>;
  assetId?: string;
  unmappedFields?: string[];
}

export interface AssessmentProgress {
  website?: WebsiteTarget;
  network?: NetworkTarget;
  cloud?: CloudIntegration;
  iam?: IAMIntegration;
  business?: BusinessContext;
}

// risk_scores fields joined with the related asset context; values remain pending until the risk engine populates them.
export interface RiskQuantificationSummary {
  likelihood_score?: number | null;
  impact_score?: number | null;
  sle?: number | null;
  aro?: number | null;
  ale?: number | null;
  asset_name: string;
  criticality: number | null;
  asset_value: number | null;
  business_unit: string | null;
  // Illustrative estimate only — no VaR calculation exists in the schema or risk engine yet. Computed client-side as a simple percentile-style projection from ALE for display purposes. Replace with a real backend-computed VaR if/when one exists.
  estimatedValueAtRisk?: number;
  estimation_method?: string;
  modeled_issues?: number;
  model_results?: Array<{ finding_id: string; source: string; title: string; likelihood: { incident_probability: number; risk_class?: string }; impact: { total_loss_inr: number }; monte_carlo: { eal_inr: number; var_95_inr: number } }>;
}

// Directly mapped from investment_recommendations; risk_reduction is a percentage.
export interface MitigationRecommendation {
  recommendation_id: string;
  asset_id: string;
  control_name: string;
  investment_cost: number;
  risk_reduction: number;
  roi: number;
  priority: number;
  annual_benefit?: number;
  estimated?: boolean;
  basis?: string;
}

export interface AIRecommendation {
  control_name: string;
  description: string;
  risk_reduction: number;
  roi_estimate: string;
  priority: number;
}

// Joined dashboard row: findings columns plus assets, asset_controls, and risk_scores joins.
export interface TechnicalFindingRow {
  finding_id: string; // findings.finding_id
  asset_id: string; // findings.asset_id -> assets.asset_id
  asset_name: string; // assets.asset_name
  asset_type: string; // assets.asset_type
  business_unit: string | null; // assets.business_unit
  dependencies?: string[]; // assets.dependencies
  criticality: number | null; // assets.criticality
  asset_value: number | null; // assets.asset_value
  internet_exposed: boolean; // assets.internet_exposed
  environment: string | null; // assets.environment
  owner: string | null; // assets.owner
  production_status: string | null; // assets.production_status
  source: string; // findings.source
  cve_id: string | null; // findings.cve_id
  cvss_score: number | null; // findings.cvss_score
  epss_score: number | null; // findings.epss_score
  model_cvss_score?: number;
  model_epss_score?: number;
  cvss_origin?: "scanner" | "assumed";
  epss_origin?: "threat_intel" | "assumed";
  cisa_kev: boolean; // findings.cisa_kev
  exploit_available: boolean | null; // findings.exploit_available
  exploit_type: string | null; // findings.exploit_type
  mitre_technique: string | null; // findings.mitre_technique
  title: string; // findings.title
  description?: string | null;
  severity: "critical" | "high" | "medium" | "low" | "info"; // findings.severity
  patching_status: "patched" | "unpatched" | "partial" | "unknown"; // asset_controls.patching_status
  mfa_enabled: boolean | null; // asset_controls.mfa_enabled
  waf_enabled: boolean | null; // asset_controls.waf_enabled
  edr_enabled: boolean | null; // asset_controls.edr_enabled
  firewall_enabled: boolean | null; // asset_controls.firewall_enabled
  encryption_enabled: boolean | null; // asset_controls.encryption_enabled
  backup_exists: boolean | null; // asset_controls.backup_exists
  likelihood_score?: number | null; // risk_scores.likelihood_score
  impact_score?: number | null; // risk_scores.impact_score
  ale?: number | null; // risk_scores.ale
  evidence_url?: string | null;
  evidence?: string | null;
  occurrences?: number;
  created_at: string; // findings.created_at
}

export interface TechnicalDashboardSummary {
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  low_findings: number;
  info_findings: number;
  mfa_edr_coverage_percent: number | null;
}

export interface ComplianceFrameworkSummary {
  framework: "ISO 27001" | "NIST CSF" | "CIS Controls" | "RBI CSCF" | "SEBI CSCRF";
  mapped_findings: number;
  coverage_percent: number | null;
}

export interface ComplianceSummary {
  total_findings: number;
  unmapped_findings: number;
  frameworks: ComplianceFrameworkSummary[];
}

export interface AssetFinancialExposure {
  asset_id: string;
  asset_name: string;
  business_unit: string | null;
  criticality: number | null;
  ale: number | null;
  asset_value: number | null;
  likelihood_score: number | null;
  impact_score: number | null;
}

export interface ExecutiveDashboardSummary {
  observed_findings?: number;
  critical_high_findings?: number;
  total_ale: number | null;
  total_estimated_var: number | null;
  total_recommended_investment: number | null;
  average_roi: number | null;
  critical_assets: number;
  compliance_coverage_percent: number | null;
  enterprise_risk_score: number | null;
}

export interface ComplianceMapping {
  framework: string;
  control_id: string | null;
  match_method: "source_title_rule" | "cwe_fallback" | "unmapped";
  confidence: "high" | "medium" | "none";
}

export interface ComplianceFindingMapping {
  finding_id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  asset_id: string | null;
  mappings: ComplianceMapping[];
}

export interface TechnicalFindingDetail {
  finding_id: string; // findings.finding_id
  asset_id: string; // findings.asset_id -> assets.asset_id
  title: string; // findings.title
  description: string | null; // findings.description
  source: string; // findings.source
  severity: TechnicalFindingRow["severity"]; // findings.severity
  cve_id: string | null; // findings.cve_id
  cvss_score: number | null; // findings.cvss_score
  epss_score: number | null; // findings.epss_score
  cisa_kev: boolean; // findings.cisa_kev
  exploit_available: boolean; // findings.exploit_available
  exploit_type: string | null; // findings.exploit_type
  mitre_technique: string | null; // findings.mitre_technique
  created_at: string; // findings.created_at
  updated_at: string; // findings.updated_at
  asset_name: string; // assets.asset_name
  asset_type: string; // assets.asset_type
  business_unit: string | null; // assets.business_unit
  criticality: number | null; // assets.criticality
  asset_value: number | null; // assets.asset_value
  internet_exposed: boolean; // assets.internet_exposed
  environment: string | null; // assets.environment
  owner: string | null; // assets.owner
  production_status: string | null; // assets.production_status
  mfa_enabled: boolean; // asset_controls.mfa_enabled
  patching_status: TechnicalFindingRow["patching_status"]; // asset_controls.patching_status
  waf_enabled: boolean; // asset_controls.waf_enabled
  edr_enabled: boolean; // asset_controls.edr_enabled
  firewall_enabled: boolean; // asset_controls.firewall_enabled
  encryption_enabled: boolean; // asset_controls.encryption_enabled
  backup_exists: boolean; // asset_controls.backup_exists
  likelihood_score?: number | null; // risk_scores.likelihood_score
  impact_score?: number | null; // risk_scores.impact_score
  ale?: number | null; // risk_scores.ale
  sle?: number | null; // risk_scores.sle
  aro?: number | null; // risk_scores.aro
  complianceDataAvailable: false; // No compliance_mappings table exists yet.
  riskDrivers?: string[]; // populated by a rules helper, not a direct schema field — added here so the type is ready before that helper is built.
  remediationActions?: string[]; // populated by a rules helper, not a direct schema field — added here so the type is ready before that helper is built.
}
