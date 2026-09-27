export const technicalSeverityLevels = ["critical", "high", "medium", "low", "info"] as const;
export type TechnicalSeverity = (typeof technicalSeverityLevels)[number];
export const technicalSeverityConfig: Record<TechnicalSeverity, { label: string; color: string }> = {
  critical: { label: "Critical", color: "var(--danger)" }, high: { label: "High", color: "var(--warning)" }, medium: { label: "Medium", color: "#92751b" }, low: { label: "Low", color: "var(--success)" },
  info: { label: "Info", color: "var(--muted)" },
};
