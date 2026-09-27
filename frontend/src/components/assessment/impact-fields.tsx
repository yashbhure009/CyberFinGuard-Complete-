"use client";

export type ImpactForm = Record<string, string>;

const numbers: [string, string, string?][] = [
  ["customers_affected", "Customers affected", "1"],
  ["records_affected", "Records affected", "1"],
  ["downtime_hours", "Downtime hours", "any"],
  ["recovery_time_hours", "Recovery time hours", "any"],
  ["recovery_capability", "Recovery capability (0 to 1)", "any"],
  ["business_continuity_score", "Business continuity score (0 to 1)", "any"],
  ["revenue_per_hour", "Revenue per hour (INR)", "any"],
];
const choices: [string, string, string[]][] = [
  ["data_sensitivity", "Data sensitivity", ["Public", "Internal", "Confidential"]],
  ["data_type", "Data type", ["Financial", "Credentials", "Intellectual_Property", "Operational"]],
  ["regulatory_jurisdiction", "Regulatory jurisdiction", ["GDPR", "DPDPA", "RBI", "SEBI"]],
  ["backup_availability", "Backup availability", ["Yes", "No"]],
];

export function ImpactFields({ value, onChange }: { value: ImpactForm; onChange: (next: ImpactForm) => void }) {
  const set = (key: string, next: string) => onChange({ ...value, [key]: next });
  return <><h3>Impact model inputs</h3><p className="form-hint">Asset value is entered above. These business facts are saved to the database before the scan results are scored.</p><div className="form-grid">
    {numbers.map(([key, label, step]) => <label className="form-field" key={key}><span className="field-label">{label}</span><input className="field-input" type="number" min="0" max={key === "recovery_capability" || key === "business_continuity_score" ? "1" : undefined} step={step} required value={value[key] ?? ""} onChange={(event) => set(key, event.target.value)} /></label>)}
    {choices.map(([key, label, options]) => <label className="form-field" key={key}><span className="field-label">{label}</span><select className="field-input" required value={value[key] ?? ""} onChange={(event) => set(key, event.target.value)}><option value="">Select...</option>{options.map((option) => <option key={option} value={option}>{option.replaceAll("_", " ")}</option>)}</select></label>)}
  </div></>;
}
