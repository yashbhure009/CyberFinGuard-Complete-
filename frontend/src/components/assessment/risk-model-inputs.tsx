"use client";

import { useEffect, useState } from "react";
import { getAssessmentStatus, getModelPreview, submitAssessment, type ModelPreview } from "@/lib/api";

const autoFields = ["cvss_score", "epss_score", "exploit_available", "exploit_type", "threat_actor", "malware", "mitre_technique", "patched"] as const;
const controls = ["mfa", "waf", "edr"] as const;

export function RiskModelInputs({ onSaved }: { onSaved: () => void }) {
  const [preview, setPreview] = useState<ModelPreview | null>(null);
  const [values, setValues] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [stage, setStage] = useState("");
  const [error, setError] = useState("");
  useEffect(() => {
    getModelPreview().then((data) => {
      setPreview(data);
      if (data.controls) setValues(data.controls);
    }).catch((cause) => setError(cause instanceof Error ? cause.message : "Unable to load scan inputs."));
  }, []);
  async function save() {
    setError("");
    if (controls.some((key) => values[key] !== "Yes" && values[key] !== "No")) {
      setError("Choose Yes or No for MFA, WAF, and EDR.");
      return;
    }
    setBusy(true);
    try {
      setStage("Saving inputs to database...");
      const assessmentId = await submitAssessment({ mfa: values.mfa, waf: values.waf, edr: values.edr });
      setStage("Calculating with hosted risk model...");
      let complete = false;
      for (let attempt = 0; attempt < 90; attempt++) {
        const result = await getAssessmentStatus(assessmentId);
        if (result.status === "failed") throw new Error(result.error || "Risk model calculation failed.");
        if (result.status === "complete") { complete = true; break; }
        await new Promise((resolve) => window.setTimeout(resolve, 2000));
      }
      if (!complete) throw new Error("Calculation is still running. Your inputs are saved; refresh the results page shortly.");
      onSaved();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Unable to calculate risk."); }
    finally { setBusy(false); setStage(""); }
  }
  return <>
    <p className="form-hint">Risk inputs below come from the completed scan and documented defaults. Fields marked inferred are model defaults, not observed evidence. Impact values come from your saved business context.</p>
    {preview ? <>
      <p className="form-hint">{preview.scan_finding_count} distinct scanner issues for {preview.asset.asset_name}.</p>
      <div className="form-grid">{controls.map((key) => <label className="form-field" key={key}><span className="field-label">{key.toUpperCase()} enabled</span><select className="field-input" value={values[key] ?? ""} onChange={(event) => setValues({ ...values, [key]: event.target.value })}><option value="">Select...</option><option value="Yes">Yes</option><option value="No">No</option></select></label>)}</div>
      <h3>Auto-filled risk inputs</h3>
      <div className="model-preview-list">{preview.issues.map((issue) => <details key={issue.finding_id}><summary>{issue.source}: {issue.title}</summary><div className="form-grid">{autoFields.map((key) => <label className="form-field" key={key}><span className="field-label">{key.replaceAll("_", " ")} · {issue.provenance[key] ?? "inferred"}</span><input className="field-input" readOnly value={String(issue.payload.likelihood[key])} /></label>)}</div></details>)}</div>
      <h3>Impact inputs from your assessment data</h3><div className="form-grid">{Object.entries(preview.impact).map(([key, value]) => <label className="form-field" key={key}><span className="field-label">{key.replaceAll("_", " ")}</span><input className="field-input" readOnly value={String(value)} /></label>)}</div>
      <button className="primary-button" onClick={save} disabled={busy}>{busy ? stage : "Save inputs and calculate risk"}</button>
    </> : <p>Loading scan inputs...</p>}
    {error && <p className="error-text">{error}</p>}
  </>;
}

