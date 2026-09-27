"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Check, Globe2, Landmark, ShieldCheck } from "lucide-react";
import { getAssessmentConfig, getScanStatus, runAssessmentScan, saveBusinessContext, saveWebsiteTarget } from "@/lib/api";
import { websiteSchema } from "@/lib/validators";
import { ImpactFields } from "@/components/assessment/impact-fields";
import { RiskModelInputs } from "@/components/assessment/risk-model-inputs";
import type { User } from "@/types";

const steps = [
  { title: "Website scan", description: "Save the target URL and start the live scan.", icon: Globe2 },
  { title: "Business impact", description: "Enter facts a website scanner cannot observe.", icon: Landmark },
  { title: "Risk review", description: "Review scan inputs and provide MFA, WAF, and EDR status.", icon: ShieldCheck },
];

export function AssessmentStepper({ user }: { user: User }) {
  const router = useRouter();
  const [activeStep, setActiveStep] = useState(0);
  const [completed, setCompleted] = useState<number[]>([]);
  const [website, setWebsite] = useState("");
  const [savedUrl, setSavedUrl] = useState("");
  const [scanStatus, setScanStatus] = useState<"idle" | "running" | "complete" | "failed">("idle");
  const [scanStage, setScanStage] = useState("");
  const [findingCount, setFindingCount] = useState(0);
  const [impact, setImpact] = useState<Record<string, string>>({});
  const [business, setBusiness] = useState({ assetName: "", assetType: "web_application", businessUnit: "", assetOwner: user.name, businessValue: "", assetCriticality: "" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    getAssessmentConfig().then((config) => {
      if (config.target_url) { setWebsite(config.target_url); setSavedUrl(config.target_url); }
      if (config.impact) setImpact(Object.fromEntries(Object.entries(config.impact).filter(([key]) => key !== "asset_value").map(([key, value]) => [key, String(value)])));
      if (config.business) setBusiness((current) => ({
        ...current,
        assetName: config.target_url ? new URL(config.target_url).hostname : current.assetName,
        assetType: String(config.business.asset_type || current.assetType),
        businessUnit: String(config.business.business_unit || current.businessUnit),
        assetOwner: String(config.business.asset_owner || current.assetOwner),
        businessValue: String(config.business.business_value ?? config.impact?.asset_value ?? current.businessValue),
        assetCriticality: String(config.business.asset_criticality ?? current.assetCriticality),
      }));
    }).catch((cause) => setError(cause instanceof Error ? cause.message : "Could not load assessment."));
  }, []);

  useEffect(() => {
    let active = true;
    const poll = () => getScanStatus().then((result) => {
      if (!active) return;
      setScanStatus(result.status);
      setScanStage(result.stage);
      setFindingCount(result.findings_count ?? 0);
      if (result.status === "failed") setError(result.error || "Scan failed. Check data/scan.log.");
    }).catch((cause) => { if (active) setError(cause instanceof Error ? cause.message : "Could not read scan status."); });
    void poll();
    const timer = window.setInterval(poll, 2000);
    return () => { active = false; window.clearInterval(timer); };
  }, []);

  function markDone(index: number) { setCompleted((current) => current.includes(index) ? current : [...current, index]); }

  async function saveTarget() {
    setError("");
    const parsed = websiteSchema.safeParse({ url: website });
    if (!parsed.success) { setError(parsed.error.issues[0].message); return; }
    setBusy(true);
    try {
      const changed = website.trim() !== savedUrl;
      if (changed || !savedUrl) {
        await saveWebsiteTarget({ url: website.trim(), scanStatus: "idle" });
        setSavedUrl(website.trim());
        setBusiness((current) => ({ ...current, assetName: new URL(website.trim()).hostname }));
      }
      if (changed || scanStatus === "idle" || scanStatus === "failed") {
        await runAssessmentScan();
        setScanStatus("running");
        setScanStage("Starting scanners");
        setFindingCount(0);
      }
      markDone(0);
      setActiveStep(1);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Could not start scan."); }
    finally { setBusy(false); }
  }

  async function saveImpact() {
    setError("");
    if (!savedUrl || website.trim() !== savedUrl) { setError("Save the current website URL first."); return; }
    if (!business.businessValue.trim() || !business.assetCriticality.trim()) { setError("Enter asset value and criticality."); return; }
    setBusy(true);
    try {
      await saveBusinessContext({
        assetName: new URL(savedUrl).hostname,
        assetType: business.assetType,
        businessUnit: business.businessUnit,
        assetOwner: business.assetOwner,
        businessValue: Number(business.businessValue),
        operationalCriticality: Number(business.assetCriticality),
        dataSensitivity: impact.data_sensitivity || "",
        assetCriticality: Number(business.assetCriticality),
        impact: { asset_value: business.businessValue, ...impact },
      });
      markDone(1);
      setActiveStep(2);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Could not save business impact."); }
    finally { setBusy(false); }
  }

  return <div className="assessment-layout">
    <div className="stepper-column">{steps.map((step, index) => {
      const Icon = step.icon;
      return <div className={"step-row " + (activeStep === index ? "step-active" : "")} key={step.title}>
        <div className={"step-number " + (completed.includes(index) ? "step-number-done" : "")}>{completed.includes(index) ? <Check size={15} /> : index + 1}</div>
        <div className="step-line-content"><button className="step-heading" onClick={() => setActiveStep(index)}><span><Icon size={17} />{step.title}</span></button><p>{step.description}</p>
          {activeStep === index && <div className="step-form">
            {index === 0 && <><label className="form-field"><span className="field-label">Website URL</span><input className="field-input" value={website} onChange={(event) => setWebsite(event.target.value)} placeholder="https://your-site.example" /></label><button className="primary-button" onClick={saveTarget} disabled={busy}>{busy ? "Starting..." : "Save website and start scan"}</button></>}
            {index === 1 && <><p className="form-hint">The scanner supplies the technical findings. Enter only business impact facts it cannot observe.</p><div className="form-grid">
              <label className="form-field"><span className="field-label">Asset name (from website)</span><input className="field-input" readOnly value={business.assetName || (savedUrl ? new URL(savedUrl).hostname : "")} /></label>
              <label className="form-field"><span className="field-label">Asset type</span><input className="field-input" readOnly value={business.assetType} /></label>
              <label className="form-field"><span className="field-label">Business unit</span><input className="field-input" value={business.businessUnit} onChange={(event) => setBusiness({ ...business, businessUnit: event.target.value })} /></label>
              <label className="form-field"><span className="field-label">Asset owner</span><input className="field-input" value={business.assetOwner} onChange={(event) => setBusiness({ ...business, assetOwner: event.target.value })} /></label>
              <label className="form-field"><span className="field-label">Asset value (INR)</span><input className="field-input" type="number" min="0" value={business.businessValue} onChange={(event) => setBusiness({ ...business, businessValue: event.target.value })} /></label>
              <label className="form-field"><span className="field-label">Asset criticality (3 to 5)</span><input className="field-input" type="number" min="3" max="5" value={business.assetCriticality} onChange={(event) => setBusiness({ ...business, assetCriticality: event.target.value })} /></label>
            </div><ImpactFields value={impact} onChange={setImpact} /><button className="primary-button" onClick={saveImpact} disabled={busy}>{busy ? "Saving..." : "Save business impact"}</button></>}
            {index === 2 && (scanStatus === "complete" ? <RiskModelInputs onSaved={() => { markDone(2); router.push("/risk-analysis"); }} /> : <><p className="form-hint">{scanStatus === "running" ? "Scan is running. Findings appear as each scanner finishes." : scanStatus === "failed" ? "Scan failed. Return to Website scan to retry." : "Start the website scan first."}</p><p>{scanStage}</p><p>{findingCount} findings ingested for this scan</p>{findingCount > 0 && <button className="secondary-button" onClick={() => router.push("/dashboard/technical")}>View live findings</button>}</>)}
            {error && <p className="error-text">{error}</p>}
          </div>}
        </div>
      </div>;
    })}</div>
    <aside className="setup-summary app-card"><div className="summary-icon"><ShieldCheck size={21} /></div><p className="eyebrow">Assessment readiness</p><h2>{scanStatus === "running" ? "Scanning website" : scanStatus === "complete" ? "Scan complete" : "Build your risk picture"}</h2><p>{scanStage || "Save a website to start scanning."}</p><div className="summary-progress"><div><span>Setup progress</span><strong>{Math.round(completed.length / steps.length * 100)}%</strong></div><div className="progress-track"><span style={{ width: (completed.length / steps.length * 100) + "%" }} /></div></div><p className="summary-note">{findingCount} findings in this scan</p>{findingCount > 0 && <button className="secondary-button" onClick={() => router.push("/dashboard/technical")}>View live findings</button>}{completed.length === steps.length && <button className="primary-button" onClick={() => router.push("/risk-analysis")}>View risk results</button>}</aside>
  </div>;
}
