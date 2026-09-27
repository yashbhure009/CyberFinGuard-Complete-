"use client";

import { FormEvent, useState } from "react";
import { ArrowRight, BarChart3, ShieldCheck } from "lucide-react";
import { useRouter } from "next/navigation";
import type { User, UserRole } from "@/types";

export default function LoginPage() {
  const router = useRouter();
  const [role, setRole] = useState<UserRole>("CISO");
  const [email, setEmail] = useState("");
  function submit(event: FormEvent) {
    event.preventDefault();
    const user: User = { id: email.toLowerCase(), email, name: email.split("@")[0].replace(/[._-]/g, " "), role };
    sessionStorage.setItem("cyberfinguard-user", JSON.stringify(user));
    router.push("/assessment");
  }
  return <main className="login-page"><div className="login-brand"><div className="brand-mark brand-mark-large"><ShieldCheck size={26} /></div><div><strong>CyberFinGuard</strong><span>Continuous cyber risk quantification</span></div></div><section className="login-card app-card"><div className="login-heading"><p className="eyebrow">Workspace profile</p><h1>Make cyber risk easier to decide.</h1><p>Choose a view and enter your work email to label this browser session.</p></div><div className="role-toggle" role="tablist">{(["CISO", "CFO"] as UserRole[]).map((item) => <button key={item} type="button" className={role === item ? "role-active" : ""} onClick={() => setRole(item)}><span>{item === "CISO" ? <ShieldCheck size={16} /> : <BarChart3 size={16} />}</span>{item}</button>)}</div><form onSubmit={submit}><label className="form-field"><span className="field-label">Work email</span><input className="field-input" value={email} onChange={(event) => setEmail(event.target.value)} type="email" required /></label><button className="primary-button login-submit">Continue <ArrowRight size={16} /></button></form><p className="login-footnote">This profile is local to your browser. The API does not provide account authentication yet.</p></section></main>;
}
