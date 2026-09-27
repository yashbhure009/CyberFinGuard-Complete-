"use client";

import { useEffect, useState } from "react";
import { Menu } from "lucide-react";
import { Sidebar } from "@/components/layout/sidebar";
import { DashboardViewLinks } from "@/components/layout/dashboard-view-links";
import type { User } from "@/types";

export function AppShell({ user, title, eyebrow, children }: { user: User; title: string; eyebrow?: string; children: React.ReactNode }) {
  const [collapsed, setCollapsed] = useState(false);
  const [currentUser, setCurrentUser] = useState(user);
  useEffect(() => {
    const stored = sessionStorage.getItem("cyberfinguard-user");
    if (stored) { try { setCurrentUser(JSON.parse(stored) as User); } catch { /* use supplied profile */ } }
  }, []);
  return <div className="shell">
    <Sidebar user={currentUser} collapsed={collapsed} onToggle={() => setCollapsed(!collapsed)} />
    <main className={`main-content ${collapsed ? "main-content-wide" : ""}`}>
      <header className="topbar"><button className="mobile-menu" aria-label="Open navigation"><Menu size={20} /></button><div><p className="eyebrow">{eyebrow || "CyberFinGuard"}</p><h1>{title}</h1></div><div className="topbar-meta">Live data</div></header>
      <DashboardViewLinks />
      {children}
    </main>
  </div>;
}
