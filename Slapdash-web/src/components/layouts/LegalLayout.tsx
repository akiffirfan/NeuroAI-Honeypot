import { Link } from "@tanstack/react-router";
import { Logo } from "../Logo";
import type { ReactNode } from "react";

export function LegalLayout({ children }: { children: ReactNode }) {
  return (
    <div className="relative min-h-screen bg-[color:var(--canvas)] overflow-hidden">
      <div aria-hidden className="absolute inset-x-0 top-0 h-[420px] nro-grid-bg nro-radial-fade opacity-50 pointer-events-none" />
      <div aria-hidden className="absolute inset-x-0 top-0 h-[420px] nro-accent-glow pointer-events-none" />
      <div className="relative mx-auto" style={{ maxWidth: 820, paddingTop: 56, paddingBottom: 96 }}>
        <div className="px-6">
          <div className="flex items-center justify-between">
            <Logo />
            <Link
              to="/"
              className="text-[13px] text-[color:var(--text-secondary)] hover:text-white"
            >
              ← Back to neuro.cyveera.com
            </Link>
          </div>
          <div className="mt-14 text-[color:var(--text-primary)] nro-card p-10 bg-[color:var(--surface)]/70 backdrop-blur">
            {children}
          </div>
          <p className="mt-6 text-center text-[12px] text-[color:var(--text-secondary)]">
            Questions? Email <span className="font-mono">legal@cyveera.ai</span>
          </p>
        </div>
      </div>
    </div>
  );
}
