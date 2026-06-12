import type { ReactNode } from "react";

/**
 * Reusable header for private app pages: title, description, optional actions.
 */
export function AppPageHeader({
  title,
  description,
  actions,
  children,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <div className="relative mb-8 -mx-8 px-8 pt-4 pb-7 border-b border-[color:var(--border)] overflow-hidden">
      <div aria-hidden className="absolute inset-0 nro-grid-bg opacity-[0.18] pointer-events-none" />
      <div
        aria-hidden
        className="absolute -top-24 -left-10 w-[420px] h-[260px] pointer-events-none"
        style={{
          background:
            "radial-gradient(ellipse at center, color-mix(in oklab, var(--accent) 18%, transparent), transparent 70%)",
        }}
      />
      <div className="relative flex flex-wrap items-end justify-between gap-6">
        <div className="min-w-0">
          <h1
            className="font-bold text-white"
            style={{ fontSize: 30, letterSpacing: "-0.02em", lineHeight: 1.1 }}
          >
            {title}
          </h1>
          {description && (
            <p className="mt-2 text-[14px] text-[color:var(--text-secondary)] max-w-[680px]">
              {description}
            </p>
          )}
        </div>
        {actions && <div className="flex items-center gap-2 shrink-0">{actions}</div>}
      </div>
      {children && <div className="relative mt-6">{children}</div>}
    </div>
  );
}
