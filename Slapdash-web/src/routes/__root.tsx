import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  Outlet,
  Link,
  createRootRouteWithContext,
} from "@tanstack/react-router";
import { useEffect } from "react";

import { captureError } from "../lib/error-capture";
import { AuthProvider } from "../lib/auth.context";
import { MarketingLayout } from "../components/layouts/MarketingLayout";
import { Logo } from "../components/Logo";

function NotFoundComponent() {
  return (
    <MarketingLayout>
      <div className="min-h-[70vh] flex items-center justify-center px-4">
        <div className="text-center max-w-[520px]">
          <div className="flex justify-center mb-6">
            <Logo />
          </div>
          <div
            className="font-bold"
            style={{ fontSize: 64, color: "var(--text-secondary)", opacity: 0.3 }}
          >
            404
          </div>
          <h1 className="text-[24px] font-bold mt-2">Page not found.</h1>
          <p className="mt-2 text-[16px] text-[color:var(--text-secondary)]">
            The page you're looking for doesn't exist or has been moved.
          </p>
          <div className="mt-6 flex justify-center gap-3">
            <button
              onClick={() => window.history.back()}
              className="nro-btn-secondary"
            >
              ← Back
            </button>
            <Link to="/dashboard" className="nro-btn-primary">
              Go to dashboard
            </Link>
          </div>
          <p className="mt-6 text-[12px] text-[color:var(--text-secondary)]">
            If you believe this is an error, contact support@cyveera.ai.
          </p>
        </div>
      </div>
    </MarketingLayout>
  );
}

function ErrorComponent({ error, reset }: { error: Error; reset: () => void }) {
  console.error(error);
  useEffect(() => {
    captureError(error, { boundary: "tanstack_root_error_component" });
  }, [error]);
  return (
    <div className="flex min-h-screen items-center justify-center bg-[color:var(--canvas)] px-4">
      <div className="max-w-xl text-center">
        <h1 className="text-xl font-bold text-white">This page didn't load</h1>
        <p className="mt-2 text-sm text-[color:var(--text-secondary)]">
          Something went wrong on our end.
        </p>
        <pre className="mt-4 text-left text-xs text-red-400 bg-[color:var(--elevated)] rounded p-3 overflow-x-auto whitespace-pre-wrap break-all">
          {String(error?.message || error)}
          {error?.stack ? "\n\n" + error.stack : ""}
        </pre>
        <div className="mt-6 flex flex-wrap justify-center gap-2">
          <button onClick={reset} className="nro-btn-primary">
            Try again
          </button>
          <a href="/" className="nro-btn-secondary">
            Go home
          </a>
        </div>
      </div>
    </div>
  );
}

export const Route = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  component: RootComponent,
  notFoundComponent: NotFoundComponent,
  errorComponent: ErrorComponent,
});

function RootComponent() {
  const { queryClient } = Route.useRouteContext();
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <Outlet />
      </AuthProvider>
    </QueryClientProvider>
  );
}
