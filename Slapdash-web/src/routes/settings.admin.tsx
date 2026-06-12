import { createFileRoute } from "@tanstack/react-router";
import { AppLayout } from "@/components/layouts/AppLayout";
import { AppPageHeader } from "@/components/ui/AppPageHeader";
import data from "@/mocks/data.json";
import { useMutation } from "@tanstack/react-query";
import { adminTenantAction } from "@/lib/api/mutations";
import { useAuth } from "@/lib/auth.context";
import { useState } from "react";

export const Route = createFileRoute("/settings/admin")({
  component: CrossTenantAdminPage,
  head: () => ({ meta: [{ title: "Cross-Tenant Admin — Neuro" }] }),
});

function CrossTenantAdminPage() {
  const { user } = useAuth();
  const [modalData, setModalData] = useState<{
    workspace: string;
    action: string;
    apiResponse?: Record<string, unknown>;
  } | null>(null);

  const actionMutation = useMutation({
    mutationFn: ({ action, body }: { action: string; body: Record<string, unknown> }) =>
      adminTenantAction(action, body),
    onSuccess: (data) => {
      setModalData((prev) =>
        prev ? { ...prev, apiResponse: data as Record<string, unknown> } : null,
      );
    },
  });

  const doAction = (workspace: string, action: string) => {
    setModalData({ workspace, action });
    actionMutation.mutate({
      action,
      body: { workspace, _csrf: user?.csrf_token },
    });
  };

  return (
    <AppLayout title="Cross-Tenant Administration">
      <AppPageHeader
        title="Cross-tenant administration."
        description="Customer workspace operations. Every click is audit-logged to the immutable security journal. Handle with care."
      />
      <div
        className="rounded-md text-white text-[14px] mb-6"
        style={{ background: "#92400e", padding: 16 }}
      >
        <b>Cyveera Internal Use Only</b> — Cross-Tenant Administration Console.
        All actions are logged and audited. Unauthorized access is a violation
        of the Cyveera Terms of Service and may result in account termination
        and legal action.
      </div>

      <div className="nro-card overflow-hidden mt-6">
        <table className="w-full">
          <thead>
            <tr>
              {[
                "Workspace",
                "Admin Email",
                "Plan",
                "Active Users",
                "Storage Used",
                "Created",
                "Actions",
              ].map((h) => (
                <th key={h} className="nro-th">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.tenants.map((t) => (
              <tr key={t.workspace} className="nro-row">
                <td className="nro-td font-bold">{t.workspace}</td>
                <td className="nro-td font-mono text-[13px]">{t.admin}</td>
                <td className="nro-td">{t.plan}</td>
                <td className="nro-td">{t.users}</td>
                <td className="nro-td">{t.storage}</td>
                <td className="nro-td text-[color:var(--text-secondary)]">
                  {t.created}
                </td>
                <td className="nro-td">
                  <div className="flex gap-1.5">
                    <button
                      onClick={() => doAction(t.workspace, "impersonate")}
                      disabled={actionMutation.isPending}
                      className="px-2 py-1 text-[11px] font-medium rounded-md text-white"
                      style={{ background: "var(--amber)" }}
                    >
                      Impersonate User
                    </button>
                    <button
                      onClick={() => doAction(t.workspace, "drop_db")}
                      disabled={actionMutation.isPending}
                      className="px-2 py-1 text-[11px] font-medium rounded-md text-white"
                      style={{ background: "var(--danger)" }}
                    >
                      Drop Tenant DB
                    </button>
                    <button
                      onClick={() => doAction(t.workspace, "export")}
                      disabled={actionMutation.isPending}
                      className="nro-btn-secondary !py-1 !px-2 !text-[11px]"
                    >
                      Export Tenant Data
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {modalData && (
        <ComplianceLockModal
          onClose={() => {
            setModalData(null);
            actionMutation.reset();
          }}
          apiResponse={modalData.apiResponse}
          isLoading={actionMutation.isPending}
        />
      )}
    </AppLayout>
  );
}

function ComplianceLockModal({
  onClose,
  apiResponse,
  isLoading,
}: {
  onClose: () => void;
  apiResponse?: Record<string, unknown>;
  isLoading: boolean;
}) {
  return (
    <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
      <div
        className="nro-card bg-[color:var(--surface)] overflow-hidden"
        style={{ width: 560 }}
      >
        <div
          className="p-4 font-bold text-white"
          style={{ background: "var(--danger)" }}
        >
          Action Blocked — Compliance Hold
        </div>
        <div className="p-8 space-y-4 text-[14px]">
          {isLoading ? (
            <p className="text-[color:var(--text-secondary)]">
              Checking authorization…
            </p>
          ) : (
            <>
              <p>
                This action cannot be completed from the web console because of
                an active SOC 2 compliance review (INC-2026-047). Direct
                database access is required for administrative operations during
                compliance holds.
              </p>
              <pre
                className="font-mono text-[12px] p-3 rounded-md overflow-x-auto"
                style={{ background: "var(--canvas)" }}
              >
                {apiResponse
                  ? JSON.stringify(apiResponse, null, 2)
                  : `InternalError: web_console_proxy: authorization_check FAILED\n  at ConsoleProxy.authorize (console-proxy:1.3.2)\n  at TenantController.adminAction (tenant-ctrl:2.1.0)\n  cause: SOC2_HOLD on node 10.31.4.22 (mgmt-plane)\n  runbook: https://internal.cyveera.ai/runbooks/console-proxy-bypass\n  fallback: direct mgmt-plane access required`}
              </pre>
              <p className="text-[color:var(--text-secondary)]">
                For the duration of the compliance review, use the direct
                management plane interface. Your RSA key on file:{" "}
                <code>~/.ssh/id_rsa</code> (last registered 2026-04-14).
                Authentication via neuro-svc account. Connect:{" "}
                <code>ssh neuro-svc@10.31.4.22</code>
              </p>
              <p className="text-[13px] text-[color:var(--text-secondary)]">
                If you need to add your RSA public key to the management plane:
                go to Settings &rarr; Profile &rarr; SSH Keys.
              </p>
            </>
          )}
          <div className="flex justify-end">
            <button onClick={onClose} className="nro-btn-secondary">
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
