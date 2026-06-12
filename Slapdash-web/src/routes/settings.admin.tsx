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
  // confirmData: pending confirmation (backend NOT fired yet)
  const [confirmData, setConfirmData] = useState<{ workspace: string; action: string } | null>(null);
  // modalData: after confirmed — shows compliance/result modal
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

  // Only called after attacker clicks the red Confirm button
  const doAction = (workspace: string, action: string) => {
    setConfirmData(null);
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
                      onClick={() => setConfirmData({ workspace: t.workspace, action: "impersonate" })}
                      className="px-2 py-1 text-[11px] font-medium rounded-md text-white"
                      style={{ background: "var(--amber)" }}
                    >
                      Impersonate User
                    </button>
                    <button
                      onClick={() => setConfirmData({ workspace: t.workspace, action: "drop_db" })}
                      className="px-2 py-1 text-[11px] font-medium rounded-md text-white"
                      style={{ background: "var(--danger)" }}
                    >
                      Drop Tenant DB
                    </button>
                    <button
                      onClick={() => setConfirmData({ workspace: t.workspace, action: "export" })}
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

      {confirmData && (
        <ConfirmActionModal
          workspace={confirmData.workspace}
          action={confirmData.action}
          onCancel={() => setConfirmData(null)}
          onConfirm={() => doAction(confirmData.workspace, confirmData.action)}
        />
      )}

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

const ACTION_LABELS: Record<string, string> = {
  impersonate: "Impersonate User",
  drop_db: "Drop Tenant DB",
  export: "Export Tenant Data",
};

const ACTION_WARNINGS: Record<string, string> = {
  impersonate: "You will be issued a temporary session token scoped to this workspace. All actions taken will be logged under your support account.",
  drop_db: "This will permanently delete all training runs, models, and dataset references for this workspace. This action cannot be undone.",
  export: "A full data export will be queued. The archive will include model weights, training logs, and pipeline configs for this workspace.",
};

function ConfirmActionModal({
  workspace,
  action,
  onCancel,
  onConfirm,
}: {
  workspace: string;
  action: string;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const isDangerous = action === "drop_db";
  const borderColor = isDangerous ? "rgba(239,68,68,0.5)" : "rgba(245,158,11,0.5)";
  const iconColor = isDangerous ? "#ef4444" : "#f59e0b";
  const confirmBg = isDangerous ? "#ef4444" : "#f59e0b";

  return (
    <div
      className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4"
      onClick={onCancel}
    >
      <div
        className="nro-card bg-[color:var(--surface)]"
        style={{ width: 480, padding: 32, border: `1px solid ${borderColor}` }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-3 mb-5">
          <div
            className="w-10 h-10 rounded-full flex items-center justify-center flex-shrink-0"
            style={{ background: isDangerous ? "rgba(239,68,68,0.15)" : "rgba(245,158,11,0.15)" }}
          >
            <svg width="20" height="20" fill="none" viewBox="0 0 24 24">
              <path
                d="M12 9v4m0 4h.01M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"
                stroke={iconColor}
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </div>
          <div>
            <h3 className="font-bold text-[18px]">{ACTION_LABELS[action] ?? action}</h3>
            <p className="text-[12px] text-[color:var(--text-secondary)] mt-0.5 font-mono">
              {workspace}
            </p>
          </div>
        </div>

        <div
          className="rounded-md p-4 mb-6 text-[13px] leading-relaxed"
          style={{
            background: isDangerous ? "rgba(239,68,68,0.07)" : "rgba(245,158,11,0.07)",
            border: `1px solid ${borderColor}`,
            color: "var(--text-primary)",
          }}
        >
          <strong style={{ color: iconColor }}>Warning:</strong>{" "}
          {ACTION_WARNINGS[action] ?? "This action will be logged."}
        </div>

        <div className="flex justify-end gap-2">
          <button type="button" onClick={onCancel} className="nro-btn-secondary">
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className="nro-btn-primary"
            style={{ background: confirmBg, borderColor: confirmBg }}
          >
            Confirm — {ACTION_LABELS[action] ?? action}
          </button>
        </div>
      </div>
    </div>
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
