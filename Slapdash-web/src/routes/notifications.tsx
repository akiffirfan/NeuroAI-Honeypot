import { createFileRoute } from "@tanstack/react-router";
import { AppLayout } from "@/components/layouts/AppLayout";
import { AppPageHeader } from "@/components/ui/AppPageHeader";
import { AlertCircle, AlertTriangle, Info } from "lucide-react";
import { useNotifications, type NotificationItem } from "@/lib/notifications.store";

export const Route = createFileRoute("/notifications")({
  component: NotificationsPage,
  head: () => ({ meta: [{ title: "Notifications — Neuro" }] }),
});

type Severity = "critical" | "warning" | "info";

function NotificationsPage() {
  const { items, history, markAllRead, dismiss, clearHistory } = useNotifications();
  return (
    <AppLayout title="Notifications">
      <AppPageHeader
        title="Alert center."
        description="Drift alerts, billing thresholds, infrastructure events, and security signals — routed in priority order."
        actions={
          items.length > 0 ? (
            <button onClick={markAllRead} className="nro-btn-secondary text-sm">
              Mark all as read
            </button>
          ) : undefined
        }
      />

      <div className="space-y-3">
        {items.length === 0 ? (
          <div className="nro-card p-8 text-center text-[14px] text-[color:var(--text-secondary)]">
            You're all caught up. No active notifications.
          </div>
        ) : (
          items.map((n) => (
            <NotifRow key={n.id} n={n} onDismiss={() => dismiss(n.id)} />
          ))
        )}
      </div>

      <div className="mt-10">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h2 className="text-[16px] font-semibold text-white">History</h2>
            <p className="text-[13px] text-[color:var(--text-secondary)]">
              Previously dismissed and read notifications.
            </p>
          </div>
          {history.length > 0 && (
            <button onClick={clearHistory} className="nro-btn-secondary text-sm">
              Clear history
            </button>
          )}
        </div>
        <div className="space-y-3">
          {history.length === 0 ? (
            <div className="nro-card p-6 text-center text-[13px] text-[color:var(--text-secondary)]">
              No history yet.
            </div>
          ) : (
            history.map((n) => <NotifRow key={`h-${n.id}`} n={n} muted />)
          )}
        </div>
      </div>
    </AppLayout>
  );
}

function NotifRow({
  n,
  onDismiss,
  muted,
}: {
  n: NotificationItem;
  onDismiss?: () => void;
  muted?: boolean;
}) {
  return (
    <div className={`nro-card p-5 flex gap-4 ${muted ? "opacity-70" : ""}`}>
      <SevIcon sev={n.sev} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <div className="font-bold text-[15px]">{n.title}</div>
          {n.unread && (
            <span className="nro-badge nro-badge--accent !text-[10px]">Unread</span>
          )}
        </div>
        <p className="mt-1 text-[13px] text-[color:var(--text-secondary)]">{n.body}</p>
      </div>
      <div className="flex flex-col items-end gap-2 shrink-0">
        <span className="text-[12px] text-[color:var(--text-secondary)] whitespace-nowrap">
          {n.time}
        </span>
        {onDismiss && (
          <button
            onClick={onDismiss}
            className="nro-btn-secondary !py-1 !px-3 text-[12px]"
          >
            Dismiss
          </button>
        )}
      </div>
    </div>
  );
}

function SevIcon({ sev }: { sev: Severity }) {
  const cfg: Record<Severity, { Icon: any; color: string }> = {
    critical: { Icon: AlertCircle, color: "var(--danger)" },
    warning: { Icon: AlertTriangle, color: "var(--amber)" },
    info: { Icon: Info, color: "var(--text-secondary)" },
  };
  const { Icon, color } = cfg[sev];
  return (
    <div
      className="shrink-0 inline-flex items-center justify-center rounded-md"
      style={{ width: 36, height: 36, background: "var(--elevated)", color }}
    >
      <Icon size={18} />
    </div>
  );
}
