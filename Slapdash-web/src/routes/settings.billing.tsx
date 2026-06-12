import { createFileRoute } from "@tanstack/react-router";
import { AppLayout } from "@/components/layouts/AppLayout";
import { AppPageHeader } from "@/components/ui/AppPageHeader";
import { beacon } from "@/lib/api/telemetry";
import data from "@/mocks/data.json";

export const Route = createFileRoute("/settings/billing")({
  component: BillingPage,
  head: () => ({ meta: [{ title: "Billing — Neuro" }] }),
});

function BillingPage() {
  return (
    <AppLayout title="Billing">
      <AppPageHeader
        title="Billing."
        description="Plan, renewal, payment method, and your last 12 months of invoices — all in one place."
      />
      <div className="nro-card p-8" style={{ borderLeft: "4px solid var(--accent)" }}>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          <div>
            <span className="nro-badge nro-badge--accent">Pro</span>
            <div className="font-bold mt-3" style={{ fontSize: 36 }}>$899/mo</div>
            <div className="text-[14px] text-[color:var(--text-secondary)] mt-1">
              3 seats · Billed annually.
            </div>
          </div>
          <div>
            <div className="nro-label">Renewal</div>
            <div className="text-white text-[16px] mt-2">2027-01-01</div>
            <div className="text-[13px] text-[color:var(--text-secondary)] mt-1">
              Annual contract · Auto-renews unless cancelled 30 days prior.
            </div>
          </div>
          <div>
            <div className="nro-label">Payment method</div>
            <div className="text-white text-[14px] mt-2 font-mono">VISA •••• •••• •••• 4242</div>
            <div className="text-[13px] text-[color:var(--text-secondary)] mt-1">
              Expires 08/2028.
            </div>
            <a href="#" className="text-[13px] text-[color:var(--accent)] mt-1 inline-block">
              Update payment method
            </a>
          </div>
        </div>
        <button className="nro-btn-secondary w-full mt-6">
          View contract details or add seats →
        </button>
      </div>

      <h2 className="font-bold text-[18px] mt-10 mb-4">Invoice History</h2>
      <div className="nro-card overflow-hidden">
        <table className="w-full">
          <thead>
            <tr>
              {["Invoice", "Period", "Amount", "Status", "Action"].map((h) => (
                <th key={h} className="nro-th">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.invoices.map((inv) => (
              <tr key={inv.id} className="nro-row">
                <td className="nro-td font-mono text-[13px]">{inv.id}</td>
                <td className="nro-td text-[color:var(--text-secondary)]">{inv.period}</td>
                <td className="nro-td">{inv.amount}</td>
                <td className="nro-td">
                  <span className="nro-badge nro-badge--accent">{inv.status}</span>
                </td>
                <td className="nro-td">
                  <button
                    onClick={() => {
                      beacon("billing_invoice_download", { invoice_id: inv.id });
                      const a = document.createElement("a");
                      a.href = `/api/v2/settings/billing/invoice/${encodeURIComponent(inv.id)}`;
                      a.download = `invoice-${inv.id}.pdf`;
                      a.click();
                    }}
                    className="nro-btn-secondary !py-1 !px-3 text-[12px]"
                  >
                    Download PDF
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </AppLayout>
  );
}
