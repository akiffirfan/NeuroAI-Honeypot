import { createFileRoute } from "@tanstack/react-router";
import { LegalLayout } from "@/components/layouts/LegalLayout";

export const Route = createFileRoute("/terms-of-service")({
  component: TermsOfServicePage,
  head: () => ({ meta: [{ title: "Terms of Service — Neuro by Cyveera" }] }),
});

function TermsOfServicePage() {
  return (
    <LegalLayout>
      <h1 className="font-bold" style={{ fontSize: 32 }}>Terms of Service</h1>
      <p className="text-[color:var(--text-secondary)] mt-2">Last updated: January 1, 2026</p>

      <Section title="Acceptance">
        <p>
          By accessing or using the Neuro platform ("Service") operated by
          Cyveera, Inc. ("Cyveera"), you agree to be bound by these Terms of
          Service. If you are entering into this agreement on behalf of a
          company or other legal entity, you represent that you have the
          authority to bind that entity. If you do not agree to these terms,
          you may not access the Service.
        </p>
      </Section>

      <Section title="License Grant">
        <p>
          Subject to your compliance with these terms and timely payment of all
          applicable fees, Cyveera grants you a limited, non-exclusive,
          non-transferable, non-sublicensable license to access and use the
          Service for your internal business purposes during the term of your
          subscription. The Service, including all software, content, and
          intellectual property, remains the exclusive property of Cyveera.
          Customer model artifacts, datasets, and configuration data remain the
          property of the customer.
        </p>
      </Section>

      <Section title="Acceptable Use">
        <p>
          You agree not to misuse the Service. Prohibited activities include
          reverse engineering, attempting to gain unauthorized access to other
          tenants' data, circumventing rate limits, uploading malicious code,
          or using the Service in violation of applicable law. Cyveera may
          suspend or terminate accounts engaged in prohibited activities. All
          platform access is monitored and audited.
        </p>
      </Section>

      <Section title="Limitation of Liability">
        <p>
          To the maximum extent permitted by law, Cyveera shall not be liable
          for any indirect, incidental, special, consequential, or punitive
          damages arising from your use of the Service. Our aggregate liability
          for any claim arising out of these terms is limited to the amount you
          paid Cyveera in the twelve months preceding the claim. The Service is
          provided "as is" without warranties of any kind, except as required
          by applicable law.
        </p>
      </Section>
    </LegalLayout>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mt-8">
      <h2 className="font-bold text-[20px] mb-3">{title}</h2>
      <div className="text-[15px] leading-relaxed text-[color:var(--text-primary)] space-y-3">
        {children}
      </div>
    </section>
  );
}
