import { createFileRoute } from "@tanstack/react-router";
import { LegalLayout } from "@/components/layouts/LegalLayout";

export const Route = createFileRoute("/privacy-policy")({
  component: PrivacyPolicyPage,
  head: () => ({ meta: [{ title: "Privacy Policy — Neuro by Cyveera" }] }),
});

function PrivacyPolicyPage() {
  return (
    <LegalLayout>
      <h1 className="font-bold" style={{ fontSize: 32 }}>Privacy Policy</h1>
      <p className="text-[color:var(--text-secondary)] mt-2">Effective date: January 1, 2026</p>

      <Section title="Data Controller">
        <p>
          Cyveera, Inc. ("Cyveera", "we", "us") acts as the data controller for
          information collected through the Neuro platform at
          neuro.cyveera.com. Our registered office is in Boston, Massachusetts,
          United States. For any questions regarding this policy or your
          personal data, contact <code>privacy@cyveera.ai</code>.
        </p>
      </Section>

      <Section title="Data We Collect">
        <p>
          We collect the minimum data required to operate the Neuro platform:
          your work email, display name, workspace name, and authentication
          credentials. When you use the platform, we collect usage metadata
          (training run identifiers, dataset names, API call counts), session
          telemetry (IP address, browser user-agent, approximate location), and
          billing information (where applicable). Customer model artifacts and
          datasets uploaded to Neuro remain the property of the customer and
          are processed solely to deliver the contracted service.
        </p>
      </Section>

      <Section title="How We Use Your Data">
        <p>
          We use collected data to authenticate users, deliver requested
          features (drift detection, alert routing, billing), protect the
          platform from abuse, and comply with legal obligations. We do not
          sell personal data and do not use customer model artifacts to train
          third-party models. Aggregated, anonymized telemetry may be used to
          improve platform reliability and performance.
        </p>
      </Section>

      <Section title="Your Rights">
        <p>
          Under GDPR and similar regulations, you have the right to access,
          rectify, port, and erase your personal data. You may also restrict or
          object to certain processing activities. To exercise any of these
          rights, email <code>privacy@cyveera.ai</code> from the email address
          associated with your Neuro account. We respond to all verifiable
          requests within thirty days. Cyveera is SOC 2 Type II certified and
          maintains a Data Processing Agreement available on request.
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
