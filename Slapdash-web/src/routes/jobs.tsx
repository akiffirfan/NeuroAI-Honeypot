import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { AppLayout } from "@/components/layouts/AppLayout";
import { AppPageHeader } from "@/components/ui/AppPageHeader";
import { useMutation } from "@tanstack/react-query";
import { submitJob } from "@/lib/api/mutations";
import { useAuth } from "@/lib/auth.context";
import { isApiError } from "@/lib/api/client";
import { useState } from "react";

export const Route = createFileRoute("/jobs")({
  component: JobCreationPage,
  head: () => ({ meta: [{ title: "New Training Job — Neuro" }] }),
});

function JobCreationPage() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [script, setScript] = useState("");
  const [submitError, setSubmitError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: submitJob,
    onSuccess: () => {
      navigate({ to: "/runs" });
    },
    onError: (err) => {
      if (isApiError(err)) {
        setSubmitError(`Error ${err.status}: ${err.detail}`);
      } else {
        setSubmitError("Failed to launch job. Please try again.");
      }
    },
  });

  const onSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setSubmitError(null);
    const form = new FormData(e.currentTarget);
    mutation.mutate({
      job_name: form.get("job_name") as string,
      base_model: form.get("base_model") as string,
      gpu_allocation: form.get("gpu_allocation") as string,
      startup_script: script,
      description: form.get("description") as string,
      _csrf: user?.csrf_token,
    });
  };

  return (
    <AppLayout title="New Training Job">
      <AppPageHeader
        title="Launch a training job."
        description="Pin a base model, allocate GPUs, attach an init script, and queue it on the next available node. Average start time: 38 seconds."
      />
      <div className="mx-auto" style={{ maxWidth: 720 }}>
        <form className="nro-card p-8 space-y-4" onSubmit={onSubmit}>
          <div>
            <label className="nro-label">Job Name</label>
            <input
              name="job_name"
              className="nro-input mt-2"
              placeholder="e.g. vantara-risk-v4-finetune"
              required
            />
          </div>

          <div>
            <label className="nro-label">Base Model</label>
            <select name="base_model" className="nro-input mt-2">
              {[
                "vantara-risk-v3",
                "merisol-nlp-v2",
                "quelaris-embed-001",
                "ardentix-llm-ft",
                "lumira-clf-v4",
              ].map((m) => (
                <option key={m}>{m}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="nro-label">GPU Allocation</label>
            <select name="gpu_allocation" className="nro-input mt-2">
              {[
                "1× A100 (80GB)",
                "2× A100 (160GB)",
                "4× A100 (320GB)",
                "8× A100 (640GB)",
              ].map((g) => (
                <option key={g}>{g}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="nro-label">Startup Script</label>
            <textarea
              className="nro-input mt-2 font-mono !text-[13px]"
              rows={6}
              value={script}
              onChange={(e) => setScript(e.target.value)}
              placeholder={"#!/bin/bash\n# optional init script"}
            />
          </div>

          <div>
            <label className="nro-label">Run Description</label>
            <input
              name="description"
              className="nro-input mt-2"
              placeholder="Optional description for this run"
            />
          </div>

          {submitError && (
            <p className="text-[13px] text-[color:var(--danger)]">{submitError}</p>
          )}

          <button
            disabled={mutation.isPending}
            className="nro-btn-primary w-full mt-2"
          >
            {mutation.isPending ? "Launching…" : "Launch Job"}
          </button>
        </form>
      </div>
    </AppLayout>
  );
}
