import { createFileRoute } from "@tanstack/react-router";
import { AppLayout } from "@/components/layouts/AppLayout";
import { AppPageHeader } from "@/components/ui/AppPageHeader";
import { useQuery, useMutation } from "@tanstack/react-query";
import { fetchDatasets, type Dataset } from "@/lib/api/data";
import { importDataset } from "@/lib/api/mutations";
import { isApiError } from "@/lib/api/client";
import { Plus, Search } from "lucide-react";
import { useState } from "react";

export const Route = createFileRoute("/datasets")({
  component: DatasetsPage,
  head: () => ({ meta: [{ title: "Datasets — Neuro" }] }),
});

const TAG_CLASS: Record<string, string> = {
  CONFIDENTIAL: "nro-badge--danger",
  PHI: "nro-badge--danger",
  RESTRICTED: "nro-badge--amber",
  INTERNAL: "nro-badge--amber",
  PUBLIC: "nro-badge--accent",
  RESEARCH: "nro-badge--slate",
};

function DatasetsPage() {
  const { data: datasets = [], isLoading } = useQuery({
    queryKey: ["datasets"],
    queryFn: fetchDatasets,
  });
  const [open, setOpen] = useState(false);
  const [banner, setBanner] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const q = query.trim().toLowerCase();

  const filtered = datasets.filter(
    (d: Dataset) =>
      !q ||
      d.name.toLowerCase().includes(q) ||
      d.source.toLowerCase().includes(q) ||
      d.format.toLowerCase().includes(q) ||
      d.tags.some((t) => t.toLowerCase().includes(q)),
  );

  return (
    <AppLayout title="Datasets">
      <AppPageHeader
        title="Datasets."
        description="Training corpora, eval splits, and red-team probes — versioned, tagged, and locked to least-privilege access by default."
        actions={
          <button
            onClick={() => setOpen(true)}
            className="nro-btn-primary text-sm flex items-center gap-1.5"
          >
            <Plus size={14} /> Import from URL
          </button>
        }
      />
      {banner && (
        <div
          className="mb-4 p-3 rounded-md text-[13px] font-mono"
          style={{
            background: "color-mix(in oklab, var(--accent) 14%, transparent)",
            border: "1px solid var(--accent)",
            color: "var(--accent)",
          }}
        >
          {banner}
        </div>
      )}

      <div className="mb-4 relative max-w-md">
        <Search
          size={14}
          className="absolute left-3 top-1/2 -translate-y-1/2 text-[color:var(--text-secondary)]"
        />
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search by name, source, format, or tag…"
          className="w-full pl-9 pr-3 py-2 rounded-md bg-[color:var(--elevated)] border border-[color:var(--border)] text-[13px] text-white placeholder:text-[color:var(--text-secondary)] focus:outline-none focus:border-[color:var(--accent)]"
        />
      </div>

      {isLoading ? (
        <div className="nro-card p-8 text-center text-[14px] text-[color:var(--text-secondary)]">
          Loading…
        </div>
      ) : (
        <div className="nro-card overflow-hidden">
          <table className="w-full">
            <thead>
              <tr>
                {["Name", "Source", "Format", "Rows", "Size", "Uploaded", "Tags"].map(
                  (h) => (
                    <th key={h} className="nro-th">
                      {h}
                    </th>
                  ),
                )}
              </tr>
            </thead>
            <tbody>
              {filtered.map((d: Dataset) => (
                <tr key={d.name} className="nro-row">
                  <td className="nro-td font-mono text-[13px]">{d.name}</td>
                  <td className="nro-td text-[color:var(--text-secondary)]">
                    {d.source}
                  </td>
                  <td className="nro-td">{d.format}</td>
                  <td className="nro-td font-mono text-[13px]">{d.row_count}</td>
                  <td className="nro-td">{d.size_display}</td>
                  <td className="nro-td text-[color:var(--text-secondary)]">
                    {d.uploaded_at}
                  </td>
                  <td className="nro-td">
                    <div className="flex flex-wrap gap-1">
                      {d.tags.map((t) => (
                        <span
                          key={t}
                          className={`nro-badge ${TAG_CLASS[t] ?? "nro-badge--slate"}`}
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {open && (
        <RemoteImportModal
          onClose={() => setOpen(false)}
          onSuccess={(jobId) => {
            setOpen(false);
            setBanner(
              `{"status": "ingestion_queued", "job_id": "${jobId}"}`,
            );
          }}
        />
      )}
    </AppLayout>
  );
}

function RemoteImportModal({
  onClose,
  onSuccess,
}: {
  onClose: () => void;
  onSuccess: (jobId: string) => void;
}) {
  const [importError, setImportError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: importDataset,
    onSuccess: (data) => {
      onSuccess(data.job_id);
    },
    onError: (err) => {
      if (isApiError(err)) {
        setImportError(`Error ${err.status}: ${err.detail}`);
      } else {
        setImportError("Import failed. Please try again.");
      }
    },
  });

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setImportError(null);
    const form = new FormData(e.currentTarget);
    mutation.mutate({
      dataset_name: form.get("dataset_name") as string,
      url: form.get("source_url") as string,
      format: form.get("format") as string,
    });
  };

  return (
    <div
      className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4"
      onClick={onClose}
    >
      <div
        className="nro-card bg-[color:var(--elevated)]"
        style={{ width: 480, padding: 32 }}
        onClick={(e) => e.stopPropagation()}
      >
        <h3 className="font-bold text-[20px]">Import Dataset from URL</h3>
        <p className="mt-2 text-[14px] text-[color:var(--text-secondary)]">
          Paste a publicly accessible URL and Neuro will fetch and ingest the
          dataset on your behalf. Supports CSV, JSONL, Parquet, and HuggingFace
          dataset paths.
        </p>

        <form onSubmit={handleSubmit} className="mt-6 space-y-4">
          <div>
            <label className="nro-label">Dataset name</label>
            <input
              name="dataset_name"
              className="nro-input mt-2"
              placeholder="e.g. customer-feedback-q2-2026"
              required
            />
          </div>
          <div>
            <label className="nro-label">Source URL</label>
            <input
              name="source_url"
              className="nro-input mt-2"
              placeholder="https://datasets.example.com/data.parquet or hf://datasets/owner/name"
              required
            />
          </div>
          <div>
            <label className="nro-label">Format</label>
            <select name="format" className="nro-input mt-2">
              <option value="auto">Auto-detect</option>
              <option value="csv">CSV</option>
              <option value="jsonl">JSONL</option>
              <option value="parquet">Parquet</option>
              <option value="huggingface">HuggingFace Hub</option>
            </select>
          </div>
          {importError && (
            <p className="text-[13px] text-[color:var(--danger)]">{importError}</p>
          )}
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" onClick={onClose} className="nro-btn-secondary">
              Cancel
            </button>
            <button disabled={mutation.isPending} className="nro-btn-primary">
              {mutation.isPending ? "Importing…" : "Import"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
