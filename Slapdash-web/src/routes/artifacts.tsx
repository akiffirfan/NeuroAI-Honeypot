import { createFileRoute } from "@tanstack/react-router";
import { AppLayout } from "@/components/layouts/AppLayout";
import { AppPageHeader } from "@/components/ui/AppPageHeader";
import { useQuery } from "@tanstack/react-query";
import { fetchArtifacts, type ArtifactEntry } from "@/lib/api/data";
import { beacon } from "@/lib/api/telemetry";
import { ChevronRight } from "lucide-react";

export const Route = createFileRoute("/artifacts")({
  component: ArtifactsPage,
  head: () => ({ meta: [{ title: "Artifacts — Neuro" }] }),
});

function ArtifactsPage() {
  const { data: artifacts = [], isLoading } = useQuery({
    queryKey: ["artifacts"],
    queryFn: () => fetchArtifacts(),
  });

  const handleDownload = (entry: ArtifactEntry) => {
    beacon("artifact_download", {
      name: entry.name,
      checksum: entry.checksum,
      size: entry.size,
    });
    const url = `/api/v2/artifacts/download?name=${encodeURIComponent(entry.name)}`;
    const a = document.createElement("a");
    a.href = url;
    a.download = entry.name;
    a.click();
  };

  return (
    <AppLayout title="Artifacts">
      <AppPageHeader
        title="Run artifacts."
        description="Checkpoints, configs, eval metrics, and tokenizer files emitted by every training run — content-addressed, hash-verified, and retained per workspace policy."
      />
      <div className="flex items-center gap-1.5 text-[13px] text-[color:var(--text-secondary)] font-mono mb-3">
        <span>artifacts</span>
        <ChevronRight size={12} />
        <span>models</span>
        <ChevronRight size={12} />
        <span className="text-white">vantara-risk-v3</span>
      </div>

      <div className="nro-card p-3 flex gap-2 mb-6">
        <input
          className="nro-input flex-1 font-mono !text-[13px]"
          defaultValue="models/vantara-risk-v3/"
        />
        <button className="nro-btn-secondary">Browse</button>
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
                {[
                  "Name",
                  "Size",
                  "Last Modified",
                  "Checksum (SHA256)",
                  "Action",
                ].map((h) => (
                  <th key={h} className="nro-th">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {artifacts.map((f: ArtifactEntry) => (
                <tr key={f.name} className="nro-row">
                  <td className="nro-td font-mono text-[13px]">{f.name}</td>
                  <td className="nro-td">{f.size}</td>
                  <td className="nro-td text-[color:var(--text-secondary)]">
                    {f.modified}
                  </td>
                  <td className="nro-td font-mono text-[12px] text-[color:var(--text-secondary)]">
                    {f.checksum}
                  </td>
                  <td className="nro-td">
                    <button
                      onClick={() => handleDownload(f)}
                      className="nro-btn-secondary !py-1 !px-3 text-[12px]"
                    >
                      Download
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </AppLayout>
  );
}
