"use client";

import { useAuth } from "@clerk/nextjs";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { AppHeader } from "@/components/AppHeader";
import { ScanComparePanel } from "@/components/ScanComparePanel";
import {
  ApiProject,
  ApiScan,
  DomainVerificationInfo,
  ScanCompareResult,
  compareScans,
  deleteProject,
  getDomainVerification,
  getProject,
  listScans,
  startScan,
  updateProject,
  updateProjectPrChecks,
  verifyDomain,
} from "@/lib/api";

const statusColors: Record<ApiProject["status"], string> = {
  pending: "text-zinc-400",
  processing: "text-amber-400",
  ready: "text-emerald-400",
  failed: "text-red-400",
};

const scanStatusColors: Record<ApiScan["status"], string> = {
  queued: "text-zinc-400",
  running: "text-amber-400",
  completed: "text-emerald-400",
  failed: "text-red-400",
};

export default function ProjectDetailPage() {
  const { getToken } = useAuth();
  const router = useRouter();
  const params = useParams();
  const projectId = params.id as string;

  const [project, setProject] = useState<ApiProject | null>(null);
  const [scans, setScans] = useState<ApiScan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [editing, setEditing] = useState(false);
  const [editName, setEditName] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [saving, setSaving] = useState(false);
  const [baseScanId, setBaseScanId] = useState("");
  const [targetScanId, setTargetScanId] = useState("");
  const [comparison, setComparison] = useState<ScanCompareResult | null>(null);
  const [comparing, setComparing] = useState(false);
  const [domainInfo, setDomainInfo] = useState<DomainVerificationInfo | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [prChecksLoading, setPrChecksLoading] = useState(false);

  const completedScans = scans.filter((s) => s.status === "completed");
  const websiteNeedsVerification =
    project?.source_type === "website" && !project.domain_verified;

  useEffect(() => {
    async function load() {
      try {
        const token = await getToken();
        if (!token) return;
        const [projectData, scanData] = await Promise.all([
          getProject(token, projectId),
          listScans(token, projectId),
        ]);
        setProject(projectData);
        setScans(scanData.scans);
        setEditName(projectData.name);
        setEditDescription(projectData.description ?? "");

        if (projectData.source_type === "website") {
          try {
            const info = await getDomainVerification(token, projectId);
            setDomainInfo(info);
          } catch {
            setDomainInfo(null);
          }
        }

        const completed = scanData.scans.filter((s) => s.status === "completed");
        if (completed.length >= 2) {
          setBaseScanId(completed[1].id);
          setTargetScanId(completed[0].id);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load project");
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [getToken, projectId]);

  useEffect(() => {
    async function runCompare() {
      if (!baseScanId || !targetScanId || baseScanId === targetScanId) {
        setComparison(null);
        return;
      }
      setComparing(true);
      try {
        const token = await getToken();
        if (!token) return;
        const result = await compareScans(token, projectId, baseScanId, targetScanId);
        setComparison(result);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to compare scans");
      } finally {
        setComparing(false);
      }
    }
    runCompare();
  }, [baseScanId, targetScanId, getToken, projectId]);

  async function handleStartAudit() {
    setScanning(true);
    setError(null);
    try {
      const token = await getToken();
      if (!token) return;
      const scan = await startScan(token, projectId);
      router.push(`/projects/${projectId}/scans/${scan.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start audit");
      setScanning(false);
    }
  }

  async function handleSaveSettings() {
    setSaving(true);
    setError(null);
    try {
      const token = await getToken();
      if (!token) return;
      const updated = await updateProject(token, projectId, {
        name: editName.trim(),
        description: editDescription.trim() || undefined,
      });
      setProject(updated);
      setEditing(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update project");
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete() {
    if (!confirm("Delete this project and all uploaded files?")) return;
    setDeleting(true);
    try {
      const token = await getToken();
      if (!token) return;
      await deleteProject(token, projectId);
      router.push("/projects");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete project");
      setDeleting(false);
    }
  }

  const latestScore = completedScans[0]?.health_score;

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50">
      <AppHeader badge="Phase 8 — History" />

      <main className="mx-auto max-w-4xl px-6 py-12">
        <Link href="/projects" className="text-sm text-zinc-500 hover:text-zinc-300">
          ← Back to Projects
        </Link>

        {loading && <p className="mt-8 text-zinc-400">Loading project...</p>}
        {error && (
          <p className="mt-8 rounded-lg border border-red-900 bg-red-950/50 p-4 text-sm text-red-300">
            {error}
          </p>
        )}

        {project && (
          <div className="mt-6">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <h1 className="text-3xl font-bold tracking-tight">{project.name}</h1>
                {project.description && (
                  <p className="mt-2 text-zinc-400">{project.description}</p>
                )}
              </div>
              <div className="flex flex-col items-end gap-2">
                <span
                  className={`rounded-full border border-zinc-700 px-3 py-1 text-sm capitalize ${statusColors[project.status]}`}
                >
                  {project.status}
                </span>
                {latestScore != null && (
                  <span className="text-sm text-zinc-400">
                    Latest score: <strong className="text-emerald-400">{latestScore}</strong>
                  </span>
                )}
              </div>
            </div>

            <div className="mt-8 space-y-4 rounded-xl border border-zinc-800 bg-zinc-900/50 p-6">
              <DetailRow
                label="Source"
                value={
                  project.source_type === "github"
                    ? "GitHub"
                    : project.source_type === "website"
                      ? "Live Website"
                      : "ZIP Upload"
                }
              />
              {project.repo_url && (
                <DetailRow
                  label={project.source_type === "website" ? "Website URL" : "Repository"}
                  value={project.repo_url}
                  mono
                />
              )}
              {project.repo_branch && <DetailRow label="Branch" value={project.repo_branch} />}
              {project.source_type !== "website" && (
                <DetailRow label="Files" value={String(project.file_count)} />
              )}
              <DetailRow label="Created" value={new Date(project.created_at).toLocaleString()} />
              {project.status_message && (
                <DetailRow label="Status Message" value={project.status_message} />
              )}
            </div>

            {project.source_type === "website" && domainInfo && (
              <section className="mt-8 rounded-xl border border-amber-500/20 bg-amber-950/10 p-6">
                <h2 className="text-sm font-medium uppercase tracking-widest text-amber-300">
                  Domain Ownership Verification
                </h2>
                {domainInfo.verified ? (
                  <p className="mt-3 text-sm text-emerald-300">
                    Domain verified — you can run website security scans.
                  </p>
                ) : (
                  <>
                    <p className="mt-3 text-sm text-zinc-300">
                      Verify you own <strong>{domainInfo.domain}</strong> before scanning.
                      Choose one method:
                    </p>
                    <div className="mt-4 space-y-3 text-sm">
                      <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-4">
                        <p className="text-zinc-400">DNS TXT record</p>
                        <p className="mt-1 font-mono text-xs text-zinc-200">
                          {domainInfo.dns_record_name} → {domainInfo.dns_record_value}
                        </p>
                      </div>
                      <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-4">
                        <p className="text-zinc-400">HTML meta tag (homepage)</p>
                        <code className="mt-1 block break-all text-xs text-zinc-200">
                          {domainInfo.meta_tag}
                        </code>
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={async () => {
                        setVerifying(true);
                        setError(null);
                        try {
                          const token = await getToken();
                          if (!token) return;
                          const info = await verifyDomain(token, projectId);
                          setDomainInfo(info);
                          const updated = await getProject(token, projectId);
                          setProject(updated);
                        } catch (err) {
                          setError(err instanceof Error ? err.message : "Verification failed");
                        } finally {
                          setVerifying(false);
                        }
                      }}
                      disabled={verifying}
                      className="mt-4 rounded-lg bg-amber-500 px-5 py-2 text-sm font-semibold text-zinc-950 disabled:opacity-50"
                    >
                      {verifying ? "Checking..." : "Verify Domain"}
                    </button>
                  </>
                )}
              </section>
            )}

            {project.source_type === "github" && (
              <section className="mt-8 rounded-xl border border-zinc-800 bg-zinc-900/50 p-6">
                <h2 className="text-sm font-medium uppercase tracking-widest text-zinc-500">
                  GitHub PR Checks
                </h2>
                <p className="mt-2 text-sm text-zinc-400">
                  Enable to scan pull requests and post findings as PR comments. Requires GitHub
                  PAT in Enterprise settings and webhook at{" "}
                  <code className="text-emerald-400">POST /api/integrations/github/webhook</code>.
                </p>
                <label className="mt-4 flex items-center gap-3">
                  <input
                    type="checkbox"
                    checked={project.pr_checks_enabled ?? false}
                    onChange={async (e) => {
                      setPrChecksLoading(true);
                      try {
                        const token = await getToken();
                        if (!token) return;
                        const updated = await updateProjectPrChecks(
                          token,
                          projectId,
                          e.target.checked,
                        );
                        setProject(updated);
                      } catch (err) {
                        setError(err instanceof Error ? err.message : "Failed to update PR checks");
                      } finally {
                        setPrChecksLoading(false);
                      }
                    }}
                    disabled={prChecksLoading}
                    className="h-4 w-4 rounded border-zinc-600"
                  />
                  <span className="text-sm text-zinc-300">Enable PR security checks</span>
                </label>
              </section>
            )}

            <div className="mt-8 flex flex-wrap gap-3">
              <button
                type="button"
                onClick={handleStartAudit}
                disabled={project.status !== "ready" || scanning || websiteNeedsVerification}
                className="rounded-lg bg-emerald-500 px-6 py-2.5 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {scanning ? "Starting Audit..." : "Re-scan Project"}
              </button>
              {websiteNeedsVerification && (
                <p className="self-center text-sm text-amber-300">
                  Verify domain ownership before scanning.
                </p>
              )}
              <button
                type="button"
                onClick={() => setEditing((v) => !v)}
                className="rounded-lg border border-zinc-700 px-6 py-2.5 text-sm text-zinc-300 transition hover:border-zinc-500"
              >
                {editing ? "Cancel Edit" : "Edit Settings"}
              </button>
              <button
                type="button"
                onClick={handleDelete}
                disabled={deleting}
                className="rounded-lg border border-red-900 px-6 py-2.5 text-sm text-red-400 transition hover:bg-red-950/30 disabled:opacity-50"
              >
                {deleting ? "Deleting..." : "Delete Project"}
              </button>
            </div>

            {editing && (
              <section className="mt-6 rounded-xl border border-zinc-800 bg-zinc-900/50 p-6">
                <h2 className="text-sm font-medium uppercase tracking-widest text-zinc-500">
                  Project Settings
                </h2>
                <div className="mt-4 space-y-4">
                  <label className="block">
                    <span className="text-sm text-zinc-400">Name</span>
                    <input
                      value={editName}
                      onChange={(e) => setEditName(e.target.value)}
                      className="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100"
                    />
                  </label>
                  <label className="block">
                    <span className="text-sm text-zinc-400">Description</span>
                    <textarea
                      value={editDescription}
                      onChange={(e) => setEditDescription(e.target.value)}
                      rows={3}
                      className="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100"
                    />
                  </label>
                  <button
                    type="button"
                    onClick={handleSaveSettings}
                    disabled={saving || !editName.trim()}
                    className="rounded-lg bg-emerald-500 px-5 py-2 text-sm font-semibold text-zinc-950 disabled:opacity-50"
                  >
                    {saving ? "Saving..." : "Save Changes"}
                  </button>
                </div>
              </section>
            )}

            {scans.length > 0 && (
              <section className="mt-10">
                <h2 className="text-sm font-medium uppercase tracking-widest text-zinc-500">
                  Scan History
                </h2>
                <div className="mt-4 space-y-3">
                  {scans.map((scan, index) => (
                    <Link
                      key={scan.id}
                      href={`/projects/${projectId}/scans/${scan.id}`}
                      className="flex items-center justify-between rounded-lg border border-zinc-800 bg-zinc-900/40 px-4 py-3 transition hover:border-emerald-500/50"
                    >
                      <div>
                        <p className="text-sm text-zinc-200">
                          {new Date(scan.created_at).toLocaleString()}
                          {index === 0 && scan.status === "completed" && (
                            <span className="ml-2 text-xs text-emerald-400">Latest</span>
                          )}
                        </p>
                        <p className="text-xs text-zinc-500">
                          {scan.total_issues} issues · {scan.critical_count} critical
                        </p>
                      </div>
                      <div className="flex items-center gap-4">
                        {scan.health_score != null && (
                          <div className="text-right">
                            <p className="text-lg font-bold text-zinc-50">{scan.health_score}</p>
                            {scan.grade && (
                              <p className="text-xs text-zinc-500">Grade {scan.grade}</p>
                            )}
                          </div>
                        )}
                        <span className={`text-sm capitalize ${scanStatusColors[scan.status]}`}>
                          {scan.status}
                        </span>
                      </div>
                    </Link>
                  ))}
                </div>
              </section>
            )}

            {completedScans.length >= 2 && (
              <section className="mt-10">
                <h2 className="mb-4 text-sm font-medium uppercase tracking-widest text-zinc-500">
                  Compare Scans
                </h2>
                <div className="mb-4 grid gap-4 sm:grid-cols-2">
                  <label className="block text-sm">
                    <span className="text-zinc-500">Before (baseline)</span>
                    <select
                      value={baseScanId}
                      onChange={(e) => setBaseScanId(e.target.value)}
                      className="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-zinc-100"
                    >
                      {completedScans.map((scan) => (
                        <option key={scan.id} value={scan.id}>
                          {new Date(scan.created_at).toLocaleString()} — score{" "}
                          {scan.health_score ?? "—"}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="block text-sm">
                    <span className="text-zinc-500">After (latest fixes)</span>
                    <select
                      value={targetScanId}
                      onChange={(e) => setTargetScanId(e.target.value)}
                      className="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-zinc-100"
                    >
                      {completedScans.map((scan) => (
                        <option key={scan.id} value={scan.id}>
                          {new Date(scan.created_at).toLocaleString()} — score{" "}
                          {scan.health_score ?? "—"}
                        </option>
                      ))}
                    </select>
                  </label>
                </div>
                <ScanComparePanel comparison={comparison} loading={comparing} />
              </section>
            )}
          </div>
        )}
      </main>
    </div>
  );
}

function DetailRow({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex justify-between gap-4 border-b border-zinc-800 pb-3 last:border-0 last:pb-0">
      <span className="text-sm text-zinc-500">{label}</span>
      <span className={`text-right text-sm text-zinc-200 ${mono ? "font-mono text-xs" : ""}`}>
        {value}
      </span>
    </div>
  );
}
