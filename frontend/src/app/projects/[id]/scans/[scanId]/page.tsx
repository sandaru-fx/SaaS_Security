"use client";

import { useAuth } from "@clerk/nextjs";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import { AIAuditSummary } from "@/components/AIAuditSummary";
import { AppHeader } from "@/components/AppHeader";
import { AuditChatPanel } from "@/components/AuditChatPanel";
import { ComplianceBreakdown } from "@/components/ComplianceBreakdown";
import { CategoryBreakdown } from "@/components/CategoryBreakdown";
import { HealthScoreRing } from "@/components/HealthScoreRing";
import { IssueCard } from "@/components/IssueCard";
import { IssueDetailModal } from "@/components/IssueDetailModal";
import { TopFixNowPanel } from "@/components/TopFixNowPanel";
import {
  ApiIssue,
  ApiScan,
  AuditReport,
  SubscriptionInfo,
  dismissIssue,
  downloadAuditPdf,
  downloadSbom,
  getAuditReport,
  getScan,
  getSubscription,
  listScanIssues,
} from "@/lib/api";

const severityFilters = ["all", "critical", "high", "medium", "low"] as const;
const categoryFilters = [
  "all",
  "security",
  "secrets",
  "dependencies",
  "architecture",
  "performance",
  "quality",
  "devops",
] as const;

export default function ScanResultsPage() {
  const { getToken } = useAuth();
  const params = useParams();
  const projectId = params.id as string;
  const scanId = params.scanId as string;

  const [scan, setScan] = useState<ApiScan | null>(null);
  const [report, setReport] = useState<AuditReport | null>(null);
  const [issues, setIssues] = useState<ApiIssue[]>([]);
  const [severityFilter, setSeverityFilter] =
    useState<(typeof severityFilters)[number]>("all");
  const [categoryFilter, setCategoryFilter] =
    useState<(typeof categoryFilters)[number]>("all");
  const [selectedIssue, setSelectedIssue] = useState<ApiIssue | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [subscription, setSubscription] = useState<SubscriptionInfo | null>(null);
  const [pdfLoading, setPdfLoading] = useState(false);
  const [sbomLoading, setSbomLoading] = useState(false);

  const loadData = useCallback(async () => {
    try {
      const token = await getToken();
      if (!token) return;

      const [scanData, issueData, subData] = await Promise.all([
        getScan(token, scanId),
        listScanIssues(token, scanId, {
          severity: severityFilter === "all" ? undefined : severityFilter,
          category: categoryFilter === "all" ? undefined : categoryFilter,
        }),
        getSubscription(token),
      ]);

      setScan(scanData);
      setIssues(issueData.issues);
      setSubscription(subData);
      setError(null);

      if (scanData.status === "completed") {
        const reportData = await getAuditReport(token, scanId);
        setReport(reportData);
      }

      if (scanData.status === "queued" || scanData.status === "running") {
        return false;
      }
      return true;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load scan");
      return true;
    } finally {
      setLoading(false);
    }
  }, [getToken, scanId, severityFilter, categoryFilter]);

  useEffect(() => {
    let active = true;
    let interval: ReturnType<typeof setInterval> | null = null;

    async function poll() {
      const done = await loadData();
      if (!active) return;
      if (!done && !interval) {
        interval = setInterval(async () => {
          const finished = await loadData();
          if (finished && interval) {
            clearInterval(interval);
            interval = null;
          }
        }, 3000);
      }
    }

    poll();

    return () => {
      active = false;
      if (interval) clearInterval(interval);
    };
  }, [loadData]);

  async function handleDownloadPdf() {
    setPdfLoading(true);
    setError(null);
    try {
      const token = await getToken();
      if (!token) return;
      const blob = await downloadAuditPdf(token, scanId);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `audit-report-${scanId}.pdf`;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "PDF download failed");
    } finally {
      setPdfLoading(false);
    }
  }

  async function handleDownloadSbom() {
    setSbomLoading(true);
    setError(null);
    try {
      const token = await getToken();
      if (!token) return;
      const blob = await downloadSbom(token, scanId);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `sbom-${scanId}.json`;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "SBOM download failed");
    } finally {
      setSbomLoading(false);
    }
  }

  async function handleDismissIssue(issue: ApiIssue) {
    const reason = window.prompt("Reason for dismissing (optional):") ?? undefined;
    try {
      const token = await getToken();
      if (!token) return;
      await dismissIssue(token, issue.id, reason || undefined);
      setIssues((prev) =>
        prev.map((i) =>
          i.id === issue.id ? { ...i, dismissed: true, dismissed_reason: reason || null } : i,
        ),
      );
      setSelectedIssue(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to dismiss issue");
    }
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50">
      <AppHeader badge="Phase 6 — Advanced" />

      <main className="mx-auto max-w-5xl px-6 py-12">
        <Link
          href={`/projects/${projectId}`}
          className="text-sm text-zinc-500 hover:text-zinc-300"
        >
          ← Back to Project
        </Link>

        {loading && !scan && <p className="mt-8 text-zinc-400">Loading audit report...</p>}
        {error && (
          <p className="mt-8 rounded-lg border border-red-900 bg-red-950/50 p-4 text-sm text-red-300">
            {error}
          </p>
        )}

        {scan && (
          <>
            <div className="mt-6 flex flex-wrap items-start justify-between gap-4">
              <div>
                <p className="text-xs font-medium uppercase tracking-widest text-emerald-400">
                  Professional Audit Report
                </p>
                <h1 className="mt-2 text-3xl font-bold tracking-tight">Audit Results</h1>
                <p className="mt-2 capitalize text-zinc-400">Status: {scan.status}</p>
              </div>
              <div className="flex flex-col items-end gap-2">
                {(scan.status === "queued" || scan.status === "running") && (
                  <div className="flex items-center gap-2 text-amber-400">
                    <span className="h-2 w-2 animate-pulse rounded-full bg-amber-400" />
                    <span className="text-sm">Scanning in progress...</span>
                  </div>
                )}
                {scan.status === "completed" && subscription?.features.pdf_export && (
                  <button
                    type="button"
                    onClick={handleDownloadPdf}
                    disabled={pdfLoading}
                    className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-4 py-2 text-sm font-medium text-emerald-300 hover:bg-emerald-500/20 disabled:opacity-50"
                  >
                    {pdfLoading ? "Generating PDF..." : "Download PDF Report"}
                  </button>
                )}
                {scan.status === "completed" && subscription?.features.sbom_export && (
                  <button
                    type="button"
                    onClick={handleDownloadSbom}
                    disabled={sbomLoading}
                    className="rounded-lg border border-sky-500/40 bg-sky-500/10 px-4 py-2 text-sm font-medium text-sky-300 hover:bg-sky-500/20 disabled:opacity-50"
                  >
                    {sbomLoading ? "Generating SBOM..." : "Download SBOM (CycloneDX)"}
                  </button>
                )}
                {scan.status === "completed" && subscription && !subscription.features.pdf_export && (
                  <Link
                    href="/billing"
                    className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-2 text-sm text-amber-300 hover:bg-amber-500/20"
                  >
                    Upgrade for PDF Export →
                  </Link>
                )}
              </div>
            </div>

            {report && scan.status === "completed" && (
              <section className="mt-8 rounded-2xl border border-zinc-800 bg-zinc-900/50 p-8">
                <div className="flex flex-col items-center gap-8 lg:flex-row lg:items-start">
                  <HealthScoreRing score={report.overall_score} grade={report.grade} />
                  <div className="flex-1">
                    <div className="flex flex-wrap items-center gap-3">
                      <h2 className="text-xl font-semibold">Overall Health Score</h2>
                      <span
                        className={`rounded-full px-3 py-1 text-xs font-medium ${
                          report.production_ready
                            ? "bg-emerald-500/20 text-emerald-300"
                            : "bg-amber-500/20 text-amber-300"
                        }`}
                      >
                        {report.production_ready ? "Production Ready" : "Not Production Ready"}
                      </span>
                    </div>
                    <p className="mt-4 text-sm leading-relaxed text-zinc-300">
                      {report.executive_summary}
                    </p>
                    {report.estimated_score_if_top_fixed != null && (
                      <p className="mt-3 text-sm text-emerald-400">
                        Fix top critical/high issues → estimated score{" "}
                        {report.estimated_score_if_top_fixed}/100
                      </p>
                    )}
                  </div>
                </div>

                <div className="mt-8">
                  <h3 className="mb-4 text-sm font-medium uppercase tracking-widest text-zinc-500">
                    Category Breakdown
                  </h3>
                  <CategoryBreakdown categories={report.categories} />
                </div>

                {report.fix_plan.length > 0 && (
                  <div className="mt-8">
                    <h3 className="mb-4 text-sm font-medium uppercase tracking-widest text-zinc-500">
                      Recommended Fix Order
                    </h3>
                    <ol className="space-y-2">
                      {report.fix_plan.map((step) => (
                        <li
                          key={step}
                          className="rounded-lg border border-zinc-800 bg-zinc-950/50 px-4 py-3 text-sm text-zinc-300"
                        >
                          {step}
                        </li>
                      ))}
                    </ol>
                  </div>
                )}
              </section>
            )}

            {report && scan.status === "completed" && (
              <TopFixNowPanel
                issues={report.fix_now_issues}
                fixNowCount={report.fix_now_count}
                maxRiskScore={report.max_risk_score}
                onSelect={setSelectedIssue}
              />
            )}

            {report && scan.status === "completed" && <AIAuditSummary report={report} />}

            {report && scan.status === "completed" && report.compliance.length > 0 && (
              <ComplianceBreakdown controls={report.compliance} />
            )}

            {scan.status === "completed" && (
              <AuditChatPanel
                scanId={scanId}
                getToken={getToken}
                deepAuditEnabled={subscription?.features.deep_audit ?? false}
              />
            )}

            <div className="mt-8 grid grid-cols-2 gap-4 sm:grid-cols-5">
              <CountCard label="Total" value={scan.total_issues} />
              <CountCard label="Critical" value={scan.critical_count} color="text-red-400" />
              <CountCard label="High" value={scan.high_count} color="text-orange-400" />
              <CountCard label="Medium" value={scan.medium_count} color="text-amber-400" />
              <CountCard label="Low" value={scan.low_count} color="text-zinc-400" />
            </div>

            <div className="mt-8 flex flex-wrap gap-2">
              {severityFilters.map((s) => (
                <FilterButton
                  key={s}
                  active={severityFilter === s}
                  onClick={() => setSeverityFilter(s)}
                  label={s}
                />
              ))}
            </div>

            <div className="mt-3 flex flex-wrap gap-2">
              {categoryFilters.map((c) => (
                <FilterButton
                  key={c}
                  active={categoryFilter === c}
                  onClick={() => setCategoryFilter(c)}
                  label={c}
                />
              ))}
            </div>

            <div className="mt-6 space-y-4">
              {issues.length === 0 && scan.status === "completed" && (
                <p className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-8 text-center text-zinc-400">
                  No issues match your filters.
                </p>
              )}
              {issues.map((issue) => (
                <IssueCard
                  key={issue.id}
                  issue={issue}
                  onSelect={setSelectedIssue}
                />
              ))}
            </div>
          </>
        )}
      </main>

      <IssueDetailModal
        issue={selectedIssue}
        scanId={scanId}
        onClose={() => setSelectedIssue(null)}
        onDismiss={handleDismissIssue}
        onAutofix={(issue, prUrl) =>
          setSelectedIssue({ ...issue, autofix_pr_url: prUrl })
        }
      />
    </div>
  );
}

function CountCard({
  label,
  value,
  color = "text-zinc-50",
}: {
  label: string;
  value: number;
  color?: string;
}) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-4 text-center">
      <p className="text-xs text-zinc-500">{label}</p>
      <p className={`mt-1 text-2xl font-bold ${color}`}>{value}</p>
    </div>
  );
}

function FilterButton({
  active,
  onClick,
  label,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-lg px-3 py-1.5 text-sm capitalize transition ${
        active
          ? "bg-emerald-500 text-zinc-950"
          : "border border-zinc-700 text-zinc-400 hover:text-white"
      }`}
    >
      {label}
    </button>
  );
}
