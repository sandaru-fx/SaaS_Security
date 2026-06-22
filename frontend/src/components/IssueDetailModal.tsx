import { ApiIssue } from "@/lib/api";
import { useAuth } from "@clerk/nextjs";
import { useState } from "react";
import { createAutofixPr } from "@/lib/api";

type IssueDetailModalProps = {
  issue: ApiIssue | null;
  scanId?: string;
  onClose: () => void;
  onDismiss?: (issue: ApiIssue) => void;
  onAutofix?: (issue: ApiIssue, prUrl: string) => void;
};

export function IssueDetailModal({ issue, scanId, onClose, onDismiss, onAutofix }: IssueDetailModalProps) {
  const { getToken } = useAuth();
  const [autofixLoading, setAutofixLoading] = useState(false);
  const [autofixError, setAutofixError] = useState<string | null>(null);

  if (!issue) return null;

  async function handleAutofix() {
    if (!scanId) return;
    setAutofixLoading(true);
    setAutofixError(null);
    try {
      const token = await getToken();
      if (!token) throw new Error("Not authenticated");
      const result = await createAutofixPr(token, scanId, issue.id);
      onAutofix?.(issue, result.pr_url);
      window.open(result.pr_url, "_blank");
    } catch (err) {
      setAutofixError(err instanceof Error ? err.message : "Auto-fix failed");
    } finally {
      setAutofixLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
      <div className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-2xl border border-zinc-700 bg-zinc-900 p-6 shadow-2xl">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-xs font-medium uppercase tracking-widest text-emerald-400">
              Audit Finding
            </p>
            <h2 className="mt-2 text-xl font-bold text-zinc-50">{issue.title}</h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-zinc-700 px-3 py-1 text-sm text-zinc-400 hover:text-white"
          >
            Close
          </button>
        </div>

        <div className="mt-4 flex flex-wrap gap-2">
          <Badge label={issue.severity} />
          {issue.priority != null && <Badge label={`Risk ${issue.priority}`} />}
          {issue.fix_now && <Badge label="FIX NOW" tone="rose" />}
          {issue.kev_listed && <Badge label="CISA KEV" tone="rose" />}
          {issue.epss_score != null && issue.epss_score >= 0.1 && (
            <Badge label={`EPSS ${(issue.epss_score * 100).toFixed(1)}%`} tone="orange" />
          )}
          {issue.severity_adjusted && (
            <Badge label={`Adjusted → ${issue.severity_adjusted}`} warn />
          )}
          {issue.report_category && <Badge label={issue.report_category} />}
          {issue.ai_triage_verdict && (
            <Badge
              label={issue.ai_triage_verdict.replace(/_/g, " ")}
              warn={issue.ai_triage_verdict === "likely_false_positive"}
            />
          )}
          {issue.cwe_id && <Badge label={issue.cwe_id} />}
          {issue.owasp_category && <Badge label={issue.owasp_category} />}
          <Badge label={issue.scanner} />
          {issue.taint_verified && <Badge label="Taint verified" tone="violet" />}
          {issue.reachable === "yes" && <Badge label="Reachable" tone="rose" />}
          {issue.reachable === "no" && <Badge label="Not reached" tone="zinc" />}
          {issue.validated === "active" && <Badge label="VALIDATED ACTIVE" tone="rose" />}
          {issue.validated === "inactive" && <Badge label="Revoked" tone="zinc" />}
        </div>

        {issue.validated === "active" && (
          <Section
            title="Live Secret Validation"
            content={`This credential is currently ACTIVE on the provider's API${
              issue.validated_principal ? ` (${issue.validated_principal})` : ""
            }. Validation: ${issue.validated_method ?? "unknown method"}. Rotate immediately and audit recent usage.`}
            warn
          />
        )}
        {issue.validated === "inactive" && issue.validated_method && (
          <Section
            title="Live Secret Validation"
            content={`Provider returned 401/403/404 when probed via ${issue.validated_method} — credential appears revoked or invalid. Lower-priority cleanup, but rotate to be safe.`}
          />
        )}
        {issue.secret_preview && (
          <Section
            title="Detected Value (masked)"
            content={issue.secret_preview}
          />
        )}

        {issue.reachable === "yes" && issue.reachable_files && (
          <Section
            title="Reachable from"
            content={`Imported in: ${issue.reachable_files}`}
            highlight
          />
        )}
        {issue.reachable === "no" && (
          <Section
            title="Reachability"
            content="No import / require / use statement was found for this dependency in your source code. The CVE is unlikely to be exploitable through your code paths. Severity was reduced one notch."
          />
        )}
        {issue.taint_verified && (
          <Section
            title="Taint Analysis"
            content="Source-to-sink data flow verified: user-controlled input reaches this dangerous sink. This is a confirmed exploitable path, not a regex guess."
            highlight
          />
        )}

        {(issue.risk_score != null || issue.risk_factors) && (
          <Section
            title="Risk Scoring v2"
            content={[
              issue.risk_score != null ? `Risk score: ${issue.risk_score}/100` : null,
              issue.epss_score != null ? `EPSS exploit probability: ${(issue.epss_score * 100).toFixed(2)}%` : null,
              issue.kev_listed ? "Listed in CISA Known Exploited Vulnerabilities (KEV) catalog" : null,
              issue.fix_now ? "Flagged as FIX NOW — address before next release" : null,
              issue.risk_factors ? `Signals: ${issue.risk_factors.replace(/,/g, ", ")}` : null,
            ]
              .filter(Boolean)
              .join(". ")}
            warn={issue.fix_now}
          />
        )}

        {issue.ai_triage_reason && (
          <Section title="AI Triage" content={issue.ai_triage_reason} warn />
        )}
        {issue.ai_fix_suggestion && (
          <Section title="Suggested Fix (AI)" content={issue.ai_fix_suggestion} highlight />
        )}

        <Section title="Problem" content={issue.description} />
        <Section title="Impact" content={issue.impact} />
        {issue.business_risk && (
          <Section title="Business Risk" content={issue.business_risk} warn />
        )}
        <Section title="Fix" content={issue.fix_recommendation} highlight />

        {issue.autofix_pr_url && (
          <div className="mt-4">
            <p className="text-xs font-medium uppercase tracking-wider text-zinc-500">Auto-fix PR</p>
            <a
              href={issue.autofix_pr_url}
              target="_blank"
              rel="noopener noreferrer"
              className="mt-2 inline-block text-sm text-emerald-400 underline"
            >
              View pull request on GitHub
            </a>
          </div>
        )}

        {autofixError && (
          <p className="mt-4 rounded-lg border border-red-900 bg-red-950/50 p-3 text-sm text-red-300">
            {autofixError}
          </p>
        )}

        <Section
          title="Priority"
          content={`Severity: ${issue.severity.toUpperCase()} · Confidence: ${issue.confidence}${
            issue.priority != null ? ` · Risk score: ${issue.priority}/100` : ""
          }${issue.severity_adjusted ? ` · Adjusted from scanner severity → ${issue.severity_adjusted}` : ""}`}
        />

        {(issue.file_path || issue.rule_id) && (
          <div className="mt-4 rounded-lg border border-zinc-800 bg-zinc-950/60 p-4 font-mono text-xs text-zinc-400">
            {issue.file_path && (
              <p>
                File: {issue.file_path}
                {issue.line_start > 0 && `:${issue.line_start}`}
              </p>
            )}
            <p className="mt-1">Rule: {issue.rule_id}</p>
          </div>
        )}

        {issue.dismissed ? (
          <p className="mt-4 rounded-lg border border-zinc-700 bg-zinc-900 px-4 py-3 text-sm text-zinc-400">
            Dismissed as false positive
            {issue.dismissed_reason && ` — ${issue.dismissed_reason}`}
          </p>
        ) : (
          <div className="mt-4 flex flex-wrap gap-3">
            {issue.autofixable && scanId && (
              <button
                type="button"
                onClick={handleAutofix}
                disabled={autofixLoading}
                className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:opacity-50"
              >
                {autofixLoading ? "Opening PR…" : "Create Fix PR on GitHub"}
              </button>
            )}
            {onDismiss && (
              <button
                type="button"
                onClick={() => onDismiss(issue)}
                className="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-400 hover:border-zinc-500 hover:text-zinc-200"
              >
                Dismiss as false positive
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function Section({
  title,
  content,
  highlight = false,
  warn = false,
}: {
  title: string;
  content: string;
  highlight?: boolean;
  warn?: boolean;
}) {
  const tone = highlight ? "text-emerald-300" : warn ? "text-amber-300" : "text-zinc-300";
  return (
    <div className="mt-4">
      <p className="text-xs font-medium uppercase tracking-wider text-zinc-500">{title}</p>
      <p className={`mt-2 text-sm leading-relaxed ${tone}`}>{content}</p>
    </div>
  );
}

function Badge({
  label,
  warn = false,
  tone = "default",
}: {
  label: string;
  warn?: boolean;
  tone?: "default" | "violet" | "rose" | "zinc" | "orange";
}) {
  let cls = "border-zinc-700 text-zinc-300";
  if (warn) cls = "border-amber-500/40 text-amber-300";
  else if (tone === "violet") cls = "border-violet-500/40 bg-violet-500/10 text-violet-300";
  else if (tone === "rose") cls = "border-rose-500/40 bg-rose-500/10 text-rose-300";
  else if (tone === "orange") cls = "border-orange-500/40 bg-orange-500/10 text-orange-300";
  else if (tone === "zinc") cls = "border-zinc-700 bg-zinc-800/40 text-zinc-400";
  return (
    <span className={`rounded-full border px-2.5 py-1 text-xs capitalize ${cls}`}>{label}</span>
  );
}
