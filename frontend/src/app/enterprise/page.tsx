"use client";

import { useAuth } from "@clerk/nextjs";
import Link from "next/link";
import { FormEvent, useEffect, useState } from "react";

import { AppHeader } from "@/components/AppHeader";
import {
  ApiKeyCreated,
  ApiKeyInfo,
  ApiProject,
  CustomRuleInfo,
  ScheduleInfo,
  createApiKey,
  createCustomRule,
  createSchedule,
  deleteApiKey,
  listApiKeys,
  listCustomRules,
  listProjects,
  listSchedules,
  updateNotificationSettings,
  updateGithubPat,
} from "@/lib/api";

export default function EnterprisePage() {
  const { getToken } = useAuth();
  const [apiKeys, setApiKeys] = useState<ApiKeyInfo[]>([]);
  const [schedules, setSchedules] = useState<ScheduleInfo[]>([]);
  const [rules, setRules] = useState<CustomRuleInfo[]>([]);
  const [projects, setProjects] = useState<ApiProject[]>([]);
  const [newKeyName, setNewKeyName] = useState("CI Pipeline");
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [scheduleProjectId, setScheduleProjectId] = useState("");
  const [ruleName, setRuleName] = useState("");
  const [rulePattern, setRulePattern] = useState("");
  const [emailAlerts, setEmailAlerts] = useState(true);
  const [githubPat, setGithubPat] = useState("");
  const [patConfigured, setPatConfigured] = useState(false);
  const [patSaving, setPatSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const token = await getToken();
        if (!token) return;
        const [keys, scheds, customRules, projectData] = await Promise.all([
          listApiKeys(token).catch(() => []),
          listSchedules(token).catch(() => []),
          listCustomRules(token).catch(() => []),
          listProjects(token),
        ]);
        setApiKeys(keys);
        setSchedules(scheds);
        setRules(customRules);
        setProjects(projectData.projects);
        if (projectData.projects[0]) {
          setScheduleProjectId(projectData.projects[0].id);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load enterprise settings");
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [getToken]);

  async function handleCreateKey(e: FormEvent) {
    e.preventDefault();
    const token = await getToken();
    if (!token) return;
    try {
      const created: ApiKeyCreated = await createApiKey(token, newKeyName);
      setCreatedKey(created.api_key);
      setApiKeys((prev) => [created, ...prev]);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create API key");
    }
  }

  async function handleCreateSchedule(e: FormEvent) {
    e.preventDefault();
    const token = await getToken();
    if (!token || !scheduleProjectId) return;
    try {
      const schedule = await createSchedule(token, {
        project_id: scheduleProjectId,
        frequency: "weekly",
      });
      setSchedules((prev) => [schedule, ...prev]);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create schedule");
    }
  }

  async function handleCreateRule(e: FormEvent) {
    e.preventDefault();
    const token = await getToken();
    if (!token) return;
    try {
      const rule = await createCustomRule(token, {
        name: ruleName,
        pattern: rulePattern,
      });
      setRules((prev) => [rule, ...prev]);
      setRuleName("");
      setRulePattern("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create rule");
    }
  }

  async function handleToggleAlerts() {
    const token = await getToken();
    if (!token) return;
    const next = !emailAlerts;
    await updateNotificationSettings(token, next);
    setEmailAlerts(next);
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50">
      <AppHeader badge="Phase 10 — Enterprise" />

      <main className="mx-auto max-w-5xl px-6 py-12">
        <h1 className="text-3xl font-bold">Enterprise Settings</h1>
        <p className="mt-2 text-zinc-400">
          API access, scheduled audits, custom rules, webhooks, and alerts.
        </p>
        <p className="mt-3 text-sm text-amber-300">
          Team plan required for schedules & custom rules. Pro+ for API keys.{" "}
          <Link href="/billing" className="underline">
            Upgrade →
          </Link>
        </p>

        {loading && <p className="mt-8 text-zinc-400">Loading...</p>}
        {error && (
          <p className="mt-6 rounded-lg border border-red-900 bg-red-950/50 p-4 text-sm text-red-300">
            {error}
          </p>
        )}

        <div className="mt-10 space-y-10">
          <Section title="API Keys (CI/CD)">
            <p className="mb-4 text-sm text-zinc-400">
              Use <code className="text-emerald-400">X-API-Key</code> header with{" "}
              <code className="text-zinc-300">POST /api/v1/projects/&#123;id&#125;/scans</code>
            </p>
            {createdKey && (
              <div className="mb-4 rounded-lg border border-emerald-500/30 bg-emerald-950/20 p-4">
                <p className="text-xs text-emerald-300">Copy now — shown once:</p>
                <code className="mt-2 block break-all text-sm text-emerald-200">{createdKey}</code>
              </div>
            )}
            <form onSubmit={handleCreateKey} className="flex gap-2">
              <input
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
                className="flex-1 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm"
              />
              <button
                type="submit"
                className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-zinc-950"
              >
                Create Key
              </button>
            </form>
            <ul className="mt-4 space-y-2">
              {apiKeys.map((key) => (
                <li
                  key={key.id}
                  className="flex items-center justify-between rounded-lg border border-zinc-800 px-4 py-2 text-sm"
                >
                  <span>
                    {key.name} · <code>{key.key_prefix}...</code>
                  </span>
                  <button
                    type="button"
                    onClick={async () => {
                      const token = await getToken();
                      if (!token) return;
                      await deleteApiKey(token, key.id);
                      setApiKeys((prev) => prev.filter((k) => k.id !== key.id));
                    }}
                    className="text-red-400 hover:text-red-300"
                  >
                    Delete
                  </button>
                </li>
              ))}
            </ul>
          </Section>

          <Section title="Scheduled Audits">
            <form onSubmit={handleCreateSchedule} className="flex flex-wrap gap-2">
              <select
                value={scheduleProjectId}
                onChange={(e) => setScheduleProjectId(e.target.value)}
                className="rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm"
              >
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
              <button
                type="submit"
                className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-zinc-950"
              >
                Add Weekly Schedule
              </button>
            </form>
            <ul className="mt-4 space-y-2 text-sm text-zinc-300">
              {schedules.map((s) => (
                <li key={s.id} className="rounded-lg border border-zinc-800 px-4 py-2">
                  {s.frequency} · next {new Date(s.next_run_at).toLocaleString()}
                </li>
              ))}
            </ul>
          </Section>

          <Section title="Custom Rules">
            <form onSubmit={handleCreateRule} className="space-y-2">
              <input
                placeholder="Rule name"
                value={ruleName}
                onChange={(e) => setRuleName(e.target.value)}
                className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm"
              />
              <input
                placeholder="Regex pattern"
                value={rulePattern}
                onChange={(e) => setRulePattern(e.target.value)}
                className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm font-mono"
              />
              <button
                type="submit"
                className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-zinc-950"
              >
                Add Rule
              </button>
            </form>
            <ul className="mt-4 space-y-2 text-sm">
              {rules.map((r) => (
                <li key={r.id} className="rounded-lg border border-zinc-800 px-4 py-2">
                  <strong>{r.name}</strong> · <code>{r.pattern}</code>
                </li>
              ))}
            </ul>
          </Section>

          <Section title="Email Alerts">
            <button
              type="button"
              onClick={handleToggleAlerts}
              className="rounded-lg border border-zinc-700 px-4 py-2 text-sm"
            >
              Critical issue alerts: {emailAlerts ? "ON" : "OFF"}
            </button>
            <p className="mt-2 text-xs text-zinc-500">
              Configure SMTP in backend `.env` to enable delivery.
            </p>
          </Section>

          <Section title="GitHub Personal Access Token">
            <p className="mb-4 text-sm text-zinc-400">
              Required for <strong>private repositories</strong> and <strong>PR security checks</strong>.
              Create a token with <code>repo</code> scope at github.com/settings/tokens.
            </p>
            {patConfigured && (
              <p className="mb-3 text-sm text-emerald-300">GitHub PAT is configured.</p>
            )}
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                setPatSaving(true);
                try {
                  const token = await getToken();
                  if (!token) return;
                  const result = await updateGithubPat(token, githubPat || null);
                  setPatConfigured(result.github_pat_configured);
                  setGithubPat("");
                  setError(null);
                } catch (err) {
                  setError(err instanceof Error ? err.message : "Failed to save GitHub PAT");
                } finally {
                  setPatSaving(false);
                }
              }}
              className="flex flex-wrap gap-2"
            >
              <input
                type="password"
                placeholder="ghp_..."
                value={githubPat}
                onChange={(e) => setGithubPat(e.target.value)}
                className="min-w-[240px] flex-1 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm font-mono"
              />
              <button
                type="submit"
                disabled={patSaving}
                className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-zinc-950 disabled:opacity-50"
              >
                {patSaving ? "Saving..." : "Save PAT"}
              </button>
            </form>
          </Section>

          <Section title="GitHub PR Webhook">
            <p className="text-sm text-zinc-400">
              In your GitHub repo → Settings → Webhooks, add:
            </p>
            <ul className="mt-2 list-inside list-disc text-sm text-zinc-300">
              <li>
                Payload URL:{" "}
                <code className="text-emerald-400">https://your-api/api/integrations/github/webhook</code>
              </li>
              <li>Content type: application/json</li>
              <li>Events: Pull requests</li>
              <li>Secret: set <code>GITHUB_WEBHOOK_SECRET</code> in backend `.env`</li>
            </ul>
            <p className="mt-2 text-xs text-zinc-500">
              Enable PR checks on each GitHub project from the project settings page.
            </p>
          </Section>

          <Section title="GitHub Actions CI">
            <p className="text-sm text-zinc-400">
              See <code>.github/workflows/auditor-scan.yml</code> in the repo. Set secrets:
              <code className="ml-1">AUDITOR_API_KEY</code>, <code>AUDITOR_PROJECT_ID</code>,{" "}
              <code>AUDITOR_API_URL</code>.
            </p>
          </Section>
        </div>
      </main>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-2xl border border-zinc-800 bg-zinc-900/50 p-6">
      <h2 className="text-sm font-medium uppercase tracking-widest text-zinc-500">{title}</h2>
      <div className="mt-4">{children}</div>
    </section>
  );
}
