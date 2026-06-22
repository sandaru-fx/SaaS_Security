"use client";

import { useAuth } from "@clerk/nextjs";
import Link from "next/link";
import { FormEvent, useState } from "react";

import { AppHeader } from "@/components/AppHeader";
import { createGithubProject, uploadZipProject } from "@/lib/api";

type Tab = "github" | "zip";

export default function NewProjectPage() {
  const { getToken } = useAuth();
  const [tab, setTab] = useState<Tab>("github");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [repoUrl, setRepoUrl] = useState("");
  const [branch, setBranch] = useState("main");
  const [zipFile, setZipFile] = useState<File | null>(null);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const token = await getToken();
      if (!token) throw new Error("Not authenticated");

      let projectId: string;

      if (tab === "github") {
        const project = await createGithubProject(token, {
          name,
          repo_url: repoUrl,
          branch,
          description: description || undefined,
        });
        projectId = project.id;
      } else {
        if (!zipFile) throw new Error("Please select a ZIP file");
        const project = await uploadZipProject(token, {
          name,
          file: zipFile,
          description: description || undefined,
        });
        projectId = project.id;
      }

      window.location.href = `/projects/${projectId}`;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create project");
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50">
      <AppHeader badge="New Project" />

      <main className="mx-auto max-w-2xl px-6 py-12">
        <Link href="/projects" className="text-sm text-zinc-500 hover:text-zinc-300">
          ← Back to Projects
        </Link>

        <h1 className="mt-4 text-3xl font-bold tracking-tight">Create Project</h1>
        <p className="mt-2 text-zinc-400">
          Connect a public GitHub repository or upload your code as a ZIP file.
        </p>

        <div className="mt-8 flex gap-2 rounded-lg border border-zinc-800 bg-zinc-900/50 p-1">
          <TabButton active={tab === "github"} onClick={() => setTab("github")}>
            GitHub Repo
          </TabButton>
          <TabButton active={tab === "zip"} onClick={() => setTab("zip")}>
            ZIP Upload
          </TabButton>
        </div>

        <form onSubmit={handleSubmit} className="mt-6 space-y-5">
          <Field label="Project Name" required>
            <input
              type="text"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="My SaaS App"
              className={inputClass}
            />
          </Field>

          <Field label="Description (optional)">
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Brief description of this project..."
              rows={3}
              className={inputClass}
            />
          </Field>

          {tab === "github" ? (
            <>
              <Field label="GitHub URL" required>
                <input
                  type="url"
                  required
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  placeholder="https://github.com/owner/repository"
                  className={inputClass}
                />
              </Field>
              <Field label="Branch">
                <input
                  type="text"
                  value={branch}
                  onChange={(e) => setBranch(e.target.value)}
                  placeholder="main"
                  className={inputClass}
                />
              </Field>
              <p className="text-xs text-zinc-500">
                Only public GitHub repositories are supported in this version.
              </p>
            </>
          ) : (
            <Field label="ZIP File" required>
              <input
                type="file"
                accept=".zip"
                required
                onChange={(e) => setZipFile(e.target.files?.[0] ?? null)}
                className="w-full text-sm text-zinc-400 file:mr-4 file:rounded-lg file:border-0 file:bg-emerald-500 file:px-4 file:py-2 file:text-sm file:font-semibold file:text-zinc-950"
              />
              <p className="mt-2 text-xs text-zinc-500">Maximum file size: 50MB</p>
            </Field>
          )}

          {error && (
            <p className="rounded-lg border border-red-900 bg-red-950/50 p-4 text-sm text-red-300">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-lg bg-emerald-500 py-3 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-400 disabled:opacity-50"
          >
            {loading
              ? tab === "github"
                ? "Cloning repository..."
                : "Uploading & extracting..."
              : "Create Project"}
          </button>
        </form>
      </main>
    </div>
  );
}

const inputClass =
  "w-full rounded-lg border border-zinc-700 bg-zinc-800 px-4 py-2.5 text-zinc-50 outline-none focus:border-emerald-500";

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`flex-1 rounded-md px-4 py-2 text-sm font-medium transition ${
        active
          ? "bg-emerald-500 text-zinc-950"
          : "text-zinc-400 hover:text-zinc-200"
      }`}
    >
      {children}
    </button>
  );
}

function Field({
  label,
  required,
  children,
}: {
  label: string;
  required?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label className="mb-1.5 block text-sm text-zinc-400">
        {label}
        {required && <span className="text-red-400"> *</span>}
      </label>
      {children}
    </div>
  );
}
