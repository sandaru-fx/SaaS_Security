"use client";

import { useAuth } from "@clerk/nextjs";
import Link from "next/link";
import { FormEvent, useEffect, useState } from "react";

import { AppHeader } from "@/components/AppHeader";
import {
  createGithubProject,
  createLocalProject,
  createWebsiteProject,
  getApiFeatures,
  uploadFolderProject,
  uploadZipProject,
} from "@/lib/api";

type Tab = "github" | "folder" | "zip" | "local" | "website";

export default function NewProjectPage() {
  const { getToken } = useAuth();
  const [tab, setTab] = useState<Tab>("folder");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [localPathsEnabled, setLocalPathsEnabled] = useState(false);

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [repoUrl, setRepoUrl] = useState("");
  const [branch, setBranch] = useState("main");
  const [zipFile, setZipFile] = useState<File | null>(null);
  const [folderFiles, setFolderFiles] = useState<File[]>([]);
  const [folderLabel, setFolderLabel] = useState("");
  const [localPath, setLocalPath] = useState("");
  const [websiteUrl, setWebsiteUrl] = useState("");
  const [ownershipConfirmed, setOwnershipConfirmed] = useState(false);

  useEffect(() => {
    getApiFeatures().then((features) => {
      setLocalPathsEnabled(features.local_project_paths);
    });
  }, []);

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
      } else if (tab === "website") {
        if (!ownershipConfirmed) {
          throw new Error("You must confirm you own or have permission to scan this website");
        }
        const project = await createWebsiteProject(token, {
          name,
          website_url: websiteUrl,
          description: description || undefined,
          ownership_confirmed: true,
        });
        projectId = project.id;
      } else if (tab === "folder") {
        if (folderFiles.length === 0) throw new Error("Please select a project folder");
        const project = await uploadFolderProject(token, {
          name,
          files: folderFiles,
          description: description || undefined,
        });
        projectId = project.id;
      } else if (tab === "local") {
        if (!localPath.trim()) throw new Error("Enter the full path to your project folder");
        const project = await createLocalProject(token, {
          name,
          local_path: localPath.trim(),
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

  function handleFolderChange(event: React.ChangeEvent<HTMLInputElement>) {
    const files = Array.from(event.target.files ?? []);
    setFolderFiles(files);
    if (files.length > 0) {
      const root = files[0].webkitRelativePath.split("/")[0];
      setFolderLabel(root || `${files.length} files selected`);
      if (!name.trim() && root) {
        setName(root);
      }
    } else {
      setFolderLabel("");
    }
  }

  const loadingLabel =
    tab === "github"
      ? "Cloning repository..."
      : tab === "website"
        ? "Verifying website..."
        : tab === "folder"
          ? "Uploading folder..."
          : tab === "local"
            ? "Linking local folder..."
            : "Uploading & extracting...";

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50">
      <AppHeader badge="New Project" />

      <main className="mx-auto max-w-2xl px-6 py-12">
        <Link href="/projects" className="text-sm text-zinc-500 hover:text-zinc-300">
          ← Back to Projects
        </Link>

        <h1 className="mt-4 text-3xl font-bold tracking-tight">Create Project</h1>
        <p className="mt-2 text-zinc-400">
          Open a local folder, connect GitHub, upload a ZIP, or scan a live website.
        </p>
        <p className="mt-3 rounded-lg border border-indigo-500/20 bg-indigo-950/20 px-4 py-3 text-sm text-indigo-200">
          Private GitHub repos are available on{" "}
          <a href="/billing" className="font-medium text-indigo-300 underline">
            Pro & Team plans
          </a>
          . Public repos work on the Free plan.
        </p>

        <div className="mt-8 flex flex-wrap gap-2 rounded-lg border border-zinc-800 bg-zinc-900/50 p-1">
          <TabButton active={tab === "folder"} onClick={() => setTab("folder")}>
            Open Folder
          </TabButton>
          {localPathsEnabled && (
            <TabButton active={tab === "local"} onClick={() => setTab("local")}>
              Local Path
            </TabButton>
          )}
          <TabButton active={tab === "github"} onClick={() => setTab("github")}>
            GitHub
          </TabButton>
          <TabButton active={tab === "zip"} onClick={() => setTab("zip")}>
            ZIP
          </TabButton>
          <TabButton active={tab === "website"} onClick={() => setTab("website")}>
            Website
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

          {tab === "folder" ? (
            <Field label="Project Folder" required>
              <input
                type="file"
                required
                // @ts-expect-error webkitdirectory is supported by Chromium browsers
                webkitdirectory=""
                directory=""
                multiple
                onChange={handleFolderChange}
                className="w-full text-sm text-zinc-400 file:mr-4 file:rounded-lg file:border-0 file:bg-emerald-500 file:px-4 file:py-2 file:text-sm file:font-semibold file:text-zinc-950"
              />
              {folderLabel && (
                <p className="mt-2 text-sm text-emerald-300">
                  Selected: <span className="font-mono">{folderLabel}</span> ({folderFiles.length}{" "}
                  files)
                </p>
              )}
              <p className="mt-2 text-xs text-zinc-500">
                Pick any folder on your PC — like opening a project in VS Code. Skips{" "}
                <code className="text-zinc-400">node_modules</code> and{" "}
                <code className="text-zinc-400">.git</code> automatically. Max 50MB total.
              </p>
            </Field>
          ) : tab === "local" ? (
            <>
              <Field label="Folder Path on This Machine" required>
                <input
                  type="text"
                  required
                  value={localPath}
                  onChange={(e) => setLocalPath(e.target.value)}
                  placeholder="C:\Users\User\Desktop\MyProject"
                  className={inputClass}
                />
              </Field>
              <p className="text-xs text-zinc-500">
                Local dev only — backend reads files directly from disk (no upload). Scans always
                use the latest files in that folder.
              </p>
            </>
          ) : tab === "github" ? (
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
            </>
          ) : tab === "website" ? (
            <>
              <Field label="Website URL" required>
                <input
                  type="url"
                  required
                  value={websiteUrl}
                  onChange={(e) => setWebsiteUrl(e.target.value)}
                  placeholder="https://example.com"
                  className={inputClass}
                />
              </Field>
              <label className="flex items-start gap-3 rounded-lg border border-zinc-800 bg-zinc-900/50 p-4">
                <input
                  type="checkbox"
                  checked={ownershipConfirmed}
                  onChange={(e) => setOwnershipConfirmed(e.target.checked)}
                  className="mt-1 h-4 w-4 rounded border-zinc-600 bg-zinc-800 text-emerald-500"
                />
                <span className="text-sm text-zinc-300">
                  I confirm I own this website or have explicit permission to run a security
                  scan against it.
                </span>
              </label>
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
            {loading ? loadingLabel : "Create Project"}
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
      className={`flex-1 rounded-md px-3 py-2 text-sm font-medium transition ${
        active ? "bg-emerald-500 text-zinc-950" : "text-zinc-400 hover:text-zinc-200"
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
