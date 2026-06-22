import Link from "next/link";

import { ApiProject, SourceType } from "@/lib/api";

const statusStyles: Record<ApiProject["status"], string> = {
  pending: "bg-zinc-600",
  processing: "bg-amber-500",
  ready: "bg-emerald-500",
  failed: "bg-red-500",
};

const SOURCE_LABELS: Record<SourceType, string> = {
  github: "GitHub",
  zip: "ZIP Upload",
  folder: "Local Folder",
  local: "Local Path",
  website: "Website",
  api: "REST API",
  cloud: "Cloud CSPM",
};

export function ProjectCard({ project }: { project: ApiProject }) {
  return (
    <Link
      href={`/projects/${project.id}`}
      className="block rounded-xl border border-zinc-800 bg-zinc-900/50 p-5 transition hover:border-emerald-500/50 hover:bg-zinc-900"
    >
      <div className="flex items-start justify-between gap-4">
        <div>
          <h3 className="font-semibold text-zinc-50">{project.name}</h3>
          {project.description && (
            <p className="mt-1 line-clamp-2 text-sm text-zinc-400">{project.description}</p>
          )}
        </div>
        <span
          className={`mt-1 h-2.5 w-2.5 shrink-0 rounded-full ${statusStyles[project.status]}`}
          title={project.status}
        />
      </div>

      <div className="mt-4 flex flex-wrap gap-2 text-xs">
        <span className="rounded-full border border-zinc-700 px-2.5 py-1 text-zinc-400">
          {SOURCE_LABELS[project.source_type] ?? project.source_type}
        </span>
        {project.file_count > 0 && (
          <span className="rounded-full border border-zinc-700 px-2.5 py-1 text-zinc-400">
            {project.file_count} files
          </span>
        )}
        <span className="rounded-full border border-zinc-700 px-2.5 py-1 capitalize text-zinc-400">
          {project.status}
        </span>
        {project.active_dast_enabled && (
          <span className="rounded-full border border-rose-500/40 bg-rose-500/10 px-2.5 py-1 font-medium text-rose-300">
            Active DAST
          </span>
        )}
        {project.browser_dast_enabled && (
          <span className="rounded-full border border-indigo-500/40 bg-indigo-500/10 px-2.5 py-1 font-medium text-indigo-300">
            Browser DAST
          </span>
        )}
        {project.zap_dast_enabled && (
          <span className="rounded-full border border-orange-500/40 bg-orange-500/10 px-2.5 py-1 font-medium text-orange-300">
            OWASP ZAP
          </span>
        )}
        {project.has_auth_configured && (
          <span className="rounded-full border border-indigo-500/40 bg-indigo-500/10 px-2.5 py-1 font-medium text-indigo-300">
            Auth
          </span>
        )}
        {project.source_type === "api" && (
          <span className="rounded-full border border-cyan-500/40 bg-cyan-500/10 px-2.5 py-1 font-medium text-cyan-300">
            OWASP API Top 10
          </span>
        )}
        {project.asm_enabled && (
          <span className="rounded-full border border-violet-500/40 bg-violet-500/10 px-2.5 py-1 font-medium text-violet-300">
            ASM Recon
          </span>
        )}
        {project.source_type === "cloud" && project.cloud_provider && (
          <span className="rounded-full border border-sky-500/40 bg-sky-500/10 px-2.5 py-1 font-medium uppercase text-sky-300">
            {project.cloud_provider} CSPM
          </span>
        )}
      </div>

      {project.repo_url && (
        <p className="mt-3 truncate font-mono text-xs text-zinc-500">{project.repo_url}</p>
      )}
    </Link>
  );
}
