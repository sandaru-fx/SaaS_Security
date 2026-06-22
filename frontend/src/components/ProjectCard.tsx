import Link from "next/link";

import { ApiProject } from "@/lib/api";

const statusStyles: Record<ApiProject["status"], string> = {
  pending: "bg-zinc-600",
  processing: "bg-amber-500",
  ready: "bg-emerald-500",
  failed: "bg-red-500",
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
          {project.source_type === "github" ? "GitHub" : "ZIP Upload"}
        </span>
        {project.file_count > 0 && (
          <span className="rounded-full border border-zinc-700 px-2.5 py-1 text-zinc-400">
            {project.file_count} files
          </span>
        )}
        <span className="rounded-full border border-zinc-700 px-2.5 py-1 capitalize text-zinc-400">
          {project.status}
        </span>
      </div>

      {project.repo_url && (
        <p className="mt-3 truncate font-mono text-xs text-zinc-500">{project.repo_url}</p>
      )}
    </Link>
  );
}
