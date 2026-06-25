"use client";

import Link from "next/link";
import { useState } from "react";

import { completeOnboarding } from "@/lib/api";

type OnboardingWizardProps = {
  token: string;
  onComplete: () => void;
};

const STEPS = [
  {
    title: "Welcome to AI Software Auditor",
    body: "Upload code, connect GitHub, or scan a live website. You'll get a professional security report in minutes.",
  },
  {
    title: "Create your first project",
    body: "Folder upload is the fastest way to try it — pick any project folder from your PC (node_modules are skipped automatically).",
  },
  {
    title: "Run your first audit",
    body: "Open the project, click Start Audit, and review findings ranked by risk score with clear fix recommendations.",
  },
];

export function OnboardingWizard({ token, onComplete }: OnboardingWizardProps) {
  const [step, setStep] = useState(0);
  const [saving, setSaving] = useState(false);

  async function finish() {
    setSaving(true);
    try {
      await completeOnboarding(token);
      onComplete();
    } catch {
      onComplete();
    } finally {
      setSaving(false);
    }
  }

  const current = STEPS[step];
  const isLast = step === STEPS.length - 1;

  return (
    <section className="mb-8 rounded-xl border border-emerald-900/50 bg-emerald-950/20 p-6">
      <p className="text-xs font-medium uppercase tracking-widest text-emerald-400">
        Getting started — step {step + 1} of {STEPS.length}
      </p>
      <h2 className="mt-2 text-xl font-semibold text-zinc-50">{current.title}</h2>
      <p className="mt-2 max-w-2xl text-sm leading-relaxed text-zinc-400">{current.body}</p>

      <div className="mt-6 flex flex-wrap gap-3">
        {step > 0 && (
          <button
            type="button"
            onClick={() => setStep((s) => s - 1)}
            className="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-300 hover:border-zinc-500"
          >
            Back
          </button>
        )}
        {!isLast ? (
          <button
            type="button"
            onClick={() => setStep((s) => s + 1)}
            className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-zinc-950 hover:bg-emerald-400"
          >
            Next
          </button>
        ) : (
          <>
            <Link
              href="/projects/new"
              className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-zinc-950 hover:bg-emerald-400"
            >
              Create first project →
            </Link>
            <button
              type="button"
              disabled={saving}
              onClick={finish}
              className="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-300 hover:border-zinc-500 disabled:opacity-50"
            >
              {saving ? "Saving…" : "Dismiss guide"}
            </button>
          </>
        )}
      </div>
    </section>
  );
}
