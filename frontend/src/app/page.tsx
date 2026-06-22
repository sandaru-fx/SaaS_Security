import Link from "next/link";
import { SignedIn, SignedOut } from "@clerk/nextjs";

import { AppHeader } from "@/components/AppHeader";
import { PricingCards } from "@/components/PricingCards";
import { PricingData } from "@/lib/api";

async function getPricingData(): Promise<PricingData | null> {
  const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
  try {
    const res = await fetch(`${apiUrl}/api/billing/pricing`, { next: { revalidate: 60 } });
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

export default async function Home() {
  const pricing = await getPricingData();

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50">
      <AppHeader badge="Phase 9 — Launch" />

      <main>
        <section className="mx-auto max-w-6xl px-6 py-20">
          <div className="max-w-3xl">
            <p className="mb-4 text-sm font-medium uppercase tracking-widest text-emerald-400">
              AI Software Auditor
            </p>
            <h1 className="text-4xl font-bold leading-tight tracking-tight sm:text-6xl">
              Is your system production-ready?
            </h1>
            <p className="mt-6 text-lg leading-relaxed text-zinc-400">
              Upload your project or connect GitHub. Get a professional audit in the format
              executives understand: Problem → Impact → Business Risk → Fix → Priority.
            </p>
          </div>

          <div className="mt-10 flex flex-wrap gap-4">
            <SignedIn>
              <Link
                href="/dashboard"
                className="rounded-lg bg-emerald-500 px-6 py-3 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-400"
              >
                Go to Dashboard →
              </Link>
            </SignedIn>
            <SignedOut>
              <Link
                href="/sign-up"
                className="rounded-lg bg-emerald-500 px-6 py-3 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-400"
              >
                Start Free — 2 Audits/Month
              </Link>
            </SignedOut>
            <Link
              href="#pricing"
              className="rounded-lg border border-zinc-700 px-6 py-3 text-sm font-medium text-zinc-300 transition hover:border-zinc-500"
            >
              View Pricing
            </Link>
          </div>
        </section>

        <section className="border-y border-zinc-800 bg-zinc-900/30 py-16">
          <div className="mx-auto max-w-6xl px-6">
            <h2 className="text-center text-sm font-medium uppercase tracking-widest text-zinc-500">
              What You Get
            </h2>
            <div className="mt-10 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
              {[
                {
                  title: "Security Audit",
                  desc: "Secrets, vulnerabilities, SQLi, XSS patterns",
                },
                {
                  title: "Architecture Review",
                  desc: "Large files, layering issues, circular deps",
                },
                {
                  title: "Health Score",
                  desc: "0–100 score with category breakdown",
                },
                {
                  title: "AI Auditor",
                  desc: "Business-language executive summaries",
                },
              ].map((item) => (
                <div
                  key={item.title}
                  className="rounded-xl border border-zinc-800 bg-zinc-900/50 p-5"
                >
                  <h3 className="font-semibold text-zinc-100">{item.title}</h3>
                  <p className="mt-2 text-sm text-zinc-400">{item.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section id="pricing" className="mx-auto max-w-6xl px-6 py-20">
          <div className="mb-10 text-center">
            <h2 className="text-3xl font-bold">Simple, Transparent Pricing</h2>
            <p className="mt-3 text-zinc-400">
              Start free. Upgrade when you need unlimited audits, PDF reports, and AI Deep Audit.
            </p>
          </div>
          {pricing ? (
            <PricingCards plans={pricing.plans} stripeEnabled={pricing.stripe_enabled} />
          ) : (
            <p className="text-center text-zinc-500">Pricing unavailable — start the API backend.</p>
          )}
        </section>

        <section className="border-t border-zinc-800 py-12">
          <div className="mx-auto max-w-6xl px-6 text-center">
            <p className="text-zinc-400">
              Trusted format: <span className="text-zinc-200">Problem → Impact → Business Risk → Fix → Priority</span>
            </p>
          </div>
        </section>
      </main>
    </div>
  );
}
