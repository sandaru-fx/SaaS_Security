"use client";

import { useAuth } from "@clerk/nextjs";
import Link from "next/link";
import { useEffect, useState } from "react";

import { AppHeader } from "@/components/AppHeader";
import { PricingCards } from "@/components/PricingCards";
import {
  PricingData,
  SubscriptionInfo,
  createBillingPortal,
  createCheckout,
  getPricing,
  getSubscription,
} from "@/lib/api";

export default function BillingPage() {
  const { getToken } = useAuth();
  const [pricing, setPricing] = useState<PricingData | null>(null);
  const [subscription, setSubscription] = useState<SubscriptionInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingPlan, setLoadingPlan] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("success") === "1") {
      setMessage("Subscription updated successfully. Welcome to your new plan!");
    } else if (params.get("canceled") === "1") {
      setMessage("Checkout was canceled. You can upgrade anytime.");
    }
  }, []);

  useEffect(() => {
    async function load() {
      try {
        const token = await getToken();
        const [pricingData, subData] = await Promise.all([
          getPricing(),
          token ? getSubscription(token) : null,
        ]);
        setPricing(pricingData);
        setSubscription(subData);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load billing");
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [getToken]);

  async function handleUpgrade(planId: string) {
    if (planId !== "pro" && planId !== "team") return;
    setLoadingPlan(planId);
    setError(null);
    try {
      const token = await getToken();
      if (!token) return;
      const url = await createCheckout(token, planId);
      window.location.href = url;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Checkout failed");
      setLoadingPlan(null);
    }
  }

  async function handleManageBilling() {
    setError(null);
    try {
      const token = await getToken();
      if (!token) return;
      const url = await createBillingPortal(token);
      window.location.href = url;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not open billing portal");
    }
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50">
      <AppHeader badge="Phase 9 — Billing" />

      <main className="mx-auto max-w-6xl px-6 py-12">
        <div className="mb-8">
          <h1 className="text-3xl font-bold tracking-tight">Billing & Plans</h1>
          <p className="mt-2 text-zinc-400">
            Manage your subscription, usage limits, and Pro features.
          </p>
        </div>

        {message && (
          <p className="mb-6 rounded-lg border border-emerald-500/30 bg-emerald-950/30 p-4 text-sm text-emerald-200">
            {message}
          </p>
        )}
        {error && (
          <p className="mb-6 rounded-lg border border-red-900 bg-red-950/50 p-4 text-sm text-red-300">
            {error}
          </p>
        )}

        {loading && <p className="text-zinc-400">Loading billing...</p>}

        {subscription && (
          <section className="mb-10 rounded-2xl border border-zinc-800 bg-zinc-900/50 p-6">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <p className="text-xs uppercase tracking-widest text-zinc-500">Current Plan</p>
                <h2 className="mt-2 text-2xl font-bold">
                  {subscription.plan_label}{" "}
                  <span className="text-lg font-normal text-zinc-400">
                    ({subscription.price_display})
                  </span>
                </h2>
                <p className="mt-2 text-sm text-zinc-400">
                  {subscription.features.unlimited_scans
                    ? "Unlimited audits this month"
                    : `${subscription.scans_used}/${subscription.scan_limit} audits used this month`}
                  {subscription.scans_remaining != null &&
                    ` · ${subscription.scans_remaining} remaining`}
                </p>
              </div>
              {subscription.has_active_subscription && subscription.stripe_enabled && (
                <button
                  type="button"
                  onClick={handleManageBilling}
                  className="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-300 hover:border-zinc-500"
                >
                  Manage Subscription
                </button>
              )}
            </div>

            <div className="mt-6 flex flex-wrap gap-2">
              {subscription.features.pdf_export && (
                <FeatureBadge label="PDF Export" />
              )}
              {subscription.features.deep_audit && (
                <FeatureBadge label="AI Deep Audit" />
              )}
              {subscription.features.private_repos && (
                <FeatureBadge label="Private Repos" />
              )}
              {!subscription.features.pdf_export && (
                <Link href="#plans" className="text-sm text-emerald-400 hover:text-emerald-300">
                  Upgrade for PDF export & AI Deep Audit →
                </Link>
              )}
            </div>
          </section>
        )}

        {pricing && (
          <section id="plans">
            <h2 className="mb-6 text-sm font-medium uppercase tracking-widest text-zinc-500">
              Choose Your Plan
            </h2>
            <PricingCards
              plans={pricing.plans}
              currentPlan={subscription?.plan}
              onSelectPlan={handleUpgrade}
              loadingPlan={loadingPlan}
              stripeEnabled={pricing.stripe_enabled}
            />
            {!pricing.stripe_enabled && (
              <p className="mt-4 text-sm text-amber-300">
                Stripe is not configured. Add STRIPE_SECRET_KEY and price IDs to `.env` to enable
                payments. Free plan works without Stripe.
              </p>
            )}
          </section>
        )}
      </main>
    </div>
  );
}

function FeatureBadge({ label }: { label: string }) {
  return (
    <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs text-emerald-300">
      {label}
    </span>
  );
}
