import Link from "next/link";

import { PricingPlan } from "@/lib/api";

type PricingCardsProps = {
  plans: PricingPlan[];
  currentPlan?: string;
  onSelectPlan?: (planId: string) => void;
  loadingPlan?: string | null;
  stripeEnabled?: boolean;
};

export function PricingCards({
  plans,
  currentPlan,
  onSelectPlan,
  loadingPlan,
  stripeEnabled = false,
}: PricingCardsProps) {
  return (
    <div className="grid gap-6 lg:grid-cols-3">
      {plans.map((plan) => {
        const isCurrent = currentPlan === plan.id;
        const highlighted = plan.id === "pro";

        return (
          <div
            key={plan.id}
            className={`rounded-2xl border p-6 ${
              highlighted
                ? "border-emerald-500/50 bg-emerald-950/20"
                : "border-zinc-800 bg-zinc-900/50"
            }`}
          >
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold text-zinc-50">{plan.label}</h3>
              {isCurrent && (
                <span className="rounded-full bg-emerald-500/20 px-2.5 py-1 text-xs text-emerald-300">
                  Current
                </span>
              )}
            </div>
            <p className="mt-2 text-3xl font-bold text-zinc-50">{plan.price_display}</p>
            <ul className="mt-6 space-y-2">
              {plan.features.map((feature) => (
                <li key={feature} className="flex items-start gap-2 text-sm text-zinc-300">
                  <span className="text-emerald-400">✓</span>
                  {feature}
                </li>
              ))}
            </ul>

            <div className="mt-8">
              {plan.id === "free" ? (
                <Link
                  href="/sign-up"
                  className="block w-full rounded-lg border border-zinc-700 px-4 py-2.5 text-center text-sm font-medium text-zinc-300 hover:border-zinc-500"
                >
                  Get Started
                </Link>
              ) : isCurrent ? (
                <button
                  type="button"
                  disabled
                  className="w-full rounded-lg border border-zinc-700 px-4 py-2.5 text-sm text-zinc-500"
                >
                  Current Plan
                </button>
              ) : onSelectPlan ? (
                <button
                  type="button"
                  onClick={() => onSelectPlan(plan.id)}
                  disabled={!stripeEnabled || loadingPlan === plan.id}
                  className="w-full rounded-lg bg-emerald-500 px-4 py-2.5 text-sm font-semibold text-zinc-950 hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {loadingPlan === plan.id
                    ? "Redirecting..."
                    : stripeEnabled
                      ? `Upgrade to ${plan.label}`
                      : "Stripe not configured"}
                </button>
              ) : (
                <Link
                  href="/billing"
                  className="block w-full rounded-lg bg-emerald-500 px-4 py-2.5 text-center text-sm font-semibold text-zinc-950 hover:bg-emerald-400"
                >
                  View Plans
                </Link>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
