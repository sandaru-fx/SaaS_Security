"use client";

import { useAuth, useUser } from "@clerk/nextjs";
import Image from "next/image";
import { FormEvent, useEffect, useState } from "react";

import { AppHeader } from "@/components/AppHeader";
import { ApiUser, getCurrentUser, updateCurrentUser, updateNotificationSettings } from "@/lib/api";

export default function ProfilePage() {
  const { getToken } = useAuth();
  const { user } = useUser();
  const [apiUser, setApiUser] = useState<ApiUser | null>(null);
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [emailAlerts, setEmailAlerts] = useState(true);
  const [slackAlerts, setSlackAlerts] = useState(false);
  const [slackWebhook, setSlackWebhook] = useState("");
  const [savingNotifications, setSavingNotifications] = useState(false);

  useEffect(() => {
    async function loadProfile() {
      try {
        const token = await getToken();
        if (!token) return;
        const data = await getCurrentUser(token);
        setApiUser(data);
        setFirstName(data.first_name ?? user?.firstName ?? "");
        setLastName(data.last_name ?? user?.lastName ?? "");
        setEmailAlerts(data.email_alerts_enabled ?? true);
        setSlackAlerts(data.slack_alerts_enabled ?? false);
        setSlackWebhook(data.slack_webhook_configured ? "••••••••" : "");
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load profile");
      } finally {
        setLoading(false);
      }
    }

    loadProfile();
  }, [getToken, user?.firstName, user?.lastName]);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    setMessage(null);
    setError(null);

    try {
      const token = await getToken();
      if (!token) throw new Error("Not authenticated");
      const updated = await updateCurrentUser(token, {
        first_name: firstName,
        last_name: lastName,
      });
      setApiUser(updated);
      setMessage("Profile updated successfully");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update profile");
    } finally {
      setSaving(false);
    }
  }

  async function handleNotificationsSubmit(event: FormEvent) {
    event.preventDefault();
    setSavingNotifications(true);
    setMessage(null);
    setError(null);
    try {
      const token = await getToken();
      if (!token) throw new Error("Not authenticated");
      const payload: {
        email_alerts_enabled: boolean;
        slack_alerts_enabled: boolean;
        slack_webhook_url?: string | null;
      } = {
        email_alerts_enabled: emailAlerts,
        slack_alerts_enabled: slackAlerts,
      };
      if (slackWebhook && !slackWebhook.startsWith("••")) {
        payload.slack_webhook_url = slackWebhook;
      }
      const updated = await updateNotificationSettings(token, payload);
      setApiUser(updated);
      setSlackWebhook(updated.slack_webhook_configured ? "••••••••" : "");
      setMessage("Notification settings saved");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save notifications");
    } finally {
      setSavingNotifications(false);
    }
  }

  const avatar = apiUser?.avatar_url ?? user?.imageUrl;

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50">
      <AppHeader badge="Profile" />

      <main className="mx-auto max-w-2xl px-6 py-12">
        <h1 className="text-3xl font-bold tracking-tight">Profile</h1>
        <p className="mt-2 text-zinc-400">Manage your account details.</p>

        <div className="mt-8 rounded-xl border border-zinc-800 bg-zinc-900/50 p-6">
          {loading ? (
            <p className="text-zinc-400">Loading profile...</p>
          ) : (
            <>
              <div className="mb-6 flex items-center gap-4">
                {avatar ? (
                  <Image
                    src={avatar}
                    alt="Avatar"
                    width={64}
                    height={64}
                    className="rounded-full"
                  />
                ) : (
                  <div className="flex h-16 w-16 items-center justify-center rounded-full bg-zinc-800 text-xl font-bold">
                    {(firstName || "U").charAt(0)}
                  </div>
                )}
                <div>
                  <p className="font-medium">{apiUser?.email}</p>
                  <p className="text-sm text-zinc-500">Clerk authenticated</p>
                </div>
              </div>

              <form onSubmit={handleSubmit} className="space-y-4">
                <Field
                  label="First Name"
                  value={firstName}
                  onChange={setFirstName}
                />
                <Field
                  label="Last Name"
                  value={lastName}
                  onChange={setLastName}
                />
                <div>
                  <label className="mb-1 block text-sm text-zinc-400">Email</label>
                  <input
                    type="email"
                    value={apiUser?.email ?? ""}
                    disabled
                    className="w-full rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-2 text-zinc-500"
                  />
                </div>

                {message && (
                  <p className="text-sm text-emerald-400">{message}</p>
                )}
                {error && <p className="text-sm text-red-400">{error}</p>}

                <button
                  type="submit"
                  disabled={saving}
                  className="rounded-lg bg-emerald-500 px-6 py-2.5 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-400 disabled:opacity-50"
                >
                  {saving ? "Saving..." : "Save Changes"}
                </button>
              </form>
            </>
          )}
        </div>

        <div className="mt-6 rounded-xl border border-zinc-800 bg-zinc-900/50 p-6">
          <h2 className="text-lg font-semibold">Notifications</h2>
          <p className="mt-1 text-sm text-zinc-400">
            Email alerts for critical findings (requires SMTP on server). Slack alerts on every completed audit.
          </p>
          <form onSubmit={handleNotificationsSubmit} className="mt-4 space-y-4">
            <label className="flex items-center gap-3 text-sm text-zinc-300">
              <input
                type="checkbox"
                checked={emailAlerts}
                onChange={(e) => setEmailAlerts(e.target.checked)}
                className="rounded border-zinc-600"
              />
              Email me when critical issues are found
            </label>
            <label className="flex items-center gap-3 text-sm text-zinc-300">
              <input
                type="checkbox"
                checked={slackAlerts}
                onChange={(e) => setSlackAlerts(e.target.checked)}
                className="rounded border-zinc-600"
              />
              Send Slack message when an audit completes
            </label>
            <div>
              <label className="mb-1 block text-sm text-zinc-400">Slack Incoming Webhook URL</label>
              <input
                type="url"
                value={slackWebhook}
                onChange={(e) => setSlackWebhook(e.target.value)}
                placeholder="https://hooks.slack.com/services/..."
                className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-4 py-2 text-zinc-50 outline-none focus:border-emerald-500"
              />
            </div>
            <button
              type="submit"
              disabled={savingNotifications}
              className="rounded-lg border border-zinc-700 px-5 py-2 text-sm font-medium text-zinc-200 hover:border-zinc-500 disabled:opacity-50"
            >
              {savingNotifications ? "Saving…" : "Save notifications"}
            </button>
          </form>
        </div>
      </main>
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <div>
      <label className="mb-1 block text-sm text-zinc-400">{label}</label>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-4 py-2 text-zinc-50 outline-none focus:border-emerald-500"
      />
    </div>
  );
}
