"use client";

import { Suspense } from "react";
import { useSearchParams } from "next/navigation";

const ERROR_COPY: Record<string, string> = {
  invalid_credentials: "Invalid username or password.",
  too_many_attempts: "Too many attempts. Wait and try again.",
  login_required: "Sign in to access the dashboard.",
};

function sanitizeNextPath(pathname: string | null): string {
  const raw = String(pathname ?? "").trim();
  if (!raw.startsWith("/") || raw.startsWith("//")) {
    return "/";
  }
  return raw;
}

function LoginForm() {
  const searchParams = useSearchParams();
  const nextPath = sanitizeNextPath(searchParams.get("next"));
  const errorCode = searchParams.get("error") ?? "";
  const errorMessage = ERROR_COPY[errorCode] ?? "";

  return (
    <main className="min-h-screen bg-[radial-gradient(circle_at_top,_rgba(34,197,94,0.16),_transparent_38%),linear-gradient(180deg,#09090b_0%,#111113_100%)] px-6 py-24 text-zinc-100">
      <div className="mx-auto max-w-md rounded-[28px] border border-zinc-800 bg-black/55 p-8 shadow-[0_24px_80px_rgba(0,0,0,0.45)] backdrop-blur">
        <p className="text-xs uppercase tracking-[0.32em] text-emerald-400">Aletheia</p>
        <h1 className="mt-3 text-3xl font-semibold tracking-tight">Operator Login</h1>
        <p className="mt-3 text-sm leading-6 text-zinc-400">
          Authenticate to access hosted run artifacts, launch repo scans, and use the sovereign command center.
        </p>
        {errorMessage ? (
          <div className="mt-5 rounded-2xl border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-200">
            {errorMessage}
          </div>
        ) : null}
        <form action="/api/auth/login" method="post" className="mt-6 grid gap-4">
          <input type="hidden" name="next" value={nextPath} />
          <label className="grid gap-2 text-sm text-zinc-300">
            Username
            <input
              name="username"
              autoComplete="username"
              required
              className="rounded-2xl border border-zinc-700 bg-zinc-950 px-4 py-3 text-sm text-zinc-100 outline-none transition focus:border-emerald-400"
            />
          </label>
          <label className="grid gap-2 text-sm text-zinc-300">
            Password
            <input
              type="password"
              name="password"
              autoComplete="current-password"
              required
              className="rounded-2xl border border-zinc-700 bg-zinc-950 px-4 py-3 text-sm text-zinc-100 outline-none transition focus:border-emerald-400"
            />
          </label>
          <button
            type="submit"
            className="mt-2 rounded-full bg-emerald-500 px-5 py-3 text-sm font-semibold text-black transition hover:bg-emerald-400"
          >
            Sign in
          </button>
        </form>
        <form action="/api/auth/logout" method="post" className="mt-6 text-xs text-zinc-500">
          <button type="submit" className="underline decoration-zinc-700 underline-offset-4 hover:text-zinc-300">
            Clear stale session
          </button>
        </form>
      </div>
    </main>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={<main className="min-h-screen bg-black text-zinc-100 px-6 py-24">Loading login...</main>}>
      <LoginForm />
    </Suspense>
  );
}
