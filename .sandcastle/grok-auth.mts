import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export interface GrokAccessSnapshot {
  readonly found: boolean;
  readonly expiresAt: Date | undefined;
  readonly remainingMs: number | undefined;
  readonly hasRefreshToken: boolean;
}

export function grokAuthFilePath(): string {
  const home = process.env.GROK_HOME || join(homedir(), ".grok");
  return join(home, "auth.json");
}

function jwtExpMs(token: string): number | undefined {
  const parts = token.split(".");
  if (parts.length < 2) {
    return undefined;
  }
  try {
    const padded = parts[1] + "=".repeat((4 - (parts[1].length % 4)) % 4);
    const json = Buffer.from(
      padded.replace(/-/g, "+").replace(/_/g, "/"),
      "base64",
    ).toString("utf8");
    const payload = JSON.parse(json) as { readonly exp?: unknown };
    if (typeof payload.exp === "number" && Number.isFinite(payload.exp)) {
      return payload.exp * 1000;
    }
  } catch {
    return undefined;
  }
  return undefined;
}

function visitAccount(value: unknown): {
  readonly expiresAt: Date | undefined;
  readonly hasRefreshToken: boolean;
} {
  if (!value || typeof value !== "object") {
    return { expiresAt: undefined, hasRefreshToken: false };
  }
  const record = value as Record<string, unknown>;
  const hasRefreshToken =
    typeof record.refresh_token === "string" && record.refresh_token.length > 0;
  let expiresAt: Date | undefined;
  if (typeof record.expires_at === "string") {
    const parsed = new Date(record.expires_at);
    if (!Number.isNaN(parsed.getTime())) {
      expiresAt = parsed;
    }
  }
  if (!expiresAt && typeof record.key === "string") {
    const expMs = jwtExpMs(record.key);
    if (expMs !== undefined) {
      expiresAt = new Date(expMs);
    }
  }
  return { expiresAt, hasRefreshToken };
}

export function parseGrokAuthFile(
  contents: string,
  now = new Date(),
): GrokAccessSnapshot {
  const trimmed = contents.trim();
  if (!trimmed) {
    return {
      found: false,
      expiresAt: undefined,
      remainingMs: undefined,
      hasRefreshToken: false,
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return {
      found: false,
      expiresAt: undefined,
      remainingMs: undefined,
      hasRefreshToken: false,
    };
  }
  if (!parsed || typeof parsed !== "object") {
    return {
      found: false,
      expiresAt: undefined,
      remainingMs: undefined,
      hasRefreshToken: false,
    };
  }

  const root = parsed as Record<string, unknown>;
  const accounts: {
    readonly expiresAt: Date | undefined;
    readonly hasRefreshToken: boolean;
  }[] = [];
  if ("expires_at" in root || "refresh_token" in root || "key" in root) {
    accounts.push(visitAccount(root));
  }
  for (const value of Object.values(root)) {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const nested = value as Record<string, unknown>;
      if ("expires_at" in nested || "refresh_token" in nested || "key" in nested) {
        accounts.push(visitAccount(nested));
      }
    }
  }
  if (accounts.length === 0) {
    return {
      found: true,
      expiresAt: undefined,
      remainingMs: undefined,
      hasRefreshToken: false,
    };
  }

  const chosen = accounts.reduce((best, current) => {
    if (!best.expiresAt) {
      return current;
    }
    if (!current.expiresAt) {
      return best;
    }
    return current.expiresAt > best.expiresAt ? current : best;
  });
  const expiresAt = chosen.expiresAt;
  return {
    found: true,
    expiresAt,
    remainingMs: expiresAt ? expiresAt.getTime() - now.getTime() : undefined,
    hasRefreshToken: accounts.some((account) => account.hasRefreshToken),
  };
}

export function readGrokAccessSnapshot(now = new Date()): GrokAccessSnapshot {
  const filePath = grokAuthFilePath();
  if (!existsSync(filePath)) {
    return parseGrokAuthFile("", now);
  }
  return parseGrokAuthFile(readFileSync(filePath, "utf8"), now);
}

export function formatDurationMs(milliseconds: number): string {
  if (milliseconds <= 0) {
    return "expired";
  }
  const totalMinutes = Math.floor(milliseconds / 60_000);
  if (totalMinutes < 1) {
    return "<1m";
  }
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  if (hours === 0) {
    return `${minutes}m`;
  }
  if (minutes === 0) {
    return `${hours}h`;
  }
  return `${hours}h ${minutes}m`;
}

export function describeGrokAccessTtl(snapshot: GrokAccessSnapshot): string {
  if (!snapshot.found) {
    return "Grok access token: no local auth.json snapshot. Silent grok models refresh will still be attempted.";
  }
  const refreshNote = snapshot.hasRefreshToken
    ? "Silent grok models refresh uses the stored refresh_token to pass the ~6h access TTL."
    : "No refresh_token is present; run grok login before the access token expires.";
  if (snapshot.remainingMs === undefined || snapshot.expiresAt === undefined) {
    return `Grok access token: expiry unknown. ${refreshNote}`;
  }
  if (snapshot.remainingMs <= 0) {
    return `Grok access token: expired at ${snapshot.expiresAt.toISOString()}. ${refreshNote}`;
  }
  return `Grok access token: ${formatDurationMs(snapshot.remainingMs)} remaining (expires ${snapshot.expiresAt.toISOString()}). ${refreshNote}`;
}

export function grokLoginReminder(snapshot: GrokAccessSnapshot): string {
  return [
    describeGrokAccessTtl(snapshot),
    "Grok authentication is exhausted. Run grok login in this terminal, then re-run Sandcastle.",
    "Worktrees with local work are preserved. No new batches will start.",
  ].join("\n");
}
