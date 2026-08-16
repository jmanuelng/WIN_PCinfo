import { mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AgentProvider } from "@ai-hero/sandcastle";

export const GROK_MODEL = "grok-4.6";
export const GROK_REASONING_EFFORT = "xhigh";

export interface GrokStreamEvent {
  readonly type: string;
  readonly data?: unknown;
  readonly toolName?: unknown;
  readonly rawInput?: unknown;
  readonly sessionId?: unknown;
  readonly usage?: unknown;
  readonly message?: unknown;
}

function quoteWindowsArg(value: string): string {
  if (!/[ \t"]/.test(value)) {
    return value;
  }

  return `"${value.replace(/"/g, '\\"')}"`;
}

function writePromptFile(prompt: string): string {
  const directory = join(tmpdir(), "sandcastle-grok-prompts");
  mkdirSync(directory, { recursive: true });
  const promptPath = join(
    directory,
    `prompt-${Date.now()}-${Math.random().toString(16).slice(2)}.md`,
  );
  writeFileSync(promptPath, prompt, "utf8");
  return promptPath;
}

function usageFromUnknown(value: unknown): {
  readonly inputTokens: number;
  readonly cacheCreationInputTokens: number;
  readonly cacheReadInputTokens: number;
  readonly outputTokens: number;
} | undefined {
  if (!value || typeof value !== "object") {
    return undefined;
  }

  const usage = value as Record<string, unknown>;
  const inputTokens = usage.input_tokens;
  const outputTokens = usage.output_tokens;
  if (typeof inputTokens !== "number" || typeof outputTokens !== "number") {
    return undefined;
  }

  return {
    inputTokens,
    cacheCreationInputTokens:
      typeof usage.cache_creation_input_tokens === "number"
        ? usage.cache_creation_input_tokens
        : 0,
    cacheReadInputTokens:
      typeof usage.cache_read_input_tokens === "number"
        ? usage.cache_read_input_tokens
        : 0,
    outputTokens,
  };
}

export function parseGrokStreamLine(line: string): ReturnType<
  AgentProvider["parseStreamLine"]
> {
  const trimmed = line.trim();
  if (!trimmed.startsWith("{")) {
    return [];
  }

  let event: GrokStreamEvent;
  try {
    event = JSON.parse(trimmed) as GrokStreamEvent;
  } catch {
    return [];
  }

  if (event.type === "text" && typeof event.data === "string") {
    return [
      { type: "text", text: event.data },
      { type: "result", result: event.data },
    ];
  }

  if (event.type === "tool_call" && typeof event.toolName === "string") {
    const args =
      event.rawInput === undefined
        ? ""
        : typeof event.rawInput === "string"
          ? event.rawInput
          : JSON.stringify(event.rawInput);
    return [{ type: "tool_call", name: event.toolName, args }];
  }

  if (event.type === "end") {
    const events: ReturnType<AgentProvider["parseStreamLine"]> = [];
    if (typeof event.sessionId === "string") {
      events.push({ type: "session_id", sessionId: event.sessionId });
    }
    const usage = usageFromUnknown(event.usage);
    if (usage) {
      events.push({ type: "usage", usage });
    }
    return events;
  }

  if (event.type === "error") {
    const message =
      typeof event.message === "string"
        ? event.message
        : event.data && typeof event.data === "string"
          ? event.data
          : undefined;
    return message ? [{ type: "result", result: message }] : [];
  }

  return [];
}

export function buildGrokPrintCommand(prompt: string): {
  readonly command: string;
  readonly promptPath: string;
} {
  const promptPath = writePromptFile(prompt);
  const command = [
    "grok",
    "--prompt-file",
    quoteWindowsArg(promptPath),
    "--output-format",
    "streaming-json",
    "--always-approve",
    "--no-plan",
    "--verbatim",
    "--reasoning-effort",
    GROK_REASONING_EFFORT,
    "-m",
    GROK_MODEL,
  ].join(" ");

  return { command, promptPath };
}

export function createGrokAgent(): AgentProvider {
  return {
    name: "grok",
    env: {},
    captureSessions: false,
    buildPrintCommand(options) {
      return {
        command: buildGrokPrintCommand(options.prompt).command,
      };
    },
    parseStreamLine: parseGrokStreamLine,
  };
}
