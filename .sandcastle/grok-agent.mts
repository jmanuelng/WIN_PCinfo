import { mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AgentProvider } from "@ai-hero/sandcastle";

export const GROK_MODEL = "grok-4.6";
export const GROK_REASONING_EFFORT = "xhigh";

export interface GrokStreamEvent {
  readonly type?: string;
  readonly data?: unknown;
  readonly text?: unknown;
  readonly result?: unknown;
  readonly content?: unknown;
  readonly toolName?: unknown;
  readonly rawInput?: unknown;
  readonly sessionId?: unknown;
  readonly session_id?: unknown;
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

function textEvents(text: string): ReturnType<AgentProvider["parseStreamLine"]> {
  return [
    { type: "text", text },
    { type: "result", result: text },
  ];
}

function firstString(
  ...candidates: readonly unknown[]
): string | undefined {
  for (const candidate of candidates) {
    if (typeof candidate === "string" && candidate.length > 0) {
      return candidate;
    }
  }
  return undefined;
}

function textFromAssistantMessage(message: unknown): string | undefined {
  if (!message || typeof message !== "object") {
    return undefined;
  }

  const content = (message as { readonly content?: unknown }).content;
  if (typeof content === "string") {
    return content;
  }
  if (!Array.isArray(content)) {
    return undefined;
  }

  const parts = content
    .map((block) => {
      if (!block || typeof block !== "object") {
        return "";
      }
      const item = block as { readonly type?: unknown; readonly text?: unknown };
      return item.type === "text" && typeof item.text === "string"
        ? item.text
        : "";
    })
    .join("");
  return parts.length > 0 ? parts : undefined;
}

export function parseGrokStreamLine(line: string): ReturnType<
  AgentProvider["parseStreamLine"]
> {
  const trimmed = line.trim();
  if (!trimmed) {
    return [];
  }

  // Grok often prints the completion marker as a plain stdout line. The
  // previous adapter ignored non-JSON, so Sandcastle logged COMPLETE and
  // still reported no completion signal.
  if (!trimmed.startsWith("{")) {
    return textEvents(trimmed);
  }

  let event: GrokStreamEvent;
  try {
    event = JSON.parse(trimmed) as GrokStreamEvent;
  } catch {
    return textEvents(trimmed);
  }

  const jsonText = firstString(
    event.type === "text" ? event.data : undefined,
    event.type === "text" ? event.text : undefined,
    event.type === "text" ? event.content : undefined,
    event.type === "result" ? event.result : undefined,
    event.type === "result" ? event.text : undefined,
    event.type === undefined ? event.text : undefined,
  );
  if (jsonText !== undefined) {
    return textEvents(jsonText);
  }

  if (event.type === "assistant") {
    const assistantText = textFromAssistantMessage(event.message);
    if (assistantText) {
      return textEvents(assistantText);
    }
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
    const sessionId = firstString(event.sessionId, event.session_id);
    if (sessionId) {
      events.push({ type: "session_id", sessionId });
    }
    const usage = usageFromUnknown(event.usage);
    if (usage) {
      events.push({ type: "usage", usage });
    }
    const endText = firstString(event.text, event.result);
    if (endText) {
      events.push(...textEvents(endText));
    }
    return events;
  }

  if (event.type === "error") {
    const message = firstString(event.message, event.data, event.text);
    return message ? textEvents(message) : [];
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
    "--no-leader",
    "--no-alt-screen",
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
