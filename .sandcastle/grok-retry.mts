import { spawn } from "node:child_process";
import {
  GROK_AUTH_RETRY_ATTEMPTS,
  GROK_AUTH_RETRY_DELAYS_MS,
  planGrokAuthRetry,
} from "./grok-agent.mts";

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}

function spawnGrok(
  args: readonly string[],
  options: { readonly forward: boolean },
): Promise<{
  readonly exitCode: number;
  readonly output: string;
}> {
  return new Promise((resolve, reject) => {
    const useWindowsCmd = process.platform === "win32";
    const child = spawn(
      useWindowsCmd ? process.env.ComSpec || "cmd.exe" : "grok",
      useWindowsCmd ? ["/d", "/s", "/c", "grok", ...args] : [...args],
      {
        stdio: ["inherit", "pipe", "pipe"],
        windowsHide: true,
      },
    );

    let output = "";
    child.stdout?.on("data", (chunk: Buffer | string) => {
      const text = typeof chunk === "string" ? chunk : chunk.toString("utf8");
      output += text;
      if (options.forward) {
        process.stdout.write(text);
      }
    });
    child.stderr?.on("data", (chunk: Buffer | string) => {
      const text = typeof chunk === "string" ? chunk : chunk.toString("utf8");
      output += text;
      if (options.forward) {
        process.stderr.write(text);
      }
    });
    child.once("error", reject);
    child.once("close", (code) => {
      resolve({ exitCode: code ?? 1, output });
    });
  });
}

async function refreshGrokSession(): Promise<void> {
  try {
    const result = await spawnGrok(["models"], { forward: false });
    const loggedIn = /logged in/i.test(result.output);
    process.stderr.write(
      loggedIn
        ? "Silent Grok session refresh succeeded (grok models).\n"
        : `Silent Grok session refresh failed (exit ${result.exitCode}).\n`,
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`Silent Grok session refresh failed: ${message}\n`);
  }
}

export async function runGrokPhaseWithAuthRetry(
  args: readonly string[],
  delaysMs: readonly number[] = GROK_AUTH_RETRY_DELAYS_MS,
): Promise<number> {
  let lastExit = 1;
  for (let attempt = 1; attempt <= GROK_AUTH_RETRY_ATTEMPTS; attempt += 1) {
    await refreshGrokSession();
    const result = await spawnGrok(args, { forward: true });
    lastExit = result.exitCode;
    const plan = planGrokAuthRetry({
      attempt,
      maxAttempts: GROK_AUTH_RETRY_ATTEMPTS,
      delaysMs,
      exitCode: result.exitCode,
      output: result.output,
    });
    if (plan.adapterWarning) {
      process.stderr.write(`${plan.adapterWarning}\n`);
    }
    if (plan.action === "return") {
      return plan.exitCode;
    }
    process.stderr.write(
      `Grok authentication failed transiently (attempt ${attempt}/${GROK_AUTH_RETRY_ATTEMPTS}); refreshing session and retrying in ${plan.delayMs}ms.\n`,
    );
    await sleep(plan.delayMs ?? 5_000);
  }
  return lastExit;
}

const invokedDirectly = /grok-retry\.mts$/.test(process.argv[1] ?? "");

if (invokedDirectly) {
  const args = process.argv.slice(2);
  runGrokPhaseWithAuthRetry(args)
    .then((exitCode) => {
      process.exitCode = exitCode;
    })
    .catch((error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`Unable to run Grok: ${message}`);
      process.exitCode = 1;
    });
}
