import { spawn } from "node:child_process";
import {
  GROK_AUTH_RETRY_ATTEMPTS,
  GROK_AUTH_RETRY_DELAYS_MS,
  isTransientGrokAuthFailure,
} from "./grok-agent.mts";

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}

function spawnGrok(args: readonly string[]): Promise<{
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
      process.stdout.write(text);
    });
    child.stderr?.on("data", (chunk: Buffer | string) => {
      const text = typeof chunk === "string" ? chunk : chunk.toString("utf8");
      output += text;
      process.stderr.write(text);
    });
    child.once("error", reject);
    child.once("close", (code) => {
      resolve({ exitCode: code ?? 1, output });
    });
  });
}

export async function runGrokPhaseWithAuthRetry(
  args: readonly string[],
  delaysMs: readonly number[] = GROK_AUTH_RETRY_DELAYS_MS,
): Promise<number> {
  let lastExit = 1;
  for (let attempt = 1; attempt <= GROK_AUTH_RETRY_ATTEMPTS; attempt += 1) {
    const result = await spawnGrok(args);
    lastExit = result.exitCode;
    if (result.exitCode === 0) {
      return 0;
    }
    const retryable =
      attempt < GROK_AUTH_RETRY_ATTEMPTS &&
      isTransientGrokAuthFailure(result.output);
    if (!retryable) {
      return result.exitCode;
    }
    const delay = delaysMs[attempt - 1] ?? delaysMs[delaysMs.length - 1] ?? 5000;
    process.stderr.write(
      `Grok authentication failed transiently (attempt ${attempt}/${GROK_AUTH_RETRY_ATTEMPTS}); retrying in ${delay}ms.\n`,
    );
    await sleep(delay);
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
