import * as sandcastle from "@ai-hero/sandcastle";

const UPSTREAM_BYPASS_FLAG = "--dangerously-bypass-approvals-and-sandbox";
const EXPECTED_UPSTREAM_COMMAND =
  `codex exec --json ${UPSTREAM_BYPASS_FLAG} -m 'gpt-5.4' ` +
  `-c 'model_reasoning_effort="high"'`;
const WINDOWS_SAFE_COMMAND =
  "codex exec --json --approve-for-me -m gpt-5.4 " +
  "-c model_reasoning_effort=high";

export function createCodexAgent() {
  const upstream = sandcastle.codex("gpt-5.4", {
    effort: "high",
  });

  return {
    ...upstream,
    buildPrintCommand(
      options: Parameters<typeof upstream.buildPrintCommand>[0],
    ) {
      const printCommand = upstream.buildPrintCommand(options);
      if (printCommand.command !== EXPECTED_UPSTREAM_COMMAND) {
        throw new Error(
          "Sandcastle generated an unexpected Codex command shape; refusing to adapt it.",
        );
      }

      return {
        ...printCommand,
        command: WINDOWS_SAFE_COMMAND,
      };
    },
  };
}
