/** Merge only the wrapper command and argument vector. Existing project settings/environment stay operator-owned. */
export function mergeStdio(template: string, originalCommand: string, argumentsJson: string): string {
  if (!originalCommand || originalCommand.length > 2048 || hasControl(originalCommand) || argumentsJson.length > 16_384) {
    throw new Error('Enter the original command and a bounded JSON argument array');
  }
  let args: unknown;
  try { args = JSON.parse(argumentsJson); } catch { throw new Error('Original arguments must be a JSON string array'); }
  if (!Array.isArray(args) || args.length > 100 || !args.every(arg => typeof arg === 'string' && arg.length <= 2048 && !hasControl(arg))) {
    throw new Error('Original arguments must be a bounded JSON string array');
  }
  const value = JSON.parse(template) as { mcpServers: { guarded: { command: string; args: string[] } } };
  const old = value.mcpServers.guarded.args;
  if (old.at(-2) !== '<ORIGINAL_COMMAND>' || old.at(-1) !== '<ORIGINAL_ARGS>') throw new Error('Unsupported stdio template');
  value.mcpServers.guarded.args = [...old.slice(0, -2), originalCommand, ...args];
  return JSON.stringify(value, null, 2);
}

function hasControl(value: string): boolean {
  return [...value].some(character => character.charCodeAt(0) < 32);
}
