import type { SourceChoice, StartupFields } from '@/types/onboarding';

export const emptyStartup = (): StartupFields => ({ source_id: '', binding_id: '', worker: '', team: null, kind: 'task',
  callee_worker: null, callee_team: null, operation: '', module: '', callable: '', entry: '', sdk_directory: '',
  spool_directory: '', configuration_file: '', target_file: null, async_mode: null });
export function missingRequiredTeam(sources: SourceChoice[], value: StartupFields): boolean {
  const source = sources.find(row => row.sourceId === value.source_id);
  const multiple = (worker: string | null, team: string | null) => !team && (source?.workers.find(row => row.name === worker)?.teams.length ?? 0) > 1;
  return multiple(value.worker, value.team) || (value.kind === 'call' && multiple(value.callee_worker, value.callee_team));
}
