const STATES: Record<string, [string, string]> = {
  requested: ['申请中', 'Requested'], 'under-review': ['评审中', 'Under review'], trial: ['试用', 'Trial'],
  production: ['生产', 'Production'], changing: ['变更中', 'Changing'], archived: ['归档', 'Archived'],
  rejected: ['拒绝', 'Rejected'],
};
export function skillLifecycleLabel(value: string, zh: boolean) { return STATES[value]?.[zh ? 0 : 1] ?? value; }
