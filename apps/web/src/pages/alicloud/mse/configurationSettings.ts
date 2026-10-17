export type MseNamespaceSelection = 'default' | 'specific';
export function initialNamespace(settings: Record<string, unknown>): MseNamespaceSelection | undefined {
  if (typeof settings.namespace_id !== 'string') return undefined;
  return settings.namespace_id === '' ? 'default' : 'specific';
}
export function configurationSettings(name: string, original: Record<string, unknown>, values: Record<string, unknown>,
  namespace?: MseNamespaceSelection): Record<string, unknown> {
  const merged = { ...original, ...values };
  const settings = Object.fromEntries(Object.entries(merged).filter(([, value]) => value !== '' && value !== null && value !== undefined));
  if (name !== 'alicloud-mse') return settings;
  if (typeof merged.instance_id !== 'string' || !merged.instance_id.trim()) {
    throw new Error('MSE instance ID is required / 请填写 MSE 实例 ID');
  }
  settings.instance_id = merged.instance_id.trim();
  if (namespace === 'default') settings.namespace_id = '';
  else if (namespace === 'specific' && typeof merged.namespace_id === 'string' && merged.namespace_id.trim()) {
    settings.namespace_id = merged.namespace_id.trim();
  } else throw new Error('Select the default namespace or enter a specific namespace ID / 请明确选择默认命名空间或填写指定命名空间 ID');
  return settings;
}
