import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Checkbox, Input, InputNumber, Select, Space, Typography } from 'antd';
import { multiTargetApi, type ManagedView, type McpRevision, type MultiProfile } from '@/api/redteamMultiTarget';
import { useAuthStore } from '@/stores/authStore';
interface Draft { enabled: boolean; revision: McpRevision; private: boolean; addresses: string; port: number; plainHttp: boolean }
const empty: Draft = { enabled: true, revision: '2026-07-28', private: false, addresses: '', port: 443, plainHttp: false };
const scope = () => { const state = useAuthStore.getState(); return state.tenant?.id + ':' + state.tenant?.slug + ':' + state.sessionGeneration; };
export function ManagedTransport({ agents, mcps, zh }: { agents: MultiProfile[]; mcps: MultiProfile[]; zh: boolean }) {
  const [selection, setSelection] = useState(''); const [baseline, setBaseline] = useState<ManagedView | null>(null);
  const [latest, setLatest] = useState<ManagedView | null>(null); const [draft, setDraft] = useState(empty);
  const [confirmed, setConfirmed] = useState(false); const [busy, setBusy] = useState(false); const [error, setError] = useState('');
  const life = useRef({ live: true, rank: 0, active: false, controllers: new Set<AbortController>() });
  useEffect(() => {
    const state = life.current; state.live = true;
    const unsubscribe = useAuthStore.subscribe((next, previous) => {
      if (next.tenant?.id !== previous.tenant?.id || next.tenant?.slug !== previous.tenant?.slug || next.sessionGeneration !== previous.sessionGeneration) {
        state.rank++; for (const controller of state.controllers) controller.abort();
        setBaseline(null); setLatest(null); setSelection(''); setConfirmed(false); setDraft(empty);
      }
    });
    return () => { state.live = false; unsubscribe(); for (const controller of state.controllers) controller.abort(); };
  }, []);
  const text = (en: string, cn: string) => zh ? cn : en;
  const choices = [...agents.map(row => ({ row, kind: 'agent-http' as const })), ...mcps.map(row => ({ row, kind: 'mcp-http' as const }))];
  const selected = choices.find(value => value.kind + ':' + value.row.id === selection);
  async function run(operation: (signal: AbortSignal, current: () => boolean) => Promise<void>) {
    const state = life.current; if (state.active) return; state.active = true; setBusy(true); setError('');
    const initialScope = scope(); const rank = ++state.rank; const controller = new AbortController(); state.controllers.add(controller);
    const current = () => state.live && !controller.signal.aborted && rank === state.rank && scope() === initialScope;
    try { await operation(controller.signal, current); } catch { if (current()) setError(text('Rejected or unresolved. Draft and reviewed CAS version retained; compare before another manual save.', '被拒绝或未确认，草稿与已核对 CAS 版本保留；再次手动保存前请比较。')); }
    finally { state.active = false; state.controllers.delete(controller); if (current()) setBusy(false); }
  }
  function adopt(result: ManagedView) {
    setBaseline(result); setLatest(null); setConfirmed(false);
    const settings = result.settings;
    setDraft({ enabled: settings?.enabled ?? true, revision: settings?.mcpProtocolRevision ?? '2026-07-28',
      private: !!settings?.privateNetwork, addresses: settings?.privateNetwork?.addresses.join('\n') ?? '',
      port: settings?.privateNetwork?.port ?? Number(new URL(result.url).port || (result.url.startsWith('http:') ? 80 : 443)),
      plainHttp: settings?.privateNetwork?.allowPlainHttp ?? false });
  }
  const load = (compare: boolean) => run(async (signal, current) => {
    if (!selected) return; const { kind, row } = selected;
    const result = await multiTargetApi.managed(kind, row.id, signal);
    if (result.profileId !== row.id || !Number.isSafeInteger(result.version) || result.version < 0) throw new Error('Profile identity mismatch');
    if (current()) { if (compare) setLatest(result); else adopt(result); }
  });
  const save = () => run(async (signal, current) => {
    if (!selected || !baseline || !confirmed || baseline.profileId !== selected.row.id) return;
    const { kind, row } = selected; const reviewed = { ...baseline }; const candidate = { ...draft };
    const addresses = candidate.addresses.split(/[\n,]/).map(value => value.trim()).filter(Boolean);
    if (candidate.private && (addresses.length < 1 || addresses.length > 8 || new Set(addresses).size !== addresses.length || !Number.isSafeInteger(candidate.port) || candidate.port < 1 || candidate.port > 65535)) throw new Error('Review exact network');
    const result = await multiTargetApi.saveManaged(kind, row.id, { expected_version: reviewed.version,
      profile_version: reviewed.profileVersion, url: reviewed.url, enabled: candidate.enabled,
      mcp_protocol_revision: kind === 'agent-http' ? '2026-07-28' : candidate.revision,
      private_network: candidate.private ? { addresses, port: candidate.port, allow_plain_http: candidate.plainHttp, confirm_exact_private_network: true } : null }, signal);
    if (result.profileId !== row.id || result.version !== reviewed.version + 1) throw new Error('Profile identity mismatch');
    if (current()) { setBaseline({ ...reviewed, configured: true, version: result.version, settings: result }); setConfirmed(false); setLatest(null); }
  });
  const update = (value: Partial<Draft>) => { setDraft(previous => ({ ...previous, ...value })); setConfirmed(false); };
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Alert type="info" message={text('Administrator managed transport approval', '管理员托管传输批准')}
      description={text('No private access by default. Bind exact current profile/version/URL and every DNS address plus port. Private HTTP needs separate explicit consent. No credentials are entered here; changing the registered profile invalidates this approval.', '默认不允许私网。批准绑定准确当前配置、版本、URL、全部 DNS 地址和端口；私网 HTTP 另需明确同意。此处不输入凭据，已登记配置变版即使批准失效。')} />
    <Select aria-label="Managed target profile" value={selection || undefined} disabled={busy} style={{ width: '100%' }}
      placeholder={text('Select exact registered profile', '选择准确登记配置')} options={choices.map(({ row, kind }) => ({ value: kind + ':' + row.id, label: row.name + ' · v' + row.version + ' · ' + row.id, disabled: !row.enabled }))}
      onChange={value => { life.current.rank++; setSelection(value); setBaseline(null); setLatest(null); setDraft(empty); setConfirmed(false); }} />
    <Button disabled={!selected || busy} onClick={() => void load(false)}>{text('Read current transport settings', '读取当前传输设置')}</Button>
    {baseline && <><Typography.Paragraph code>{baseline.profileId} · profile v{baseline.profileVersion} · CAS v{baseline.version} · {baseline.url}</Typography.Paragraph>
      <Checkbox checked={draft.enabled} disabled={busy} onChange={event => update({ enabled: event.target.checked })}>{text('Enable this exact approval', '启用此准确批准')}</Checkbox>
      {selected?.kind === 'mcp-http' && <Select aria-label="MCP protocol revision" disabled={busy} value={draft.revision} onChange={revision => update({ revision })} options={['2026-07-28', '2025-11-25'].map(value => ({ value, label: value }))} />}
      <Checkbox checked={draft.private} disabled={busy} onChange={event => update({ private: event.target.checked })}>{text('Explicitly approve private network', '明确批准私有网络')}</Checkbox>
      {draft.private && <><Input.TextArea aria-label="Exact private addresses" value={draft.addresses} disabled={busy} placeholder="RFC1918 / ULA" onChange={event => update({ addresses: event.target.value })} />
        <InputNumber aria-label="Exact private port" min={1} max={65535} value={draft.port} disabled={busy} onChange={port => update({ port: port ?? 0 })} />
        <Checkbox checked={draft.plainHttp} disabled={busy} onChange={event => update({ plainHttp: event.target.checked })}>{text('I explicitly permit plain HTTP on this approved private address/port', '我明确允许此已批准私网地址与端口上的明文 HTTP')}</Checkbox></>}
      <Checkbox checked={confirmed} disabled={busy} onChange={event => setConfirmed(event.target.checked)}>{text('I reviewed this exact URL/version, protocol and network', '我已核对此准确 URL、版本、协议及网络')}</Checkbox>
      <Space><Button disabled={busy || !confirmed} onClick={() => void save()}>{text('Save reviewed approval', '保存已核对批准')}</Button>
        <Button disabled={busy} onClick={() => void load(true)}>{text('Compare latest settings', '比较最新设置')}</Button></Space>
      {latest && <><Typography.Paragraph code>{JSON.stringify(latest, null, 2)}</Typography.Paragraph>
        <Button disabled={busy} onClick={() => adopt(latest)}>{text('Explicitly adopt latest settings', '明确采用最新设置')}</Button></>}</>}
    {error && <Alert type="warning" message={error} />}
  </Space>;
}
