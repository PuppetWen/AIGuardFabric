import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Drawer, Input, InputNumber, Popconfirm, Space, Switch, Table, Typography, message } from 'antd';
import { useTranslation } from 'react-i18next';
import { ApiRequestError, useApiQuery } from '@/api/client';
import { parsersApi, type ParserInput, type ParserPreview, type ParseOutcome } from '@/api/parsers';
import { DataState } from '@/components/DataState';
import { useAuthStore } from '@/stores/authStore';
import type { Parser } from '@/types/domain';
import { ParserInference } from './ParserInference';
import { ParserVersionComparison } from './ParserVersionComparison';

const starter = {
  key: 'my-json-parser', name: 'Custom JSON log', engine: 'json-path', pattern: '$',
  protocols: ['webhook', 'http-pull'], required_fields: ['message'],
  mapping: { map: { message: 'message', src_ip: 'source.ip' } },
};
interface Props { parser?: Parser; onClose: () => void; onSaved: () => void }
export function ParserEditor(props: Props) {
  const tenant = useAuthStore(state => state.tenant?.id);
  const generation = useAuthStore(state => state.sessionGeneration);
  return <ScopedEditor key={`${tenant ?? 'none'}:${generation}:${props.parser?.id ?? 'new'}`} {...props} />;
}

function ScopedEditor({ parser, onClose, onSaved }: Props) {
  const { t } = useTranslation();
  const [snapshot, setSnapshot] = useState<ParserPreview>();
  const [error, setError] = useState<unknown>();
  const id = parser?.id;
  useEffect(() => {
    if (!id) return;
    let active = true;
    void parsersApi.preview(id).then(result => { if (active) setSnapshot(result.data); })
      .catch(reason => { if (active) setError(reason); });
    return () => { active = false; };
  }, [id]);
  return <Drawer title={t(parser ? 'parserEditor.manage' : 'parserEditor.create')} width={1000} open onClose={onClose} destroyOnClose>
    <DataState loading={!!parser && !snapshot && !error} error={error}>
      {(!parser || snapshot) && <Editor id={id} preview={snapshot} onSaved={onSaved} onClose={onClose} />}
    </DataState>
  </Drawer>;
}

function Editor({ id, preview, onSaved, onClose }: {
  id?: string; preview?: ParserPreview; onSaved: () => void; onClose: () => void;
}) {
  const { t } = useTranslation();
  const [base, setBase] = useState(preview);
  const editable = !!id && !!base?.editable;
  const [definition, setDefinition] = useState(() => {
    const value = preview ? JSON.parse(preview.definitionJson) : starter;
    // Copy a system template under a new key; shipped definitions stay unchanged.
    if (preview && !preview.editable) { value.key += '-custom'; value.builtin = false; }
    return JSON.stringify(value, null, 2);
  });
  const [sample, setSample] = useState(preview?.sampleRaw ?? '{"message":"Login failed","src_ip":"192.0.2.10"}');
  const [enabled, setEnabled] = useState(preview?.enabled ?? true);
  const [priority, setPriority] = useState(preview?.priority ?? 50);
  const [error, setError] = useState('');
  const [conflict, setConflict] = useState(false);
  const [outcome, setOutcome] = useState<ParseOutcome>();
  const [latest, setLatest] = useState<ParserPreview>();
  const [busy, setBusy] = useState(false);
  const running = useRef(false);
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const history = useApiQuery('parser-history', () => parsersApi.history(id!), { key: [id, base?.version], enabled: editable });
  const body = (): ParserInput => ({
    definition: JSON.parse(definition) as Record<string, unknown>, sample, enabled, priority,
    expected_version: editable ? base?.version : undefined,
  });
  const run = async (operation: (isCurrent: () => boolean) => Promise<void>) => {
    if (running.current) return;
    running.current = true; setError(''); setConflict(false); setBusy(true);
    const starting = useAuthStore.getState();
    const isCurrent = () => alive.current && useAuthStore.getState().tenant?.id === starting.tenant?.id
      && useAuthStore.getState().tenant?.slug === starting.tenant?.slug
      && useAuthStore.getState().sessionGeneration === starting.sessionGeneration;
    try { await operation(isCurrent); }
    catch (reason) {
      if (isCurrent()) {
        setError(reason instanceof Error ? reason.message : String(reason));
        setConflict(reason instanceof ApiRequestError && reason.status === 409);
      }
    } finally { if (isCurrent()) { running.current = false; setBusy(false); } }
  };
  const saved = () => { message.success(t('parserEditor.saved')); onSaved(); onClose(); };
  const adopt = () => {
    if (!latest?.editable || running.current) return;
    // Only this explicit confirmation changes the editing baseline, never the comparison GET.
    setBase(latest); setDefinition(latest.definitionJson); setSample(latest.sampleRaw ?? '');
    setPriority(latest.priority); setEnabled(latest.enabled); setOutcome(undefined);
    setLatest(undefined); setError(''); setConflict(false);
  };
  return <Space direction="vertical" size={14} style={{ width: '100%' }}>
    <Alert type="info" showIcon message={t(editable ? 'parserEditor.editTenant' : preview ? 'parserEditor.copySystem' : 'parserEditor.createTenant')}
      description={t('parserEditor.guide')} />
    <Typography.Paragraph type="secondary">{t('parserEditor.draftGuide')}</Typography.Paragraph>
    {error && <Alert type="error" showIcon message={error} description={conflict ? t('parserEditor.conflict') : undefined} />}
    {editable && <Button disabled={busy} onClick={() => void run(async isCurrent => {
      setLatest(undefined);
      const result = await parsersApi.preview(id!); if (isCurrent()) setLatest(result.data);
    })}>{t('parserEditor.loadLatest')}</Button>}
    {latest && <ParserVersionComparison draft={{ definition, sample, priority, enabled, expectedVersion: base?.version }}
      latest={latest} busy={busy} onAdopt={adopt} />}
    <Typography.Text strong>{t('parserEditor.definition')}</Typography.Text>
    <Input.TextArea aria-label={t('parserEditor.definition')} rows={15} value={definition} disabled={busy}
      onChange={e => { setDefinition(e.target.value); setOutcome(undefined); }} />
    <Typography.Text strong>{t('parserEditor.sample')}</Typography.Text>
    <Input.TextArea aria-label={t('parserEditor.sampleLabel')} rows={5} value={sample} disabled={busy}
      onChange={e => { setSample(e.target.value); setOutcome(undefined); }} />
    <ParserInference sample={sample} disabled={busy} onDraft={(draft, sanitized) => {
      if (!alive.current || running.current) return;
      const next = JSON.parse(draft) as Record<string, unknown>;
      if (editable && base) next.key = base.key;
      setDefinition(JSON.stringify(next, null, 2)); setSample(sanitized); setOutcome(undefined);
    }} />
    <Space><Typography.Text>{t('parserEditor.priority')}</Typography.Text>
      <InputNumber aria-label={t('parserEditor.priorityLabel')} disabled={busy} min={0} max={100000} value={priority} onChange={value => setPriority(value ?? 50)} />
      <Switch aria-label={t('parserEditor.enabled')} disabled={busy} checked={enabled} onChange={setEnabled}
        checkedChildren={t('parserEditor.enabled')} unCheckedChildren={t('parserEditor.disabled')} />
      {editable && <Typography.Text>{t('parserEditor.currentVersion', { version: base?.version })}</Typography.Text>}
    </Space>
    <Space>
      <Button aria-label={t('parserEditor.validate')} loading={busy} onClick={() => void run(async isCurrent => {
        setOutcome(undefined); const result = await parsersApi.validate(body()); if (isCurrent()) setOutcome(result.data);
      })}>{t('parserEditor.validate')}</Button>
      <Button type="primary" aria-label={t(editable ? 'parserEditor.save' : 'parserEditor.saveNew')} loading={busy} onClick={() => void run(async isCurrent => {
        await parsersApi.save(editable ? id : undefined, body()); if (isCurrent()) saved();
      })}>{t(editable ? 'parserEditor.save' : 'parserEditor.saveNew')}</Button>
      {editable && <Popconfirm title={t('parserEditor.deleteTitle')} description={t('parserEditor.deleteHint')}
        onConfirm={() => run(async isCurrent => {
          await parsersApi.delete(id!, base!.version); if (isCurrent()) { onSaved(); onClose(); }
        })}>
        <Button danger disabled={busy}>{t('parserEditor.delete')}</Button>
      </Popconfirm>}
    </Space>
    {outcome && <><Alert type={outcome.matched ? 'success' : 'warning'} message={t(outcome.matched ? 'parserEditor.matched' : 'parserEditor.notMatched')} />
      <pre className="agf-code">{JSON.stringify(outcome.fields, null, 2)}</pre></>}
    {editable && <><Typography.Title level={5}>{t('parserEditor.history')}</Typography.Title>
      <DataState loading={history.isLoading} error={history.error}>
        <Table rowKey="version" size="small" pagination={false} dataSource={history.data?.data.items ?? []} columns={[
          { title: t('parserEditor.version'), dataIndex: 'version' }, { title: t('parserEditor.savedAt'), dataIndex: 'updatedAt' },
          { title: t('parserEditor.action'), render: (_value, row) => <Popconfirm title={t('parserEditor.restoreTitle', { version: row.version })}
            description={t('parserEditor.restoreHint')} onConfirm={() => run(async isCurrent => {
              await parsersApi.restore(id!, row.version, base!.version); if (isCurrent()) saved();
            })}><Button size="small" disabled={busy || row.version === base?.version}>{t('parserEditor.restore')}</Button></Popconfirm> },
        ]} />
      </DataState></>}
  </Space>;
}
