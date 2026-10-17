import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Select, Space, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { useApiQuery } from '@/api/client';
import { gatewayApi } from '@/api/gateway';
import { parsersApi } from '@/api/parsers';
import { useAuthStore } from '@/stores/authStore';
interface Props { sample: string; disabled?: boolean; onDraft: (definition: string, sample: string) => void }
export function ParserInference({ sample, disabled, onDraft }: Props) {
  const { t } = useTranslation();
  const [model, setModel] = useState('');
  const [dataClass, setDataClass] = useState('restricted');
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState('');
  const [error, setError] = useState('');
  const running = useRef(false);
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const models = useApiQuery('parser-draft-models', gatewayApi.list);
  const generate = async () => {
    if (running.current || disabled) return;
    running.current = true; setBusy(true); setError(''); setNote('');
    const starting = useAuthStore.getState();
    const isCurrent = () => alive.current && useAuthStore.getState().tenant?.id === starting.tenant?.id
      && useAuthStore.getState().tenant?.slug === starting.tenant?.slug
      && useAuthStore.getState().sessionGeneration === starting.sessionGeneration;
    try {
      const result = await parsersApi.suggest(sample, model || undefined, dataClass);
      if (!isCurrent()) return;
      onDraft(result.data.definitionJson, result.data.sample);
      setNote(result.data.note);
    } catch (reason) { if (isCurrent()) setError(reason instanceof Error ? reason.message : String(reason)); }
    finally { if (isCurrent()) { running.current = false; setBusy(false); } }
  };
  const options = [...new Map((models.data?.data.items ?? []).filter(row => row.enabled).map(row => [
    row.model, { value: row.model, label: row.name + ' · ' + row.model + (row.mocked ? ' (' + t('parserEditor.mock') + ')' : '') },
  ])).values()];
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Text strong>{t('parserEditor.draftHeading')}</Typography.Text>
    <Space wrap>
      <Select aria-label={t('parserEditor.inferenceMethod')} style={{ width: 280 }} value={model} disabled={busy || disabled} onChange={setModel}
        options={[{ value: '', label: t('parserEditor.offlineInference') }, ...options]} />
      {!!model && <Select aria-label={t('parserEditor.dataClass')} style={{ width: 200 }} value={dataClass} disabled={busy || disabled} onChange={setDataClass}
        options={[{ value: 'restricted', label: t('parserEditor.restricted') }, { value: 'confidential', label: t('parserEditor.confidential') },
          { value: 'internal', label: t('parserEditor.internal') }, { value: 'public', label: t('parserEditor.public') }]} />}
      <Button loading={busy} disabled={disabled || !sample.trim()} onClick={() => void generate()}>{t('parserEditor.generate')}</Button>
    </Space>
    {!!model && <Alert type="info" message={t('parserEditor.modelHint')} />}
    {models.error && <Alert type="warning" message={t('parserEditor.modelsUnavailable')} />}
    {error && <Alert type="error" showIcon message={error} />}
    {note && <Alert type="info" showIcon message={note} />}
  </Space>;
}
