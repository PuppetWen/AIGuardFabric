import { useState } from 'react';
import { Alert, Button, Modal, Spin, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { callApi } from '@/api/transport';

/** Event references identify evidence; they are never treated as asset IDs or arbitrary URLs. */
export function EventEvidenceLink({ reference }: { reference: string }) {
  const { i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [event, setEvent] = useState<Record<string, unknown>>();
  const match = /^event:([0-9a-f-]{36}):([0-9a-f-]{36})$/i.exec(reference);
  if (!match) return <Typography.Text copyable>{reference}</Typography.Text>;
  const show = async () => {
    setOpen(true); setLoading(true); setError(''); setEvent(undefined);
    try {
      const result = await callApi<{ event: Record<string, unknown> }>(`/api/v1/ingest/events/${match[2]}`,
        () => { throw new Error('Event evidence is unavailable'); }, { noFallback: true, opaqueKeys: ['raw', 'extra'] });
      setEvent(result.data.event);
    } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)); }
    finally { setLoading(false); }
  };
  return <>
    <Button size="small" type="link" onClick={() => void show()}>{zh ? '查看来源事件' : 'View source event'}</Button>
    <Modal open={open} onCancel={() => setOpen(false)} footer={null} width={850}
      title={zh ? '来源事件 · 已归一化' : 'Source event · normalized'}>
      <Typography.Paragraph copyable>{reference}</Typography.Paragraph>
      {loading && <Spin />}
      {error && <Alert showIcon type="error" message={error} />}
      {event && <Typography.Paragraph copyable={{ text: JSON.stringify(event, null, 2) }}>
        <pre className="agf-code" style={{ maxHeight: '65vh', overflow: 'auto', whiteSpace: 'pre-wrap' }}>{JSON.stringify(event, null, 2)}</pre>
      </Typography.Paragraph>}
    </Modal>
  </>;
}
