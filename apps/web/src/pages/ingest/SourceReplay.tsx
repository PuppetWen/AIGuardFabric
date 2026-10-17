import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Descriptions, Select, Space, Typography } from 'antd';
import { callApi } from '@/api/transport';
import { Panel } from '@/components/Panel';
import type { LogSource } from '@/types/domain';

interface ReplayResult {
  replayed: number; newlyParsed: number; failed: number;
  parserUsed: Record<string, number>;
  rawLogs: { id: string; payload: string; decodeError?: string }[];
  notes: string[];
}
export function SourceReplay({ sources, source, onSelect }: {
  sources: LogSource[]; source: string; onSelect: (id: string) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ source: string; data: ReplayResult }>();
  const [error, setError] = useState<{ source: string; message: string }>();
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const shownResult = result?.source === source ? result.data : undefined;
  const shownError = error?.source === source ? error.message : '';
  const replay = async () => {
    setBusy(true); setError(undefined); setResult(undefined);
    try {
      const response = await callApi<ReplayResult>('/api/v1/ingest/replay',
        () => { throw new Error(text('日志回放需要连接后端', 'Log replay requires the backend')); },
        { method: 'POST', body: { source_id: source, limit: 1000 }, noFallback: true,
          opaqueKeys: ['parser_used'], timeoutMs: 30000 });
      setResult({ source, data: response.data });
    } catch (reason) { setError({ source, message: reason instanceof Error ? reason.message : String(reason) }); }
    finally { setBusy(false); }
  };
  return <Panel title={text('重新解析原始日志', 'Reparse raw logs')}>
    <Space direction="vertical" size={14} style={{ width: '100%' }}>
      <Typography.Paragraph>{text('选择日志源并执行后，平台会用当前解析模板处理尚未解析的原文，保存新事件并保留原文。',
        'Select a source to reparse unprocessed raw logs with the current templates. New events are saved; raw logs are retained.')}</Typography.Paragraph>
      <Space>
        <Select style={{ width: 240 }} placeholder={text('选择本页日志源', 'Select a source on this page')} value={source || undefined}
          disabled={busy} onChange={(next) => { setResult(undefined); setError(undefined); onSelect(next); }}
          options={sources.map((row) => ({ value: row.id, label: row.name }))} />
        <Button type="primary" disabled={!source} loading={busy} onClick={() => void replay()}>{text('执行回放', 'Run replay')}</Button>
      </Space>
      {shownError && <Alert type="error" showIcon message={shownError} />}
      {shownResult && <>
        <Descriptions bordered size="small" column={3}>
          <Descriptions.Item label={text('检查', 'Checked')}>{shownResult.replayed}</Descriptions.Item>
          <Descriptions.Item label={text('新解析', 'Newly parsed')}>{shownResult.newlyParsed}</Descriptions.Item>
          <Descriptions.Item label={text('失败', 'Failed')}>{shownResult.failed}</Descriptions.Item>
          <Descriptions.Item label={text('命中解析器', 'Matched parsers')} span={3}>
            {Object.entries(shownResult.parserUsed ?? {}).map(([name, count]) => `${name}: ${count}`).join(', ')
              || text('未命中', 'None')}
          </Descriptions.Item>
        </Descriptions>
        {shownResult.notes.map((note) => <Typography.Text type="secondary" key={note}>{note}</Typography.Text>)}
        {shownResult.rawLogs.slice(0, 10).map((row) => <pre key={row.id} className="agf-code agf-code--compact">{row.decodeError || row.payload}</pre>)}
      </>}
    </Space>
  </Panel>;
}
