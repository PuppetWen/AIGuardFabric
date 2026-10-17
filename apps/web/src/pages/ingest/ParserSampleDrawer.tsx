import { useState } from 'react';
import { Alert, Button, Drawer, Input, Space, Table, Tag, Typography } from 'antd';
import { useApiQuery } from '@/api/client';
import { parsersApi } from '@/api/parsers';
import type { ParserPreview, ParseOutcome } from '@/api/parsers';
import { DataState } from '@/components/DataState';
import type { Parser } from '@/types/domain';
import { downloadText } from '@/utils/download';

interface Props { parser: Parser | null; onClose: () => void }
export function ParserSampleDrawer({ parser, onClose }: Props) {
  const preview = useApiQuery('parser-preview', () => parsersApi.preview(parser?.id ?? ''), {
    key: [parser?.id], enabled: !!parser,
  });
  return <Drawer width={780} open={!!parser} onClose={onClose} title={parser?.name} destroyOnClose>
    <DataState loading={preview.isLoading} error={preview.error}>
      {parser && preview.data?.data && <PreviewEditor key={parser.id} id={parser.id} preview={preview.data.data} />}
    </DataState>
  </Drawer>;
}

function PreviewEditor({ id, preview }: { id: string; preview: ParserPreview }) {
  const [sample, setSample] = useState(preview.sampleRaw ?? '');
  const [outcome, setOutcome] = useState<ParseOutcome | null>(preview.outcome);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const test = async () => {
    setBusy(true); setError('');
    try { setOutcome((await parsersApi.test(id, sample)).data); }
    catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)); }
    finally { setBusy(false); }
  };
  const rows = Object.entries(outcome?.fields ?? {}).map(([field, value]) => ({
    field, value: typeof value === 'string' ? value : JSON.stringify(value),
  }));
  return <Space direction="vertical" size={14} style={{ width: '100%' }}>
    <Alert type="info" showIcon message={preview.note} />
    <Typography.Text>测试样本（使用脱敏数据，最多 64 KiB）</Typography.Text>
    <Input.TextArea aria-label="解析器测试样本" rows={8} value={sample} onChange={(event) => setSample(event.target.value)} />
    <Space>
      <Button type="primary" loading={busy} disabled={!sample.trim()} onClick={() => void test()}>试解析</Button>
      <Button onClick={() => { setSample(preview.sampleRaw ?? ''); setOutcome(preview.outcome); setError(''); }}>恢复样本</Button>
      <Button onClick={() => downloadText(preview.key + '.json', preview.definitionJson)}>导出模板 JSON</Button>
    </Space>
    {error && <Alert type="error" showIcon message={error} />}
    {outcome && <>
      <Space><Tag color={outcome.matched ? 'green' : 'orange'}>{outcome.matched ? '解析命中' : '未命中模板'}</Tag>
        <Typography.Text type="secondary">{outcome.elapsedMicros} μs</Typography.Text></Space>
      {outcome.error && <Alert type="warning" message={outcome.error} />}
      {outcome.derivedErrors.length > 0 && <Alert type="warning" message={outcome.derivedErrors.join('；')} />}
      <Table rowKey="field" size="small" pagination={false} dataSource={rows}
        columns={[{ title: '事件字段', dataIndex: 'field', width: 240 }, { title: '解析值', dataIndex: 'value' }]} />
      {Object.keys(outcome.extra).length > 0 && <details><summary>未映射字段</summary>
        <pre className="agf-code">{JSON.stringify(outcome.extra, null, 2)}</pre></details>}
    </>}
  </Space>;
}

