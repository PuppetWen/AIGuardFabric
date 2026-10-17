import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Input, List, Modal, Pagination, Space, Tag, Typography } from 'antd';
import { api } from '@/api/client';
import type { NaturalResource, NaturalSearchResult } from '@/api/naturalSearch';

const labels: Record<NaturalResource, [string, string]> = {
  assets: ['资产', 'Assets'], findings: ['风险发现', 'Findings'], alerts: ['告警', 'Alerts'], cases: ['案件', 'Cases'],
};
const detail = (resource: NaturalResource, id: string) => {
  const encoded = encodeURIComponent(id);
  return resource === 'assets' || resource === 'cases' ? `/${resource}/${encoded}`
    : `/${resource}?${resource === 'findings' ? 'finding' : 'alert'}=${encoded}`;
};

/** Mounted within the existing tenant/session keyed global search. */
export function NaturalSearch() {
  const zh = useTranslation().i18n.language.startsWith('zh');
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [question, setQuestion] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [answer, setAnswer] = useState<{ value: NaturalSearchResult; question: string }>();
  const pending = useRef<{ sequence: number; controller?: AbortController }>({ sequence: 0 });
  useEffect(() => {
    const request = pending.current;
    return () => { request.sequence += 1; request.controller?.abort(); };
  }, []);
  const close = () => {
    pending.current.sequence += 1; pending.current.controller?.abort();
    setOpen(false); setLoading(false); setAnswer(undefined); setError('');
  };
  const run = async (text: string, page = 1) => {
    const request = pending.current;
    const sequence = ++request.sequence;
    request.controller?.abort();
    const controller = new AbortController(); request.controller = controller;
    setAnswer(undefined); setError(''); setLoading(true);
    try {
      const result = await api.naturalSearch(text.trim(), page, controller.signal);
      if (sequence === request.sequence) setAnswer({ value: result.data, question: text.trim() });
    } catch (cause) {
      if (sequence === request.sequence && !controller.signal.aborted) setError(cause instanceof Error ? cause.message : String(cause));
    } finally { if (sequence === request.sequence) setLoading(false); }
  };
  const value = answer?.value;
  const asked = answer?.question ?? '';
  return <>
    <Button size="small" onClick={() => setOpen(true)}>{zh ? '自然语言查询' : 'Ask about your data'}</Button>
    <Modal title={zh ? '自然语言查询' : 'Natural language search'} open={open} onCancel={close} footer={null} width={640}>
      <Space direction="vertical" style={{ width: '100%' }}>
        <Typography.Paragraph>{zh ? '用一句话查找当前组织的资产、风险发现、告警或案件。查询遵循当前账号的权限。'
          : 'Describe the assets, findings, alerts or cases to find in your current organization. Your existing access permissions apply.'}</Typography.Paragraph>
        <Typography.Text type="secondary">{zh ? '示例：查找包含 Demo 的资产；查找严重性为 high 的告警。'
          : 'Examples: “Find assets containing Demo”; “Find high severity alerts”.'}</Typography.Text>
        <Input.TextArea value={question} onChange={event => setQuestion(event.target.value)} maxLength={1024} rows={3}
          aria-label={zh ? '查询问题' : 'Search question'} />
        <Button type="primary" aria-label={zh ? '查询' : 'Search'} aria-busy={loading}
          loading={loading} disabled={!question.trim()} onClick={() => void run(question)}>
          {zh ? '查询' : 'Search'}</Button>
        {error && <Alert type="error" showIcon message={error} />}
        {value && <>
          <Space wrap><Tag>{labels[value.plan.resource][zh ? 0 : 1]}</Tag>
            <Tag color={value.mocked ? 'orange' : 'blue'}>{value.mocked ? (zh ? 'Mock 演示查询' : 'Mock demo query')
              : (zh ? '真实模型查询' : 'Live model query')}</Tag>
            <Typography.Text>{asked}</Typography.Text></Space>
          {(value.plan.q || value.plan.severity || value.plan.kind) && <Typography.Text type="secondary">
            {[value.plan.q, value.plan.severity, value.plan.kind].filter(Boolean).join(' · ')}</Typography.Text>}
          <List dataSource={value.results.items} locale={{ emptyText: zh ? '没有匹配记录' : 'No matching records' }}
            renderItem={item => <List.Item key={item.id}><Button type="link" onClick={() => {
              navigate(detail(value.plan.resource, item.id)); close();
            }}>{item.name || item.title || item.id}</Button></List.Item>} />
          <Pagination current={value.results.page} pageSize={value.results.pageSize} total={value.results.total}
            showSizeChanger={false} onChange={page => void run(asked, page)} />
        </>}
      </Space>
    </Modal>
  </>;
}
