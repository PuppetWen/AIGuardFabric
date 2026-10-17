import { useState } from 'react';
import { Button, Space, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { useOperationScope } from '@/components/receipts/useOperationScope';
import { useAuthStore } from '@/stores/authStore';

interface IdentityProps { id: string; version: number }

export function QuotaIdentity(props: IdentityProps) {
  const tenant = useAuthStore(state => state.tenant), generation = useAuthStore(state => state.sessionGeneration);
  return <Identity key={`${tenant?.id}:${tenant?.slug}:${generation}:${props.id}:${props.version}`} {...props} />;
}

function Identity({ id, version }: IdentityProps) {
  const zh = useTranslation().i18n.language.startsWith('zh'), scope = useOperationScope();
  const text = (cn: string, en: string) => zh ? cn : en;
  const [feedback, setFeedback] = useState(''), [copying, setCopying] = useState(false);
  const validVersion = Number.isSafeInteger(version) && version > 0;
  const copy = async (value: string, kind: 'id' | 'version') => {
    const operation = scope.begin();
    if (operation === undefined) return;
    setCopying(true); setFeedback('');
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(value);
      if (scope.current(operation)) setFeedback(kind === 'id'
        ? text('已复制配额 UUID', 'Quota UUID copied') : text('已复制当前版本', 'Current quota revision copied'));
    } catch {
      if (scope.current(operation)) setFeedback(text('复制失败；请手动选择显示的 UUID 或版本复制。',
        'Copy failed. Select the displayed UUID or revision to copy manually.'));
    } finally { if (scope.finish(operation)) setCopying(false); }
  };
  return <Space direction="vertical" size={2}>
    <Typography.Text code style={{ overflowWrap: 'anywhere' }}>{id}</Typography.Text>
    <Typography.Text>{validVersion ? `v${version}` : text('版本未知', 'Revision unknown')}</Typography.Text>
    <Space wrap>
      <Button size="small" disabled={copying || !id} aria-label={`${text('复制配额 UUID', 'Copy quota UUID')} ${id}`}
        onClick={() => void copy(id, 'id')}>{text('复制 UUID', 'Copy UUID')}</Button>
      <Button size="small" disabled={copying || !validVersion} aria-label={`${text('复制配额版本', 'Copy quota revision')} ${id}`}
        onClick={() => void copy(String(version), 'version')}>{text('复制版本', 'Copy revision')}</Button>
    </Space>
    {feedback && <Typography.Text role="status">{feedback}</Typography.Text>}
  </Space>;
}
