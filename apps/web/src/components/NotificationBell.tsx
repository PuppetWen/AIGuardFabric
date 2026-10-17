import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Alert, Badge, Button, Drawer, Empty, Popover, Space, Typography } from 'antd';
import { BellOutlined } from '@ant-design/icons';
import { useApiQuery } from '@/api/client';
import { notificationApi, type InboxMessage } from '@/api/notifications';
import { useAuthStore } from '@/stores/authStore';
import { useAppLocale } from '@/app/AppLocaleProvider';
import { formatShortDateTime } from '@/utils/format';
import { DataState } from './DataState';
import { SeverityTag } from './Tags';

export function NotificationBell() {
  const tenant = useAuthStore(s => s.tenant?.id);
  const session = useAuthStore(s => s.sessionGeneration);
  return <InboxBell key={tenant + ':' + session} />;
}

function sourceLink(item: InboxMessage) {
  const id = encodeURIComponent(item.subjectId);
  if (item.subjectKind === 'alert' || item.subjectKind.startsWith('alert-escalation:')) return '/alerts?alert=' + id;
  if (item.subjectKind === 'finding') return '/findings?finding=' + id;
  if (item.subjectKind === 'case') return '/cases/' + id;
  if (item.subjectKind === 'asset') return '/assets/' + id;
  if (item.subjectKind === 'report') return '/reports';
  return undefined;
}

function InboxBell() {
  const { t, i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const locale = useAppLocale();
  const [open, setOpen] = useState(false);
  const [selected, setSelected] = useState<InboxMessage>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const inbox = useApiQuery('notification-inbox', notificationApi.inbox, { staleTime: 15_000, refetchInterval: 30_000 });
  const items = inbox.data?.data ?? [];
  const unread = items.filter(item => !item.read);
  const mark = async (ids: string[]) => {
    if (!ids.length || busy) return;
    setBusy(true); setError('');
    try { await notificationApi.markRead(ids); if (alive.current) await inbox.refetch(); }
    catch (e) { if (alive.current) setError(e instanceof Error ? e.message : String(e)); }
    finally { if (alive.current) setBusy(false); }
  };
  const content = <div style={{ width: 360, maxWidth: '80vw' }}>
    <Typography.Paragraph type="secondary">{zh ? '当前组织最近 100 条站内消息；已读状态按个人保存' : 'Latest 100 messages in this organization; read status is personal'}</Typography.Paragraph>
    {error && <Alert type="error" message={error} showIcon />}
    <DataState loading={inbox.isLoading} error={inbox.error} onRetry={() => void inbox.refetch()}>
      {items.length ? <Space direction="vertical" size={10} style={{ width: '100%', maxHeight: 380, overflowY: 'auto' }}>
        {items.map(item => <Button key={item.id} type="text" disabled={busy} style={{ width: '100%', height: 'auto', textAlign: 'left', whiteSpace: 'normal' }}
          onClick={() => { setSelected(item); setOpen(false); if (item.canMark && !item.read) void mark([item.id]); }}>
          <SeverityTag severity={item.severity} withLabel={false} />
          <div style={{ minWidth: 0, flex: 1 }}><Typography.Text style={{ fontSize: 13, fontWeight: item.read ? 400 : 600 }}>{item.title}</Typography.Text>
            <div className="agf-tertiary" style={{ fontSize: 12 }}>{formatShortDateTime(item.at, locale)}</div></div>
        </Button>)}
      </Space> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t('layout.notifications.empty')} />}
      <Space style={{ marginTop: 10 }}><Button size="small" loading={busy} disabled={!unread.some(item => item.canMark)}
        onClick={() => void mark(unread.filter(item => item.canMark).map(item => item.id))}>{t('layout.notifications.markAll')}</Button>
        <Button size="small" onClick={() => void inbox.refetch()}>{t('common.refresh')}</Button></Space>
    </DataState>
  </div>;
  return <>
    <Popover content={content} open={open} onOpenChange={setOpen} trigger="click" placement="bottomRight" title={zh ? '组织站内消息' : 'Organization inbox'}>
      <Badge count={unread.length} size="small" offset={[-2, 2]}><Button type="text" icon={<BellOutlined />}
        aria-label={t('layout.notifications')} data-testid="notification-bell" /></Badge>
    </Popover>
    <Drawer open={Boolean(selected)} onClose={() => setSelected(undefined)} title={selected?.title} width={620}>
      {error && <Alert type="error" message={error} showIcon />}
      {selected && <Space direction="vertical" style={{ width: '100%' }}>
        <SeverityTag severity={selected.severity} /><Typography.Text type="secondary">{formatShortDateTime(selected.at, locale)}</Typography.Text>
        <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{selected.body}</Typography.Paragraph>
        {sourceLink(selected) && <Link to={sourceLink(selected)!} onClick={() => setSelected(undefined)}>{zh ? '打开关联对象' : 'Open related object'}</Link>}
        {selected.canMark && !items.find(item => item.id === selected.id)?.read && <Button aria-label={zh ? '标记为已读' : 'Mark as read'} loading={busy} disabled={busy} onClick={() => void mark([selected.id])}>{zh ? '标记为已读' : 'Mark as read'}</Button>}
      </Space>}
    </Drawer>
  </>;
}

export default NotificationBell;
