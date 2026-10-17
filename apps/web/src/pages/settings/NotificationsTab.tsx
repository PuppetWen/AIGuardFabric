import { useEffect, useState } from 'react';
import { Alert, Button, Popconfirm, Space, message } from 'antd';
import { notificationApi, type ChannelRow } from '@/api/notifications';
import { ApiRequestError } from '@/api/transport';
import { NotificationChannelCard } from './NotificationChannelCard';
import { useNotificationText } from './notificationText';
import { NotificationHistory } from './NotificationHistory';
import { useAuthStore } from '@/stores/authStore';

export function NotificationsTab() {
  const tenant = useAuthStore(state => state.tenant?.id);
  const session = useAuthStore(state => state.sessionGeneration);
  return <NotificationSettings key={`${tenant}:${session}`} />;
}

function NotificationSettings() {
  const text = useNotificationText();
  const [rows, setRows] = useState<ChannelRow[]>([]);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [conflicts, setConflicts] = useState<string[]>([]);
  const [result, setResult] = useState('');
  const refresh = async () => {
    try { setRows((await notificationApi.list()).data); setError(''); setConflicts([]); }
    catch (e) { setError(e instanceof Error ? e.message : text('读取通知配置失败')); }
  };
  useEffect(() => {
    let active = true;
    notificationApi.list().then(
      ({ data }) => { if (active) { setRows(data); setError(''); } },
      (e: unknown) => { if (active) setError(e instanceof Error ? e.message : String(e)); },
    );
    return () => { active = false; };
  }, []);
  const save = async (row: ChannelRow, test = false) => {
    setBusy(row.channel); setError(''); setResult('');
    try {
      const saved = (await notificationApi.save(row)).data;
      setRows((current) => current.map((item) => item.channel === row.channel ? saved : item));
      setConflicts((current) => current.filter((channel) => channel !== row.channel));
      if (test) {
        const reply = (await notificationApi.test(row.channel)).data;
        const failed = reply.deliveries.filter((item) => item.outcome !== 'delivered');
        if (failed.length) throw new Error(failed.map((item) => item.error ?? item.outcome).join('；'));
        setResult(reply.note); message.success(reply.mocked ? text('模拟测试通过，未发送到外部系统') : text('投递成功'));
      } else { message.success(text('通知配置已保存')); }
    } catch (e) {
      if (e instanceof ApiRequestError && e.status === 409) {
        setConflicts((current) => current.includes(row.channel) ? current : [...current, row.channel]);
      }
      setError(e instanceof Error ? e.message : text('操作失败'));
    }
    finally { setBusy(''); }
  };
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Alert type="info" showIcon message={text('先配置渠道，再启用通知')}
      description={text('渠道配置说明')} />
    {error && <Alert type="error" showIcon message={error}
      description={conflicts.length ? text('通知冲突说明') : undefined}
      action={conflicts.length ? <Popconfirm title={text('丢弃通知草稿并加载最新配置？')}
        onConfirm={() => void refresh()}><Button>{text('重新加载')}</Button></Popconfirm>
        : <Button onClick={() => void refresh()}>{text('重新加载')}</Button>} />}
    {result && <Alert type="success" message={result} />}
    <NotificationHistory />
    {rows.map((row) => <NotificationChannelCard key={row.channel} row={row} busy={!!busy}
      conflicted={conflicts.includes(row.channel)}
      onChange={(next) => setRows((current) => current.map((item) => item.channel === row.channel ? next : item))}
      onSave={(test) => void save(row, test)} />)}
  </Space>;
}
