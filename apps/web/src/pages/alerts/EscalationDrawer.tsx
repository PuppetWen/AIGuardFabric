import { useRef, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Card, Checkbox, Collapse, Drawer, Form, Input, InputNumber, Select, Space, Switch, Typography, message } from 'antd';
import { Link } from 'react-router-dom';
import { useApiQuery } from '@/api/client';
import { escalationApi, type EscalationConfig, type EscalationPolicyRoute } from '@/api/escalation';
import { DataState } from '@/components/DataState';
import { EscalationGuide } from './EscalationGuide';
import { EscalationHistory } from './EscalationHistory';

export function EscalationDrawer({ onClose }: { onClose: () => void }) {
  const { t, i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const config = useApiQuery('alert-escalation-config', escalationApi.get, { staleTime: 0 });
  const row = config.data?.data;
  return <Drawer open title={t('alerts.escalation.title')} width={960} onClose={onClose}>
    <Collapse style={{ marginBottom: 16 }} items={[{ key: 'guide', label: zh ? '配置与排查指南' : 'Setup and troubleshooting guide', children: <EscalationGuide /> }]} />
    <DataState loading={config.isLoading} error={config.error} onRetry={() => void config.refetch()}>
      {row && <EscalationEditor key={row.version} config={row} refresh={() => config.refetch()} />}
    </DataState>
    <Typography.Title level={5}>{zh ? '自动升级与投递记录' : 'Automatic escalation and delivery records'}</Typography.Title>
    <EscalationHistory />
  </Drawer>;
}

function EscalationEditor({ config, refresh }: { config: EscalationConfig; refresh: () => Promise<unknown> }) {
  const { t, i18n } = useTranslation();
  const zh = i18n.language.startsWith('zh');
  const [routes, setRoutes] = useState<EscalationPolicyRoute[]>(() => structuredClone(config.policies.map(p => p.route)));
  const [reason, setReason] = useState('');
  const [includeExisting, setIncludeExisting] = useState(false);
  const [activeSeverity, setActiveSeverity] = useState(config.policies.find(p => p.route.enabled)?.route.severity ?? 'critical');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const disabled = !config.canWrite || busy;
  const severities = ['info', 'low', 'medium', 'high', 'critical'];
  const roles = ['on-call', 'team-lead', 'security-owner', 'incident-commander'];
  const roleNames: Record<string, string> = { 'on-call': '值班组', 'team-lead': '团队负责人', 'security-owner': '安全负责人', 'incident-commander': '应急指挥' };
  const update = (index: number, route: EscalationPolicyRoute) => setRoutes(rows => rows.map((r, i) => i === index ? route : r));
  const save = async () => {
    setBusy(true); setError('');
    try {
      await escalationApi.save({ expectedVersion: config.version, routes, reason, includeExisting });
      if (!alive.current) return;
      message.success(zh ? '升级配置已保存' : 'Escalation policy saved');
      await refresh();
    } catch (e) { if (alive.current) setError(e instanceof Error ? e.message : String(e)); }
    finally { if (alive.current) setBusy(false); }
  };
  return <Space direction="vertical" size={14} style={{ width: '100%' }}>
    {!config.canWrite && <Alert type="info" showIcon message={zh ? '只读：发布需要具备告警读写权限的个人账号' : 'Read only: publishing requires a personal account with alert read/write permissions'} />}
    {!config.automaticAvailable && <Alert type="warning" showIcon message={zh ? '当前为离线模式，只能保存停用策略；自动升级需要 PostgreSQL' : 'Offline mode: only disabled policies can be saved. Automatic escalation requires PostgreSQL.'} />}
    {config.mockMode && <Alert type="info" showIcon message={zh ? '模拟模式：外部通知不会实际发出；站内消息正常保存' : 'Mock mode: external delivery is simulated; in-app messages are stored.'} />}
    <Typography.Text type="secondary">{zh ? '当前版本' : 'Current version'} v{config.version} · {zh ? '最近检查' : 'Last worker check'}: {config.health ? new Date(config.health.at).toLocaleString(zh ? 'zh-CN' : 'en-US') : '—'}</Typography.Text>
    {config.health?.error && <Alert type="error" showIcon message={zh ? '自动升级需要处理' : 'Automatic escalation needs attention'} description={config.health.error} />}
    <Link to="/settings?tab=notifications">{zh ? '配置渠道、接收人与连接测试' : 'Configure channels, recipients and connection tests'}</Link>
    <Form.Item label={zh ? '选择要配置的严重等级' : 'Choose policy severity'} htmlFor="escalation-severity" style={{ marginBottom: 0 }}>
      <Select id="escalation-severity" style={{ width: 280 }} value={activeSeverity} onChange={setActiveSeverity}
        options={routes.map(route => ({ value: route.severity, label: `${t(`severity.${route.severity}`)} · ${t(route.enabled ? 'common.enabled' : 'common.disabled')}` }))} />
    </Form.Item>
    {routes.map((route, index) => route.severity === activeSeverity && <Card size="small" title={t(`severity.${route.severity}`)} key={route.severity}
      extra={<Switch aria-label={`${route.severity} ${zh ? '启用策略' : 'enable policy'}`} checked={route.enabled} disabled={disabled || !config.automaticAvailable}
        onChange={enabled => update(index, { ...route, enabled })} />}>
      <Form layout="vertical" component={false}>
        <Form.Item label={zh ? '首次响应目标（分钟）' : 'First-response target (minutes)'} htmlFor={`response-${route.severity}`}>
          <InputNumber id={`response-${route.severity}`} value={route.responseMinutes} min={1} max={43200} precision={0} disabled={disabled}
            onChange={value => update(index, { ...route, responseMinutes: value ?? 1 })} />
        </Form.Item>
        {route.tiers.map((tier, tierIndex) => <Card size="small" key={tier.level} title={`L${tier.level}`} style={{ marginBottom: 10 }}
          extra={!disabled && <Button size="small" danger onClick={() => update(index, { ...route, tiers: route.tiers.filter((_, i) => i !== tierIndex).map((item, i) => ({ ...item, level: i + 1 })) })}>{t('common.delete')}</Button>}>
          <Space align="start" wrap>
            <Form.Item label={zh ? '超过响应目标后（分钟）' : 'Minutes after response target'} htmlFor={`delay-${route.severity}-${tier.level}`}>
              <InputNumber id={`delay-${route.severity}-${tier.level}`} min={0} max={43200} precision={0} value={tier.overdueMinutes} disabled={disabled}
                onChange={value => update(index, { ...route, tiers: route.tiers.map((item, i) => i === tierIndex ? { ...item, overdueMinutes: value ?? 0 } : item) })} />
            </Form.Item>
            <Form.Item label={zh ? '角色标签（不自动指派）' : 'Role label (no automatic assignment)'} htmlFor={`role-${route.severity}-${tier.level}`}>
              <Select id={`role-${route.severity}-${tier.level}`} style={{ width: 230 }} value={tier.target} disabled={disabled} options={roles.map(value => ({ value, label: zh ? roleNames[value] : value }))}
                onChange={target => update(index, { ...route, tiers: route.tiers.map((item, i) => i === tierIndex ? { ...item, target } : item) })} />
            </Form.Item>
          </Space>
          <Form.Item label={zh ? '通知渠道' : 'Notification channels'} htmlFor={`channels-${route.severity}-${tier.level}`}>
            <Select id={`channels-${route.severity}-${tier.level}`} mode="multiple" value={tier.channels} disabled={disabled} style={{ width: '100%' }}
              options={config.channels.map(c => ({ value: c.channel, label: c.channel === 'in-app' ? (zh ? '站内消息' : 'In-app inbox') : c.channel,
                disabled: !c.enabled || severities.indexOf(c.minSeverity) > severities.indexOf(route.severity) }))}
              onChange={channels => update(index, { ...route, tiers: route.tiers.map((item, i) => i === tierIndex ? { ...item, channels } : item) })} />
          </Form.Item>
        </Card>)}
        <Button disabled={disabled || route.tiers.length >= 3} onClick={() => update(index, { ...route, tiers: [...route.tiers,
          { level: route.tiers.length + 1, overdueMinutes: (route.tiers.at(-1)?.overdueMinutes ?? -5) + 5, target: 'on-call', channels: [] }] })}>{t('alerts.escalation.addTier')}</Button>
      </Form>
      <Typography.Paragraph type="secondary" style={{ marginTop: 10 }}>{zh ? '当前生效范围：' : 'Current scope: '}{!config.policies[index].route.enabled ? (zh ? '停用' : 'disabled') : config.policies[index].since
        ? `${zh ? '首见时间不早于' : 'first seen from'} ${new Date(config.policies[index].since!).toLocaleString(zh ? 'zh-CN' : 'en-US')}` : (zh ? '包含已有未响应告警' : 'includes existing unacknowledged alerts')}</Typography.Paragraph>
    </Card>)}
    <Checkbox checked={includeExisting} disabled={disabled} onChange={e => setIncludeExisting(e.target.checked)}>{zh ? '纳入已有告警（仅用于本次由停用转为启用的策略）' : 'Include existing alerts (only routes being enabled now)'}</Checkbox>
    <Form.Item label={zh ? '变更说明' : 'Change reason'} htmlFor="escalation-reason" required style={{ width: '100%', marginBottom: 0 }}>
      <Input.TextArea id="escalation-reason" value={reason} maxLength={600} rows={2} disabled={disabled} onChange={e => setReason(e.target.value)} />
    </Form.Item>
    {error && <Alert type="error" showIcon message={zh ? '配置未保存，草稿已保留' : 'Not saved; your draft is preserved'} description={error} />}
    <Space><Button type="primary" disabled={disabled || !reason.trim()} loading={busy} onClick={() => void save()}>{t('common.save')}</Button>
      <Button disabled={busy} onClick={() => void refresh()}>{zh ? '读取最新版本' : 'Load latest version'}</Button></Space>
    <Collapse items={[{ key: 'versions', label: zh ? '最近 20 个配置版本' : 'Last 20 policy versions', children:
      <Space direction="vertical">{[...config.history].reverse().map(revision => <Card size="small" key={revision.version} title={`v${revision.version} · ${new Date(revision.at).toLocaleString(zh ? 'zh-CN' : 'en-US')}`}>
        <Typography.Paragraph>{revision.reason}</Typography.Paragraph><Typography.Text type="secondary">{revision.actor}</Typography.Text>
        {revision.policies.filter(p => p.route.enabled).map(p => <div key={p.route.severity}>{t(`severity.${p.route.severity}`)} · {p.route.responseMinutes} min · {p.route.tiers.map(tier => `L${tier.level}: +${tier.overdueMinutes} min / ${tier.channels.join(', ')}`).join('; ')}</div>)}
      </Card>)}</Space> }]} />
  </Space>;
}
