import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { Alert, Space, Table, Tabs, Tag, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { Panel } from '@/components/Panel';
import { Chip } from '@/components/Tags';
import type { AgentTeam, AgentTeamMember } from '@/types/domain';
import { TeamInventoryGuide } from './TeamInventoryGuide';

interface TeamMembersPanelProps { team: AgentTeam }

/** Worker relationships and cloud users have independent observation evidence. */
export function TeamMembersPanel({ team }: TeamMembersPanelProps) {
  const { t, i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language ?? 'zh-CN').startsWith('zh');
  const knownWorkers = team.relationshipAvailable === true;
  const knownPeople = team.humanMembersAvailable === true && Array.isArray(team.humanMembers);
  const memberColumns: ColumnsType<AgentTeamMember> = [
    {
      title: t('common.name'), dataIndex: 'name', width: 260,
      render: (value: string, row) => row.assetId ? <Link to={`/assets/${row.assetId}`}>{value}</Link>
        : <span className="agf-mono" style={{ fontSize: 12 }}>{value}</span>,
    },
    {
      title: t('alicloud.members.column.role'), dataIndex: 'cloudRole', width: 150,
      render: (value: unknown) => <Tag>{typeof value === 'string' && value.trim() ? value : t('alicloud.members.role.unknown')}</Tag>,
    },
    {
      title: t('alicloud.members.column.model'), dataIndex: 'model', width: 220,
      render: (value: string) => <span className="agf-mono" style={{ fontSize: 12 }}>{value || '—'}</span>,
    },
    {
      title: t('alicloud.members.column.status'), dataIndex: 'status', width: 110,
      render: (value: AgentTeamMember['status']) => <Chip color={value === 'active' ? '#3dd68c' : value === 'idle' ? '#f0cc6a' : '#6f7683'}>
        {t(`status.${value}`)}
      </Chip>,
    },
    {
      title: zh ? '已采集调用 / 24h' : 'Observed calls / 24h', dataIndex: 'invocations24h', width: 148, align: 'right',
      sorter: (a, b) => a.invocations24h - b.invocations24h,
      render: (value: number, row) => row.metricsAvailable === false ? '—' : value.toLocaleString(),
    },
  ];

  const workers = <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Text type="secondary">{t('alicloud.members.roleNote')}</Typography.Text>
    {knownWorkers ? <Table<AgentTeamMember> rowKey="id" size="small" columns={memberColumns}
      dataSource={team.members} pagination={false} scroll={{ x: 960 }}
      locale={{ emptyText: t('alicloud.members.empty') }} />
      : <Alert type="warning" showIcon message={t('alicloud.members.unknown')} />}
  </Space>;

  const people = <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Text>{t('alicloud.people.admin')}: {team.adminName ?? '—'} · {t('alicloud.people.leader')}: {team.leaderName ?? '—'}</Typography.Text>
    <Typography.Text type="secondary">{t('alicloud.people.note')}</Typography.Text>
    {knownPeople ? <Table<{ name: string }> rowKey="name" size="small" dataSource={team.humanMembers} pagination={false}
      columns={[{ title: t('common.name'), dataIndex: 'name' }]}
      locale={{ emptyText: t('alicloud.people.empty') }} />
      : <Alert type="warning" showIcon message={t('alicloud.people.unknown')} />}
  </Space>;

  const taskText = (value: string | null) => value?.trim() ? value : '—';
  const tasks = team.tasks ? <Table rowKey="viewKey" size="small"
    dataSource={team.tasks.map((task, index) => ({ ...task, viewKey: `${index}:${task.taskId ?? ''}` }))} columns={[
    { title: 'ID', dataIndex: 'taskId', render: taskText }, { title: zh ? '任务' : 'Task', dataIndex: 'taskTitle', render: taskText },
    { title: t('alicloud.tasks.assignedTo'), dataIndex: 'assignedTo',
      render: (value: string | null) => value?.trim() ? value : t('alicloud.members.role.unknown') },
    { title: zh ? '状态' : 'Status', dataIndex: 'status', render: taskText },
  ]} /> : <Alert type="info" message={t('alicloud.tasks.unavailable')} />;

  const dag = team.dagAvailable === true ? <Space direction="vertical" size={8} style={{ width: '100%' }}>
    {team.dag.map(node => <div key={node.id} className="agf-panel agf-panel--pad" style={{ padding: 10 }}>
      <Space size={10} wrap>
        <Tag>{node.role ?? t('alicloud.members.role.unknown')}</Tag>
        <span className="agf-mono">{node.label}</span>
        <span>{t('alicloud.dag.dependsOn')}:</span>
        {node.dependsOn.length === 0 ? <span>{t('alicloud.dag.none')}</span>
          : node.dependsOn.map(dependency => <Tag key={dependency} className="agf-mono">{dependency}</Tag>)}
      </Space>
    </div>)}
  </Space> : <Alert type="info" showIcon message={t('alicloud.dag.unavailable')} />;

  return <Panel title={`${t('alicloud.members.title')} · ${team.name}`}>
    <TeamInventoryGuide />
    <Space wrap style={{ marginBottom: 12 }}>
      <Tag color={knownWorkers ? 'blue' : 'gold'}>{t(knownWorkers ? 'alicloud.relations.available' : 'alicloud.relations.unknown')}</Tag>
      <Typography.Text>{t('alicloud.relations.evidence')}: {t(`alicloud.relations.evidence.${team.relationshipEvidence ?? 'unknown'}`)}</Typography.Text>
      {team.mocked && <Tag color="gold">Mock</Tag>}
    </Space>
    <Alert type="info" showIcon style={{ marginBottom: 12 }}
      message={zh ? '统计仅包含最近 24 小时已收到的调用事件，覆盖完整性未知。— 表示该成员尚未观测；有数值也不证明覆盖完整。'
        : 'Counts include received call events from the last 24 hours; coverage completeness is unknown. — means this member is unobserved. A value does not establish complete coverage.'} />
    <Tabs defaultActiveKey="members" items={[
      { key: 'members', label: t('alicloud.members.title'), children: workers },
      { key: 'people', label: t('alicloud.people.title'), children: people },
      { key: 'tasks', label: t('alicloud.tasks.title'), children: tasks },
      { key: 'dag', label: t('alicloud.dag.title'), children: dag },
    ]} />
  </Panel>;
}
