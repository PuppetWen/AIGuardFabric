import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import i18n from '@/locales/i18n';
import type { AgentTeam, AgentTeamMember } from '@/types/domain';
import { TeamTable } from './TeamTable';
import { TeamMembersPanel } from './TeamMembersPanel';

const team = (overrides: Partial<AgentTeam> = {}): AgentTeam => ({
  id: 'team-one', name: 'Observed team', workspaceId: 'instance-one', region: 'cn-hangzhou',
  memberCount: 0, members: [], relationshipAvailable: true, relationshipEvidence: 'team-worker-names',
  humanMembers: [], humanMembersAvailable: true, humanMemberCount: 0,
  dag: [], dagAvailable: false, dagEvidence: 'not-provided', crossTeamCalls24h: 0, riskScore: 0,
  metricsAvailable: false, riskAvailable: false, createdAt: '2026-09-20T10:00:00Z', ...overrides,
});
const worker = (overrides: Partial<AgentTeamMember> = {}): AgentTeamMember => ({
  id: 'worker-one', name: 'same-name', assetId: 'asset-one', role: 'worker', cloudRole: 'member',
  model: 'cloud-model', status: 'active', invocations24h: 0, metricsAvailable: false, ...overrides,
});
const mount = async (value: AgentTeam) => {
  await act(async () => { render(<MemoryRouter><TeamMembersPanel team={value} /></MemoryRouter>); });
};
beforeEach(async () => { await i18n.changeLanguage('en-US'); });
afterEach(async () => {
  cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks();
  await act(async () => { await i18n.changeLanguage('zh-CN'); });
});

it('distinguishes unverified and legacy counts from a verified empty roster, and keeps team selection usable', async () => {
  const select = vi.fn();
  await act(async () => {
    render(<TeamTable loading={false} error={null} onSelectTeam={select} teamList={[
      team({ id: 'unknown', name: 'Unknown team', relationshipAvailable: false, relationshipEvidence: 'unverified', memberCount: null, createdAt: null }),
      team({ id: 'legacy', name: 'Legacy team', relationshipAvailable: undefined, relationshipEvidence: undefined, memberCount: 9 }),
      team({ id: 'empty', name: 'Empty team', relationshipEvidence: 'worker-groups' }),
    ]} />);
  });
  expect(within(screen.getByRole('row', { name: /Unknown team/ })).getByText('Unknown')).toBeInTheDocument();
  expect(within(screen.getByRole('row', { name: /Legacy team/ })).getByText('Unknown')).toBeInTheDocument();
  expect(within(screen.getByRole('row', { name: /Legacy team/ })).queryByText('9')).not.toBeInTheDocument();
  const empty = within(screen.getByRole('row', { name: /Empty team/ }));
  expect(empty.getByText('0')).toBeInTheDocument();
  expect(empty.getByText('Complete Worker Groups')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Unknown team' }));
  expect(select).toHaveBeenCalledWith('unknown');
});

it('shows raw cloud roles and unknown roles without translating legacy role assumptions into permissions', async () => {
  const rawRole = '<b>custom/member-role</b>';
  await mount(team({ memberCount: 2, members: [worker({ cloudRole: rawRole }), worker({ id: 'unknown-role',
    name: 'role-not-returned', assetId: undefined, role: 'orchestrator', cloudRole: null })] }));
  const pane = within(screen.getByRole('tabpanel', { name: 'Worker members' }));
  expect(pane.getByText(rawRole)).toBeInTheDocument();
  expect(pane.getByText('Unknown')).toBeInTheDocument();
  expect(pane.queryByText('Orchestrator')).not.toBeInTheDocument();
  expect(pane.getByRole('link', { name: 'same-name' })).toHaveAttribute('href', '/assets/asset-one');
  expect(pane.queryByText('custom/member-role', { selector: 'b' })).not.toBeInTheDocument();
  expect(pane.getByText(/do not establish platform roles or tool authorization/)).toBeInTheDocument();
});

it('keeps a same-name cloud user in a separate roster without a Worker asset link', async () => {
  await mount(team({ memberCount: 1, members: [worker()], humanMembers: [{ name: 'same-name' }], humanMemberCount: 1,
    adminName: 'cloud-admin', leaderName: 'cloud-leader' }));
  expect(within(screen.getByRole('tabpanel', { name: 'Worker members' })).getByRole('link', { name: 'same-name' })).toBeInTheDocument();
  fireEvent.click(screen.getByRole('tab', { name: 'Cloud users' }));
  const people = within(await screen.findByRole('tabpanel', { name: 'Cloud users' }));
  expect(people.getByText('same-name')).toBeInTheDocument();
  expect(people.queryByRole('link', { name: 'same-name' })).not.toBeInTheDocument();
  expect(people.queryByRole('columnheader', { name: 'Cloud role' })).not.toBeInTheDocument();
  expect(people.getByText(/Cloud admin: cloud-admin/)).toBeInTheDocument();
  expect(people.getByText(/do not automatically gain platform access/)).toBeInTheDocument();
});

it('shows missing Worker relationships and missing human rosters as unknown instead of observed empty', async () => {
  await mount(team({ relationshipAvailable: false, relationshipEvidence: 'unverified', memberCount: null,
    humanMembersAvailable: false, humanMemberCount: null }));
  const workers = within(screen.getByRole('tabpanel', { name: 'Worker members' }));
  expect(workers.getByText(/complete roster is unknown/)).toBeInTheDocument();
  expect(workers.queryByText('This team was observed to have no Worker members')).not.toBeInTheDocument();
  expect(workers.queryByRole('table')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('tab', { name: 'Cloud users' }));
  const people = within(await screen.findByRole('tabpanel', { name: 'Cloud users' }));
  expect(people.getByText(/emptiness cannot be confirmed/)).toBeInTheDocument();
  expect(people.queryByText('This team was observed to have no cloud user members')).not.toBeInTheDocument();
});

it('labels explicitly observed empty Worker and human rosters independently', async () => {
  await mount(team());
  expect(screen.getByText('This team was observed to have no Worker members')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('tab', { name: 'Cloud users' }));
  expect(await screen.findByText('This team was observed to have no cloud user members')).toBeInTheDocument();
});

it.each(['en-US', 'zh-CN'])('uses an assignee title and explains missing DAG data in %s', async language => {
  await i18n.changeLanguage(language);
  await mount(team({ tasks: [
    { taskId: 'task-one', taskTitle: 'Cloud task', assignedTo: 'cloud-user-only', status: 'Pending', createdAt: '' },
    { taskId: null, taskTitle: null, assignedTo: null, status: null, createdAt: null },
  ],
    dag: [{ id: 'invented', label: 'Must not render', role: 'orchestrator', dependsOn: [] }] }));
  const zh = language === 'zh-CN';
  fireEvent.click(screen.getByRole('tab', { name: zh ? '云端任务' : 'Cloud tasks' }));
  const tasks = within(await screen.findByRole('tabpanel', { name: zh ? '云端任务' : 'Cloud tasks' }));
  expect(tasks.getByRole('columnheader', { name: zh ? '指派对象' : 'Assigned to' })).toBeInTheDocument();
  expect(tasks.queryByRole('columnheader', { name: 'Worker' })).not.toBeInTheDocument();
  expect(tasks.getByText('cloud-user-only')).toBeInTheDocument();
  expect(tasks.getByText(zh ? '未知' : 'Unknown')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('tab', { name: zh ? '编排 DAG' : 'Orchestration DAG' }));
  const dag = within(await screen.findByRole('tabpanel', { name: zh ? '编排 DAG' : 'Orchestration DAG' }));
  expect(dag.getByText(zh ? /上游未提供编排 DAG/ : /Upstream did not provide an orchestration DAG/)).toBeInTheDocument();
  expect(dag.queryByText('Must not render')).not.toBeInTheDocument();
});
