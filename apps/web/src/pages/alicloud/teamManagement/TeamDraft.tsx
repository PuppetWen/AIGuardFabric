import { useTranslation } from 'react-i18next';
import { Alert, Button, Checkbox, Input, Radio, Select, Space, Typography } from 'antd';
import type { ManagedTeam, TeamUserOption } from '@/types/teamManagement';
import type { TeamDraftValues } from './teamDraftState';

interface Props {
  draft: TeamDraftValues;
  teams: ManagedTeam[];
  team?: ManagedTeam;
  options: TeamUserOption[];
  disabled: boolean;
  canChooseUsers: boolean;
  onChange: (draft: TeamDraftValues) => void;
  onChooseTeam: (name: string) => void;
  onAction: (action: TeamDraftValues['action']) => void;
}
export default function TeamDraft({ draft, teams, team, options, disabled, canChooseUsers, onChange, onChooseTeam, onAction }: Props) {
  const { t } = useTranslation();
  const patch = (values: Partial<TeamDraftValues>) => onChange({ ...draft, ...values });
  const knownMembers = team?.memberNamesAvailable === true && Array.isArray(team.memberNames);
  const choosingMembers = draft.action === 'create' || draft.replaceMembers;
  const choices = [...new Set([...options.map(user => user.name), ...draft.memberNames])]
    .map(name => ({ value: name, label: name }));
  return <Space direction="vertical" size={12} style={{ width: '100%' }}>
    <Radio.Group value={draft.action} disabled={disabled} onChange={event => onAction(event.target.value)}>
      <Radio.Button value="create">{t('teamManagement.create')}</Radio.Button>
      <Radio.Button value="update">{t('teamManagement.update')}</Radio.Button>
      <Radio.Button value="delete">{t('teamManagement.delete')}</Radio.Button>
    </Radio.Group>
    {draft.action !== 'create' && <Select aria-label={t('teamManagement.team')} value={draft.teamName || undefined}
      disabled={disabled} style={{ width: '100%' }} onChange={onChooseTeam}
      options={teams.map(row => ({ value: row.teamName, label: row.currentAvailable ? row.teamName : `${row.teamName} · ${t('teamManagement.status.superseded')}` }))} />}
    <label htmlFor="team-management-name">{t('teamManagement.name')}</label>
    <Input id="team-management-name" value={draft.teamName} maxLength={128}
      disabled={disabled || draft.action !== 'create'} onChange={event => patch({ teamName: event.target.value })} />
    {team?.unresolvedDelete && <Alert type="warning" showIcon message={t('teamManagement.deletePending')} />}
    {draft.action !== 'delete' ? <>
      {draft.action === 'update' && <Checkbox checked={draft.changeDescription} disabled={disabled}
        onChange={event => patch({ changeDescription: event.target.checked })}>{t('teamManagement.changeDescription')}</Checkbox>}
      <label htmlFor="team-management-description">{t('teamManagement.description')}</label>
      <Input.TextArea id="team-management-description" value={draft.description} maxLength={4096} rows={3}
        disabled={disabled || !draft.changeDescription} onChange={event => patch({ description: event.target.value })} />
      {draft.action === 'create' && <>
        <Typography.Text>{t('teamManagement.admin')}</Typography.Text>
        <Select aria-label={t('teamManagement.admin')} allowClear value={draft.adminName} disabled={disabled || !canChooseUsers}
          style={{ width: '100%' }} onChange={value => patch({ adminName: value })}
          options={options.map(user => ({ value: user.name, label: user.name }))} />
        <Alert type="info" showIcon message={t('teamManagement.adminHint')} />
      </>}
      {draft.action === 'update' && <>
        <Alert type="info" showIcon message={t('teamManagement.fixedFields')} />
        {!knownMembers && <Alert type="warning" showIcon message={t('teamManagement.unknownMembers')} />}
        <Checkbox checked={draft.replaceMembers} disabled={disabled || !knownMembers}
          onChange={event => patch({ replaceMembers: event.target.checked })}>{t('teamManagement.replace')}</Checkbox>
        {!draft.replaceMembers && <Typography.Text>{t('teamManagement.keep')}</Typography.Text>}
      </>}
      <Typography.Text>{t('teamManagement.selected')}: {draft.action === 'update' && !knownMembers
        ? t('teamManagement.unknown') : draft.memberNames.join(', ') || t('teamManagement.none')}</Typography.Text>
      {choosingMembers && <>
        <Select aria-label={t('teamManagement.members')} mode="multiple" value={draft.memberNames}
          disabled={disabled || !canChooseUsers} style={{ width: '100%' }} onChange={values => patch({ memberNames: values })}
          options={choices} />
        <Button disabled={disabled || draft.memberNames.length === 0} onClick={() => patch({ memberNames: [] })}>
          {t('teamManagement.clearMembers')}
        </Button>
        {draft.memberNames.length === 0 && <Alert type="warning" showIcon message={t('teamManagement.emptyMembers')} />}
        {draft.memberNames.length > 200 && <Alert type="error" message={t('teamManagement.memberLimit')} />}
      </>}
    </> : <>
      <label htmlFor="team-management-delete-name">{t('teamManagement.deleteName')}</label>
      <Input id="team-management-delete-name" value={draft.deleteName} disabled={disabled}
        onChange={event => patch({ deleteName: event.target.value })} />
      <Checkbox checked={draft.acknowledgeCleanup} disabled={disabled}
        onChange={event => patch({ acknowledgeCleanup: event.target.checked })}>{t('teamManagement.deleteCleanup')}</Checkbox>
    </>}
  </Space>;
}
