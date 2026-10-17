import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Alert, Button, Collapse, Form, Space, message } from 'antd';
import { PlusOutlined, ReloadOutlined } from '@ant-design/icons';

import { api, useApiQuery } from '@/api/client';
import { PageHeader } from '@/components/DataState';
import { useSessionAccess } from '@/api/sessionAccess';
import { useAuthStore } from '@/stores/authStore';
import type { Policy, PolicyAction } from '@/types/domain';

import { PoliciesTable } from './policies/PoliciesTable';
import { PolicyEditor } from './policies/PolicyEditor';
import { PolicyHistory } from './policies/PolicyHistory';
import { PolicyGuide } from './policies/PolicyGuide';
import { usePolicyText } from './policies/usePolicyText';
import type { ConditionRow } from './policies/policies.data';
import {
  composePolicyCode,
  parseExpressionToConditions,
  validatePolicyCode,
  type CodeValidation,
} from './policies/policyCode';

export { composePolicyCode, validatePolicyCode };
export type { CodeValidation };

export default function PoliciesPage() {
  const tenant = useAuthStore(state => state.tenant), generation = useAuthStore(state => state.sessionGeneration);
  return <ScopedPoliciesPage key={`${tenant?.id}:${tenant?.slug}:${generation}`} />;
}

function ScopedPoliciesPage() {
  const { t } = useTranslation();
  const text = usePolicyText(), access = useSessionAccess();
  const canWrite = access.has('policies:write'), canDelete = access.has('policies:delete');
  const [editorEpoch, setEditorEpoch] = useState(0);
  const [editorOpen, setEditorOpen] = useState(false);
  const [historyPolicy,setHistoryPolicy]=useState<Policy|null>(null);
  const [mode, setMode] = useState<'form' | 'code'>('form');
  const [editing, setEditing] = useState<Policy | null>(null);
  const [action, setAction] = useState<PolicyAction>('deny');
  const [conditions, setConditions] = useState<ConditionRow[]>([
    { id: 'c1', field: 'request.host', operator: 'contains', value: 'attacker.example' },
  ]);
  const [code, setCode] = useState('');
  const [language, setLanguage] = useState<'rego' | 'cel' | 'structured'>('rego');
  const [validation, setValidation] = useState<CodeValidation | null>(null);
  const [form] = Form.useForm<Policy>();

  const policies = useApiQuery('policies', () => api.policies({ pageSize: 50 }));

  const openEditor = (policy?: Policy): void => {
    setEditorEpoch(value => value + 1);
    setEditing(policy ?? null);
    setEditorOpen(true);
    setMode(policy ? 'code' : 'form');
    setValidation(null);
    if (policy) {
      setAction(policy.action);
      setLanguage(policy.codeLanguage);
      setCode(policy.code);
      const parsed = parseExpressionToConditions(policy.expression);
      setConditions(parsed.length > 0 ? parsed : [{ id: 'c1', field: 'request.host', operator: '==', value: '' }]);
      form.resetFields(); form.setFieldsValue(policy);
    } else {
      setAction('deny');
      setLanguage('rego');
      setConditions([{ id: 'c1', field: 'request.host', operator: 'contains', value: '' }]);
      setCode(composePolicyCode('rego', 'deny', []));
      form.resetFields();
      form.setFieldsValue({
        name: '',
        description: '',
        priority: 50,
        interceptPoints: ['mcp-proxy'],
        dryRun: false,
        enabled: true,
        codeLanguage: 'rego',
      } as unknown as Policy);
    }
  };

  const syncToCode = (): void => {
    try {
      setCode(composePolicyCode(language, action, conditions));
      setValidation(null);
      message.success(t('policies.editor.synced'));
    } catch (error) { if (error instanceof Error) message.error(error.message); }
  };

  return (
    <>
      <PageHeader
        title={t('policies.title')}
        subtitle={t('policies.subtitle')}
        actions={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={() => void policies.refetch()}>
              {t('common.refresh')}
            </Button>
            <Button type="primary" icon={<PlusOutlined />} disabled={!canWrite} onClick={() => openEditor()}>
              {t('policies.editor.title')}
            </Button>
          </Space>
        }
      />

      <Collapse style={{ marginBottom: 16 }} items={[{ key: 'guide', label: text('策略发布、冲突与恢复指南', 'Policy publication, conflict and recovery guide'), children: <PolicyGuide /> }]} />
      {!access.isLoading && !canWrite && <Alert style={{ marginBottom: 16 }} type="info" message={text('当前账号可查看；发布需 policies:write，删除另需 policies:delete。',
        'You can inspect policies. Publication requires policies:write; deletion separately requires policies:delete.')} />}

      <PoliciesTable
        loading={policies.isLoading}
        error={policies.error}
        policies={policies.data?.data.items ?? []}
        onEdit={openEditor}
        onHistory={setHistoryPolicy}
      />

      {editorOpen && <PolicyEditor
        key={editorEpoch}
        canWrite={canWrite}
        canDelete={canDelete}
        open={editorOpen}
        editing={editing}
        form={form}
        mode={mode}
        setMode={setMode}
        action={action}
        setAction={setAction}
        conditions={conditions}
        setConditions={setConditions}
        code={code}
        setCode={setCode}
        language={language}
        setLanguage={setLanguage}
        validation={validation}
        setValidation={setValidation}
        onSyncToCode={syncToCode}
        onAdopt={openEditor}
        onClose={() => setEditorOpen(false)}
        onSaved={() => {
          setEditorOpen(false);
          void policies.refetch();
        }}
      />}
      {historyPolicy&&<PolicyHistory policy={historyPolicy} canWrite={canWrite} onClose={()=>setHistoryPolicy(null)} onChanged={()=>void policies.refetch()} />}
    </>
  );
}
