import { useState, type Dispatch, type SetStateAction } from 'react';
import { useTranslation } from 'react-i18next';

import {
  Button,
  Alert,
  Drawer,
  Form,
  Input,
  InputNumber,
  Radio,
  Popconfirm,
  Select,
  Space,
  Switch,
  Typography,
  message,
} from 'antd';
import type { FormInstance } from 'antd';
import { CodeOutlined, PlusOutlined, SafetyCertificateOutlined, SaveOutlined } from '@ant-design/icons';

import { policiesApi, validPolicyVersion } from '@/api/policies';
import { isPolicyAction } from '@/api/policyActions';
import type { Policy, PolicyAction } from '@/types/domain';
import { interceptPointKey, policyActionKey } from '@/utils/labels';

import { ACTIONS, INTERCEPT_POINTS, MATCH_FIELDS, OPERATORS, type ConditionRow } from './policies.data';
import { composePolicyCode, validatePolicyCode, type CodeValidation } from './policyCode';
import { PolicyVersionComparison } from './PolicyVersionComparison';
import { usePolicyOperation } from './usePolicyOperation';
import { usePolicyText } from './usePolicyText';
import { PolicyQuotaSelection } from './PolicyQuotaSelection';

interface PolicyEditorProps {
  open: boolean;
  editing: Policy | null;
  form: FormInstance<Policy>;
  mode: 'form' | 'code';
  setMode: Dispatch<SetStateAction<'form' | 'code'>>;
  action: PolicyAction;
  setAction: Dispatch<SetStateAction<PolicyAction>>;
  conditions: ConditionRow[];
  setConditions: Dispatch<SetStateAction<ConditionRow[]>>;
  code: string;
  setCode: Dispatch<SetStateAction<string>>;
  language: 'rego' | 'cel' | 'structured';
  setLanguage: Dispatch<SetStateAction<'rego' | 'cel' | 'structured'>>;
  validation: CodeValidation | null;
  setValidation: Dispatch<SetStateAction<CodeValidation | null>>;
  onSyncToCode: () => void;
  onClose: () => void;
  onSaved: () => void;
  onAdopt: (policy: Policy) => void;
  canWrite: boolean;
  canDelete: boolean;
}

/**
 * Policy editor drawer: form-mode condition builder and code-mode pane.
 *
 * State stays in the page so opening a row resets everything in one batch;
 * this component renders it and owns scoped save/delete/comparison requests.
 */
export function PolicyEditor({
  open,
  editing,
  form,
  mode,
  setMode,
  action,
  setAction,
  conditions,
  setConditions,
  code,
  setCode,
  language,
  setLanguage,
  validation,
  setValidation,
  onSyncToCode,
  onClose,
  onSaved,
  onAdopt,
  canWrite,
  canDelete,
}: PolicyEditorProps) {
  const { t } = useTranslation();
  const text = usePolicyText(), operation = usePolicyOperation();
  const [latest, setLatest] = useState<Policy>();
  const watchedValues = Form.useWatch([], { form, preserve: true }) as Partial<Policy> | undefined;
  const { busy } = operation;
  const knownVersion = validPolicyVersion(editing?.version);
  const knownAction = isPolicyAction(action) && (!editing || isPolicyAction(editing.action));
  const draftFields = (values: Partial<Policy>): Partial<Policy> => ({ ...editing, ...values, id: editing?.id,
    action, code: undefined, codeLanguage: language,
    expression: conditions.map(row => `${row.field} ${row.operator} ${row.value}`).join(' && ') });
  const draft = (values: Partial<Policy> = form.getFieldsValue(true)): Partial<Policy> => ({
    ...draftFields(values), code: mode === 'form' ? composePolicyCode(language, action, conditions) : code,
  });
  const comparison = latest ? (() => {
    const values = watchedValues ?? form.getFieldsValue(true);
    try { return { draft: draft(values), error: undefined }; }
    catch (error) { return { draft: draftFields(values), error: text(
      '条件尚不完整，无法生成待保存源码；补全条件后再比较。',
      'Conditions are incomplete; the source to save cannot be generated. Complete the conditions before comparing.',
    ) + (error instanceof Error ? ` ${error.message}` : '') }; }
  })() : undefined;
  const save = () => operation.run(async isCurrent => {
    if (!canWrite || !knownAction || (editing && !knownVersion)) return;
    // Snapshot all draft fields and the reviewed revision before asynchronous validation.
    const snapshot = JSON.parse(JSON.stringify(draft())) as Partial<Policy>, expectedVersion = editing?.version;
    try { await form.validateFields(); }
    catch { throw new Error(text('请检查表单中标记的问题；草稿未发布。', 'Check the highlighted form fields; the draft was not published.')); }
    if (!isCurrent()) return;
    const result = await policiesApi.save(snapshot, expectedVersion);
    if (!isCurrent()) return;
    if (!validPolicyVersion(result.data.version) || (editing && result.data.id !== editing.id)) {
      throw new Error(text('服务端未返回该策略的有效发布版本。', 'The server returned no valid published revision for this policy.'));
    }
    message.success(t('policies.editor.saved')); onSaved();
  });

  const previewOption = (() => {
    const conditionsText = conditions
      .map((row) => `${row.field} ${row.operator} ${row.value}`)
      .join(' AND ');
    return `WHEN ${conditionsText || '*'} THEN ${t(policyActionKey(action)).toUpperCase()}`;
  })();

  const metadata = (<>
      <Form.Item name="name" label={t('policies.editor.name')} rules={[{ required: true, message: t('policies.editor.nameRequired') }]}>
        <Input disabled={!!editing || busy || !canWrite} />
      </Form.Item>
      <Form.Item name="description" label={t('policies.editor.description')}>
        <Input.TextArea autoSize={{ minRows: 2, maxRows: 4 }} />
      </Form.Item>
      <Form.Item label={t('policies.editor.action')}>
        <Select
          value={action}
          onChange={(value: PolicyAction) => setAction(value)}
          options={ACTIONS.map((value) => ({ value, label: t(policyActionKey(value)) }))}
        />
      </Form.Item>
      <Form.Item name="priority" label={t('policies.editor.priority')}>
        <InputNumber min={1} max={999} style={{ width: '100%' }} />
      </Form.Item>
      <Form.Item name="interceptPoints" label={t('policies.editor.interceptPoints')}>
        <Select
          mode="multiple"
          options={INTERCEPT_POINTS.map((value) => ({ value, label: t(interceptPointKey(value)) }))}
        />
      </Form.Item>
      <Form.Item name="dryRun" label={t('policies.editor.dryRun')} valuePropName="checked" extra={t('policies.editor.dryRunHint')}>
        <Switch />
      </Form.Item>

      <Form.Item name="enabled" label={t('common.enabled')} valuePropName="checked"><Switch /></Form.Item>
      <Form.Item name="scopeDepartments" label="部门范围 / Departments" extra="留空适用整个租户 / Empty means the entire tenant"><Select mode="tags" /></Form.Item>
      {action === 'redirect' && <Form.Item name="degradeEndpointId" label="降级模型端点 ID / Fallback endpoint ID" rules={[{ required: true }]}><Input /></Form.Item>}
      {(action === 'throttle' || action === 'quota') && <Form.Item name="quotaId" label="配额 ID / Quota ID" extra="留空使用当前租户全部有效配额 / Empty uses all active quotas"><PolicyQuotaSelection disabled={busy || !canWrite} /></Form.Item>}
    </>);

  const formBody = (
    <Space direction="vertical" size={12} style={{ width: '100%' }}>

      <div>
        <div className="agf-drawer-section__title">{t('policies.editor.matchConditions')}</div>
        <Space direction="vertical" size={8} style={{ width: '100%' }}>
          {conditions.map((row) => (
            <Space key={row.id} size={6} style={{ width: '100%' }} align="baseline">
              <Select
                style={{ width: 176 }}
                value={row.field}
                onChange={(value) =>
                  setConditions((prev) => prev.map((item) => (item.id === row.id ? { ...item, field: value } : item)))
                }
                options={MATCH_FIELDS.map((value) => ({ value, label: value }))}
              />
              <Select
                style={{ width: 118 }}
                value={row.operator}
                onChange={(value) =>
                  setConditions((prev) =>
                    prev.map((item) => (item.id === row.id ? { ...item, operator: value } : item)),
                  )
                }
                options={OPERATORS.map((value) => ({ value, label: value }))}
              />
              <Input
                style={{ width: 180 }}
                value={row.value}
                placeholder={t('policies.editor.condition.value')}
                onChange={(event) =>
                  setConditions((prev) =>
                    prev.map((item) => (item.id === row.id ? { ...item, value: event.target.value } : item)),
                  )
                }
              />
              <Button
                disabled={busy || !canWrite}
                size="small"
                danger
                type="text"
                onClick={() => setConditions((prev) => prev.filter((item) => item.id !== row.id))}
              >
                {t('common.delete')}
              </Button>
            </Space>
          ))}
          <Space>
            <Button
              disabled={busy || !canWrite}
              size="small"
              icon={<PlusOutlined />}
              onClick={() =>
                setConditions((prev) => [
                  ...prev,
                  { id: `c${prev.length + 1}-${Date.now()}`, field: 'request.tool', operator: '==', value: '' },
                ])
              }
            >
              {t('policies.editor.addCondition')}
            </Button>
            <Button size="small" disabled={busy || !canWrite} icon={<CodeOutlined />} onClick={onSyncToCode}>
              {t('policies.editor.synced')}
            </Button>
          </Space>
        </Space>
      </div>

      <div>
        <div className="agf-drawer-section__title">{t('policies.editor.preview')}</div>
        <pre className="agf-code agf-code--compact">{previewOption}</pre>
      </div>
    </Space>
  );

  const codeBody = (
    <Space direction="vertical" size={10} style={{ width: '100%' }}>
      <Space size={10} wrap>
        <Radio.Group
          value={language}
          onChange={(event) => {
            const next = event.target.value as 'rego' | 'cel' | 'structured';
            setLanguage(next);
            setValidation(null);
          }}
          optionType="button"
          buttonStyle="solid"
          options={[
            { value: 'rego', label: 'Rego' },
            { value: 'cel', label: 'CEL' },
            { value: 'structured', label: 'JSON' },
          ]}
        />
        <Button
          disabled={busy || !canWrite}
          icon={<SafetyCertificateOutlined />}
          onClick={() => setValidation(validatePolicyCode(code, language))}
        >
          {t('policies.editor.validate')}
        </Button>
        <Button
          disabled={busy || !canWrite}
          icon={<CodeOutlined />}
          onClick={() => {
            try { setCode(composePolicyCode(language, action, conditions)); setValidation(null); }
            catch (error) { if (error instanceof Error) message.error(error.message); }
          }}
        >
          {t('policies.editor.mode.form')} → {t('policies.editor.codeLanguage')}
        </Button>
      </Space>

      <Input.TextArea
        value={code}
        onChange={(event) => {
          setCode(event.target.value);
          setValidation(null);
        }}
        autoSize={{ minRows: 14, maxRows: 22 }}
        spellCheck={false}
        style={{ fontFamily: "'JetBrains Mono', Consolas, monospace", fontSize: 12 }}
        aria-label={t('policies.editor.mode.code')}
      />

      {validation ? (
        <Typography.Text type={validation.ok ? 'success' : 'danger'}>
          {validation.ok
            ? t('policies.editor.codeValid')
            : t('policies.editor.codeInvalid', { reason: validation.reason ?? '' })}
        </Typography.Text>
      ) : null}
    </Space>
  );

  return (
    <Drawer
      width={760}
      open={open}
      onClose={() => { if (!busy) onClose(); }}
      closable={!busy}
      maskClosable={!busy}
      keyboard={!busy}
      title={editing ? `${t('policies.editor.title')} · ${editing.name}` : t('policies.editor.title')}
      destroyOnClose
      extra={
        <Button
          type="primary"
          aria-label={t('common.save')}
          icon={<SaveOutlined />}
          loading={busy}
          disabled={busy || !canWrite || !knownAction || (!!editing && !knownVersion)}
          onClick={() => void save()}
        >
          {t('common.save')}
        </Button>
      }
    >
      <Space direction="vertical" size={12} style={{ width: '100%', marginBottom: 16 }}>
        <Alert showIcon type="info" message={text('启用后保存会在平台后续实际请求中生效；不表示云 MSE/API 网关或外部调用方已热加载。',
          'Saving an enabled policy affects subsequent actual platform requests; it does not prove cloud MSE/API gateways or external consumers reloaded it.')} />
        {editing && <Typography.Text>{text(`保存基于版本 v${editing.version ?? '未知'}`, `Save uses revision v${editing.version ?? 'unknown'}`)}</Typography.Text>}
        {!knownAction && <Alert showIcon type="warning" message={text(
          `服务端动作 ${editing?.rawAction ?? action} 当前无法编辑；发布已阻止，请核对服务端与客户端版本。`,
          `Server action ${editing?.rawAction ?? action} cannot be edited by this client; publication is blocked. Verify the server and client versions.`,
        )} />}
        {operation.error && <Alert showIcon type="error" message={operation.error} description={operation.conflict ? text(editing
          ? '版本已变更。草稿仍未保存；先读取最新版本比较，不会自动换版本或重发。'
          : '名称已存在。草稿保留；新建不会覆盖，请改用新名称或从列表打开已有策略。', editing
          ? 'The revision changed. Your draft is unsaved; compare the latest revision. Revisions and requests never change automatically.'
          : 'This name exists. The draft remains; creation never overwrites it. Choose a new name or open the existing policy from the list.') : undefined} />}
        {editing && <Button disabled={busy} onClick={() => void operation.run(async isCurrent => {
          setLatest(undefined);
          const id = editing.id; const result = await policiesApi.get(id);
          if (isCurrent() && result.data.id === id) setLatest(result.data);
        })}>{text('读取最新版本并比较', 'Load latest revision to compare')}</Button>}
        {latest && comparison && <PolicyVersionComparison draft={comparison.draft} draftError={comparison.error}
          latest={latest} busy={busy} canAdopt={canWrite || canDelete}
          onAdopt={() => { if (!busy && operation.isCurrent() && latest.id === editing?.id && isPolicyAction(latest.action)) onAdopt(latest); }} />}
        {editing && canDelete && <Popconfirm title={text(`删除策略 ${editing.name}？`, `Delete policy ${editing.name}?`)}
          description={text(`仅在当前版本仍为 ${editing.version ?? '未知'} 时删除平台策略；不删除外部云配置。`,
            `Remove the platform policy only if its revision is still ${editing.version ?? 'unknown'}; external cloud configuration is unchanged.`)}
          okText={text('确认删除策略', 'Confirm policy deletion')} onConfirm={() => operation.run(async isCurrent => {
            if (!knownVersion || !canDelete) return;
            const id = editing.id, version = editing.version!; await policiesApi.delete(id, version);
            if (isCurrent()) { message.success(text('平台策略已删除', 'Platform policy deleted')); onSaved(); }
          })}>
          <Button danger disabled={busy || !knownVersion}>{text('删除当前策略', 'Delete current policy')}</Button>
        </Popconfirm>}
      </Space>
      <Form<Policy> form={form} layout="vertical" disabled={busy || !canWrite}>
        <Radio.Group
          value={mode}
          onChange={(event) => { setMode(event.target.value as 'form' | 'code'); if (event.target.value === 'form' && language === 'structured') setLanguage('cel'); }}
          optionType="button"
          buttonStyle="solid"
          style={{ marginBottom: 14 }}
          options={[
            { value: 'form', label: t('policies.editor.mode.form') },
            { value: 'code', label: t('policies.editor.mode.code') },
          ]}
        />
        {metadata}
        {mode === 'form' ? formBody : codeBody}
      </Form>
    </Drawer>
  );
}
