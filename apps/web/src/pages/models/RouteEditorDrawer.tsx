import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { Alert, Button, Drawer, Form, Input, InputNumber, Popconfirm, Select, Switch, Typography, message } from 'antd';
import type { FormInstance } from 'antd';

import { api } from '@/api/client';
import { DataState } from '@/components/DataState';
import type { ModelRoutePolicy } from '@/types/domain';
import { useApiQuery } from '@/api/client';
import { gatewayApi } from '@/api/gateway';
import { ApiRequestError } from '@/api/transport';

import { ROUTE_STRATEGIES } from './models.data';

interface RouteEditorDrawerProps {
  open: boolean;
  canWrite: boolean;
  routeTarget: ModelRoutePolicy | null;
  form: FormInstance<ModelRoutePolicy>;
  onClose: () => void;
  onSaved: () => void;
}

/** Route-policy editor drawer. */
export function RouteEditorDrawer({
  open,
  canWrite,
  routeTarget,
  form,
  onClose,
  onSaved,
}: RouteEditorDrawerProps) {
  const { t, i18n } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [errorText, setErrorText] = useState('');
  const [conflict, setConflict] = useState(false);
  const zh = i18n.language.startsWith('zh');
  const strategy = Form.useWatch('strategy', form);
  const primary = Form.useWatch('primaryEndpointId', form);
  const fallbacks: string[] = Form.useWatch('fallbackEndpointIds', form) ?? [];
  const selectedIds = [...new Set([primary, ...fallbacks].filter((id): id is string => Boolean(id)))];
  const configured = useApiQuery('gateway-configuration', gatewayApi.list);
  const endpoints = configured.data?.data.items ?? [];

  const save = async () => {
    if (!canWrite || busy || conflict) return;
    setBusy(true);
    setErrorText('');
    try {
      const values = await form.validateFields();
      await api.saveRoutePolicy({ ...values, id: routeTarget?.id || undefined,
        expectedVersion: routeTarget?.version ?? 0 });
      message.success(t('models.route.saved'));
      onSaved();
    } catch (error) {
      setConflict(error instanceof ApiRequestError && error.status === 409);
      if (error instanceof Error) setErrorText(error.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Drawer
      width={520}
      open={open}
      onClose={() => { if (!busy) onClose(); }}
      title={t('models.route.edit')}
      destroyOnClose
      extra={
        <Button
          type="primary"
          disabled={!canWrite || conflict} loading={busy}
          onClick={() => void save()}
        >
          {t('common.save')}
        </Button>
      }
    >
      <DataState loading={configured.isLoading} error={configured.error}>
      {errorText && <Alert type="error" showIcon message={errorText} style={{ marginBottom: 16 }}
        description={conflict
          ? (zh ? '草稿已保留。请先复制要保留的修改，再确认加载最新路由。' : 'Your draft is retained. Copy changes you need before loading the latest route.')
          : (zh ? '草稿已保留，修正后可再次保存。' : 'Your draft is retained. Correct it and save again.')} />}
      {conflict && <Popconfirm title={zh ? '丢弃当前草稿并加载最新路由？' : 'Discard this draft and load the latest route?'}
        onConfirm={onSaved}><Button style={{ marginBottom: 12 }}>
          {zh ? '加载最新路由' : 'Load latest route'}</Button></Popconfirm>}
      <Form<ModelRoutePolicy> name="model-route" disabled={!canWrite || busy} form={form} layout="vertical" initialValues={routeTarget ?? undefined}>
        <Form.Item name="name" label={t('models.route.name')} rules={[{ required: true, whitespace: true }]}>
          <Input maxLength={128} />
        </Form.Item>
        <Form.Item name="strategy" label={t('models.route.strategy')}>
          <Select
            options={ROUTE_STRATEGIES.map((value) => ({
              value,
              label: t(`models.route.strategy.${value}`),
            }))}
          />
        </Form.Item>
        <Form.Item name="primaryEndpointId" label={t('models.route.primary')} rules={[{ required: true }]}>
          <Select
            options={endpoints.map((endpoint) => ({
              value: endpoint.id,
              label: `${endpoint.model} · ${endpoint.id}`,
            }))}
          />
        </Form.Item>
        <Form.Item name="fallbackEndpointIds" label={t('models.route.fallbacks')}>
          <Select
            mode="multiple"
            options={endpoints
              .filter((endpoint) => endpoint.enabled)
              .map((endpoint) => ({ value: endpoint.id, label: endpoint.model }))}
          />
        </Form.Item>
        {strategy === 'weighted' && selectedIds.map(id => <Form.Item key={id} name={['weights', id]}
          label={`${zh ? '权重' : 'Weight'} · ${endpoints.find(endpoint => endpoint.id === id)?.name ?? id}`}
          initialValue={routeTarget?.weights[id] ?? 1} rules={[{ required: true, type: 'number', min: 0, max: 1000000 }]}>
          <InputNumber min={0} max={1000000} style={{ width: '100%' }} />
        </Form.Item>)}
        <Form.Item name="budgetCnyPerDay" label={t('models.route.budget')} rules={[{ required: true }]}>
          <InputNumber min={0} max={1000000} step={0.01} style={{ width: '100%' }} />
        </Form.Item>
        <Form.Item name="enabled" label={t('common.enabled')} valuePropName="checked">
          <Switch />
        </Form.Item>
        <Typography.Paragraph className="agf-tertiary" style={{ fontSize: 12 }}>
          {zh ? '日预算单位为 CNY 元，0 表示不限；下一次使用该路由的调用生效。' : 'Daily budget is in CNY; 0 means unlimited. It applies to the next call using this route.'}
        </Typography.Paragraph>
      </Form></DataState>
    </Drawer>
  );
}
