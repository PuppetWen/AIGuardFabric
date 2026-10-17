import { Form, Input, InputNumber, Select, Switch } from 'antd';
import { useTranslation } from 'react-i18next';
import type { GatewayEndpoint } from '@/api/gateway';
import type { SemanticSettings } from '@/api/semanticCacheProfile';
import { toMicroCurrency } from './validation';

export function SemanticProfileFields({ settings: s, endpoints, disabled, update }: {
  settings: SemanticSettings; endpoints: GatewayEndpoint[]; disabled: boolean;
  update: (patch: Partial<SemanticSettings>) => void;
}) {
  const zh = useTranslation().i18n.language.startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  const options = endpoints.map(endpoint => ({ value: endpoint.id,
    label: `${endpoint.name} · ${endpoint.provider} / ${endpoint.model}${endpoint.enabled ? '' : text('（已停用）', ' (disabled)')}`,
    disabled: !endpoint.enabled || (s.mode === 'mock_vector' ? endpoint.provider !== 'mock'
      : !['openai', 'custom-openai-compat'].includes(endpoint.provider) || !endpoint.credentialConfigured),
  }));
  const selectEndpoint = (kind: 'chat' | 'embedding', id: string) => {
    const endpoint = endpoints.find(row => row.id === id);
    if (endpoint) update(kind === 'chat' ? { chat_endpoint_id: id, chat_model: endpoint.model }
      : { embedding_endpoint_id: id, embedding_model: endpoint.model });
  };
  const number = (key: 'dimensions' | 'max_input_tokens' | 'ttl_seconds', value: number | null) => {
    if (value !== null) update({ [key]: value });
  };
  return <Form layout="vertical" disabled={disabled}>
    <Form.Item label={text('运行方式', 'Mode')}>
      <Select aria-label={text('运行方式', 'Mode')} value={s.mode}
        options={[{ value: 'mock_vector', label: text('本地模拟向量（零厂商费用）', 'Local mock vectors (zero provider cost)') },
          { value: 'live', label: text('真实向量服务（消耗厂商额度）', 'Live embeddings (uses provider quota)') }]}
        onChange={mode => update({ mode, ...(mode === 'mock_vector' ? { embedding_micro_per_1k: 0 } : {}) })} />
    </Form.Item>
    <Form.Item label={text('聊天端点', 'Chat endpoint')}>
      <Select aria-label={text('聊天端点', 'Chat endpoint')} value={s.chat_endpoint_id || undefined}
        options={options} onChange={id => selectEndpoint('chat', id)} placeholder={text('选择已配置的端点', 'Select a configured endpoint')} />
    </Form.Item>
    <Form.Item label={text('聊天模型 ID（来自所选端点）', 'Chat model ID (from selected endpoint)')}><Input readOnly value={s.chat_model} /></Form.Item>
    <Form.Item label={text('聊天模型版本标签', 'Chat model revision label')}
      extra={text('由管理员固定的版本标签；不证明厂商模型权重版本。', 'An operator-pinned label; it does not verify provider weight revisions.')}>
      <Input aria-label={text('聊天模型版本标签', 'Chat model revision label')} maxLength={128}
        value={s.chat_model_revision} onChange={event => update({ chat_model_revision: event.target.value })} />
    </Form.Item>
    <Form.Item label={text('向量端点', 'Embedding endpoint')}>
      <Select aria-label={text('向量端点', 'Embedding endpoint')} value={s.embedding_endpoint_id || undefined}
        options={options} onChange={id => selectEndpoint('embedding', id)} placeholder={text('选择已配置的向量模型端点', 'Select a configured embedding endpoint')} />
    </Form.Item>
    <Form.Item label={text('向量模型 ID（来自所选端点）', 'Embedding model ID (from selected endpoint)')}><Input readOnly value={s.embedding_model} /></Form.Item>
    <Form.Item label={text('向量模型版本标签', 'Embedding model revision label')}>
      <Input aria-label={text('向量模型版本标签', 'Embedding model revision label')} maxLength={128}
        value={s.embedding_model_revision} onChange={event => update({ embedding_model_revision: event.target.value })} />
    </Form.Item>
    <Form.Item label={text('向量维度', 'Vector dimensions')}
      extra={text('须与服务实际返回维度一致；更换维度或版本后缓存隔离。', 'Must match the actual response dimensions. A changed dimension or revision uses a separate cache domain.')}>
      <InputNumber aria-label={text('向量维度', 'Vector dimensions')} min={1} max={4096} precision={0}
        value={s.dimensions} onChange={value => number('dimensions', value)} />
    </Form.Item>
    <Form.Item label={text('请求中发送 dimensions 参数', 'Send dimensions in the request')}
      extra={text('仅在厂商模型支持该参数时开启。', 'Enable only if the provider model supports this parameter.')}>
      <Switch checked={s.send_dimensions} onChange={send_dimensions => update({ send_dimensions })} />
    </Form.Item>
    <Form.Item label={text('向量输入 Token 预留上限', 'Embedding input token reservation limit')}>
      <InputNumber min={1} max={8192} precision={0} value={s.max_input_tokens} onChange={value => number('max_input_tokens', value)} />
    </Form.Item>
    <Form.Item label={text('向量输入单价（元 / 千 Token）', 'Embedding input price (CNY / 1000 tokens)')}
      extra={text('真实调用必须填写正单价；模拟固定为零。命中聊天缓存仍可能产生向量费用。',
        'Live mode requires a positive price; mock mode uses zero. A chat cache hit can still incur embedding cost.')}>
      <InputNumber disabled={disabled || s.mode === 'mock_vector'} min={0} precision={6} step={0.000001}
        value={s.embedding_micro_per_1k / 1000000} onChange={value => {
          const micro = toMicroCurrency(value); if (micro !== undefined) update({ embedding_micro_per_1k: micro });
        }} />
    </Form.Item>
    <Form.Item label={text('最低相似度（%）', 'Minimum similarity (%)')}>
      <InputNumber min={90} max={100} precision={4} step={0.1} value={s.threshold_ppm / 10000}
        onChange={value => { if (value !== null) update({ threshold_ppm: Math.round(value * 10000) }); }} />
    </Form.Item>
    <Form.Item label={text('缓存有效期（秒）', 'Cache lifetime (seconds)')}>
      <InputNumber min={1} max={900} precision={0} value={s.ttl_seconds} onChange={value => number('ttl_seconds', value)} />
    </Form.Item>
    <Form.Item label={text('最低数据分级', 'Minimum data classification')}
      extra={text('真实向量服务仅允许已核验为公开的 Agent 数据；内部分级不通过公网向量服务发送。',
        'Live embeddings require a verified public Agent classification. Internal data is not sent to a public embedding service.')}>
      <Select value={s.classification_floor} options={[{ value: 'internal', label: text('内部', 'Internal') },
        { value: 'public', label: text('公开', 'Public') }]} onChange={classification_floor => update({ classification_floor })} />
    </Form.Item>
  </Form>;
}
