import { Form, InputNumber, Typography } from 'antd';
import { useTranslation } from 'react-i18next';

export function GatewayPricingFields() {
  const zh = useTranslation().i18n.language.startsWith('zh');
  return <>
    <Typography.Paragraph type="secondary">{zh
      ? '单价单位：CNY 元 / 1K Token，最多 6 位小数。零值仅表示估算为零，请按供应商价格自行核对并换算币种。'
      : 'Prices: CNY per 1K tokens, up to 6 decimals. Zero only means a zero estimate; verify provider prices and convert currencies before entering them.'}</Typography.Paragraph>
    {(['inputPriceCny', 'outputPriceCny', 'cachedPriceCny'] as const).map((name, i) =>
      <Form.Item key={name} name={name} label={(zh ? ['输入单价', '输出单价', '缓存输入单价']
        : ['Input price', 'Output price', 'Cached input price'])[i] + ' (CNY / 1K Token)'}
        rules={[{ required: true, type: 'number', min: 0, max: 1000000 }]}>
        <InputNumber min={0} max={1000000} precision={6} step={0.000001} style={{ width: '100%' }} />
      </Form.Item>)}
  </>;
}
