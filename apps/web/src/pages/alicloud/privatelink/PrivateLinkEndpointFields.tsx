import { Form, Input } from 'antd';
import { usePrivateLinkText } from './usePrivateLinkText';

/** Configuration uses an existing cloud endpoint; inventory never creates it. */
export default function PrivateLinkEndpointFields() {
  const text = usePrivateLinkText();
  return <Form.Item name={['settings', 'endpoint_id']} label={text('已有 PrivateLink 端点 ID', 'Existing PrivateLink endpoint ID')}
    extra={text('在对应地域的云控制台复制已有 EndpointId。盘点不会创建端点，未填写不会自动选择。',
      'Copy an existing EndpointId from the cloud console in this region. Inventory does not create or automatically select an endpoint.')}
    rules={[{ required: true, whitespace: true }]}><Input placeholder="ep-..." /></Form.Item>;
}
