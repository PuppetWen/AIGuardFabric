import { Alert, Form, Input, Switch } from 'antd';
import { useTranslation } from 'react-i18next';
import { sourceTransportControls } from './nativeSourceConfig';

export function SourceTransportFields({ receiver }: { receiver: string }) {
  const { i18n } = useTranslation();
  const english = i18n.language?.startsWith('en') ?? false;
  const text = (zh: string, en: string) => english ? en : zh;
  const controls = sourceTransportControls(receiver);
  return <>
    {controls.cidrs ? <Form.Item name="allowedCidrsText" label={text('允许的来源网段（CIDR）', 'Allowed source networks (CIDR)')}
      extra={text('每行一个 IPv4/IPv6 网段，最多 64 个。留空允许所有来源。按直接连接 IP 校验，忽略转发头和日志内自报地址。',
        'One IPv4/IPv6 CIDR per line, up to 64. Empty allows all. Checked against the direct connection IP; forwarded headers and log fields are ignored.')}>
      <Input.TextArea rows={3} placeholder={'192.168.1.0/24\n2001:db8::/32'} />
    </Form.Item> : <Alert style={{ marginBottom: 12 }} showIcon type="info"
      message={text('在上游配置访问限制', 'Configure access controls upstream')}
      description={text('此接收器不提供直接发送端 IP/证书校验。消息代理、拉取 API 使用各自的网络白名单、账号与 TLS 配置。',
        'This receiver cannot verify the original sender IP or certificate. Configure network access, credentials and TLS at the broker or upstream API.')} />}
    {controls.mtls && <>
      <Form.Item name="requireMtls" valuePropName="checked" label={text('要求已验证的客户端证书', 'Require a verified client certificate')}>
        <Switch />
      </Form.Item>
      <Alert style={{ marginBottom: 12 }} showIcon type="warning"
        message={text('先配置接收器的客户端 CA，再启用此限制', 'Configure the receiver client CA before enabling this restriction')}
        description={text('Syslog TLS 使用 AGF_SYSLOG_TLS_CLIENT_CA；OTLP gRPC 使用 AGF_INGEST_OTLP_GRPC_TLS_CLIENT_CA。文件须挂载到采集容器。源设置立即生效，证书文件变更需重启接收器。',
          'Use AGF_SYSLOG_TLS_CLIENT_CA for Syslog TLS or AGF_INGEST_OTLP_GRPC_TLS_CLIENT_CA for OTLP gRPC. Mount the files in the collector. Source policy applies immediately; restart the receiver after changing certificate files.')} />
    </>}
  </>;
}
