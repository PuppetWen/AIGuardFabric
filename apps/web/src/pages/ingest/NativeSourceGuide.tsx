import { Alert, Space, Typography } from 'antd';
import type { LogSource } from '@/types/domain';
import { useTranslation } from 'react-i18next';

import { nativeCompose } from './nativeSourceConfig';

export function NativeSourceGuide({ source, tenant }: { source: LogSource; tenant: string }) {
  const config = nativeCompose(source, tenant);
  const { i18n } = useTranslation();
  const text = (zh: string, en: string) => i18n.language.startsWith('zh') ? zh : en;
  return <Space direction="vertical" size={16} style={{ width: '100%' }}>
    <Alert type="info" showIcon message={text('原生接收器：', 'Native receiver: ') + source.nativeReceiver}
      description={text('配置与日志属于上方选定的租户。每个接收器进程固定归属一个租户；多个组织分别部署采集实例，并使用不同的实例名、监听端口和持久目录。',
        'Configuration and logs belong to the selected tenant. Each receiver process serves one tenant. Deploy separate instances, ports and persistent directories for different organizations.')} />
    <Alert type={source.requireMtls ? 'warning' : 'info'} showIcon
      message={text('当前来源限制', 'Current source restrictions')}
      description={<>
        <div>{text('允许的连接 IP：', 'Allowed connection IPs: ')}{source.allowedCidrs?.length ? source.allowedCidrs.join(', ') : text('未限制', 'Unrestricted')}</div>
        <div>{text('客户端证书：', 'Client certificate: ')}{source.requireMtls ? text('必须验证通过', 'Verification required') : text('由监听器配置决定', 'Determined by listener configuration')}</div>
        <div>{text('白名单使用实际连接 IP；代理和容器 NAT 可能改变来源地址。源配置立即生效。mTLS 需先配置 CA 和证书挂载，详见 docs/native-source-security-guide.md。',
          'The allowlist uses the direct connection IP; proxies and container NAT can change it. Source policy takes effect immediately. Configure and mount CA/certificates first for mTLS; see docs/native-source-security-guide.md.')}</div>
      </>} />
    <Typography.Paragraph>{text('1. 在部署项目中新建 docker-compose.native.yml，复制以下内容。已有配置请合并；AGF_INGEST_SOURCE_IDS 是完整映射，须保留同一实例的其他源绑定。',
      '1. Create docker-compose.native.yml in your deployment project and copy the configuration below. Merge existing settings; AGF_INGEST_SOURCE_IDS must retain all other source bindings in this instance.')}</Typography.Paragraph>
    <Typography.Paragraph copyable={{ text: config }}><pre style={{ whiteSpace: 'pre-wrap' }}>{config}</pre></Typography.Paragraph>
    <Typography.Paragraph>{text('2. 在项目 .env 中填写上述协议变量。凭据只保存在部署主机，控制台不回显。证书、游标和对象存储配置见项目 docs/native-ingest-guide.md；额外监听端口需要明确添加到 Compose ports，并限制来源网络。',
      '2. Fill in the protocol variables in the project .env. Keep credentials on the deployment host. See docs/native-ingest-guide.md for certificates, cursors and object storage. Add required listener ports to Compose and restrict source networks.')}</Typography.Paragraph>
    <Typography.Paragraph copyable><code>docker compose -f docker-compose.yml -f docker-compose.native.yml up -d --no-deps agf-ingest</code></Typography.Paragraph>
    <Typography.Paragraph>{text('3. 向对应接收器发送测试记录。检查接收器 /readyz 的 sink=sql 和实际监听地址，再刷新本页查看累计保存、解析命中和最近错误。未匹配的原文可以回放。',
      '3. Send a test record to the receiver. Verify sink=sql and listener addresses in /readyz, then refresh saved counts, parser matches and recent errors here. Unmatched raw records can be replayed.')}</Typography.Paragraph>
    <Typography.Paragraph>{text('4. 在检测规则中启用适用规则并通过正负样本校验；新事件命中后，会自动出现在风险发现和告警中心。在系统设置中启用通知渠道。顶部事件分析计数用于检查处理进度。',
      '4. Enable suitable detection rules and validate their positive and negative samples. Matching new events appear automatically in Findings and Alerts. Enable notification channels in Settings and check the analysis counters for progress.')}</Typography.Paragraph>
    <Alert type="warning" showIcon message={text('启停与删除的实际效果', 'Pausing and deleting sources')}
      description={text('停用源或所属租户后，采集流水线拒绝后续数据；已开始处理的一批可能完成。无确认机制的 UDP/SNMP 数据会丢弃，发送端应先暂停。删除会保留历史日志，旧 ID 在重启后仍不能自动恢复，需要新建源并重新绑定。',
        'Disabling a source or tenant rejects subsequent records; an in-flight batch may finish. Pause UDP/SNMP senders first because these protocols cannot confirm rejection. Deleting a source preserves history and its tombstone; create a new source and update the binding to resume.')}/>
  </Space>;
}
