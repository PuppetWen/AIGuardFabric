import { Alert, Typography } from 'antd';
import { usePublicationText } from './text';
const mockTarget = JSON.stringify({ engine_origin: 'https://mse-agf-demo.invalid', region_id: 'cn-hangzhou',
  instance_id: 'inst-demo', namespace_id: '', config_group: 'AGF', config_data_id: 'agf-policies.json', config_dialect: 'nacos-http-v2-cas' }, null, 2);
export default function PublicationGuide() {
  const text = usePublicationText();
  const steps: [string, string][] = [
    ['查看和明确只读观察需 alicloud:read、policies:read；准备、发送、本地恢复及归档还需 alicloud:write。不需要 assets:write。',
      'Viewing and explicit read-only observation require alicloud:read and policies:read. Preparation, sending, local recovery and archive also require alicloud:write. assets:write is not required.'],
    ['先在连接配置维护 MSE 凭据与账号来源。真实启用连接更换 engine origin 时，同次填写新地址及适用凭据，或先明确停用。保存会清旧 upsert 授权，再到目标绑定填写地域、实例、明确 namespace、Group、专用 JSON Data ID 并重新确认。旧 OpenAPI endpoint 不能代替 engine origin。',
      'Maintain MSE credentials and account source in Connection configuration. For a new engine origin on an enabled Live connection, save it with appropriate new credentials or explicitly disable first. Saving clears old upsert authorization; then configure region, instance, explicit namespace, group and dedicated JSON Data ID in Target binding and reconfirm. The OpenAPI endpoint is not the engine origin.'],
    ['默认 namespace 必须明确选择，会发送空字符串。指定 namespace 必须是真实 ID，不是 public 显示名。确认管理授权后按当前配置版本保存；目标或模式变化须重新确认。',
      'Explicitly select the default namespace to send an empty string. A specific namespace requires its actual ID, not the display name public. Confirm management and save using the current configuration revision; reconfirm after target or mode changes.'],
    ['明确读取当前云内容；Live 先勾选真实只读观察。观察 5 分钟有效。空内容是有效的 0 字节内容，不代表目标不存在。本地刷新 GET 不查询云。',
      'Explicitly read current cloud content; confirm a live read-only observation first for Live. Observations last five minutes. Empty content is valid zero-byte content, not evidence that the target is absent. Local GET refresh does not query the cloud.'],
    ['若没有可选政策，有 policies:write 权限的用户先到 /policies 新建独立名称，填写有效条件或代码并明确启用、手工保存；服务端验证并签名。隔离试用可选“告警 / Alert”（服务端 audit 动作）和 dry-run；启用策略保存影响平台后续实际请求，不代表消费者加载。再选择最多 20 个真实已启用、已签名的确切版本生成预览。服务端核完整依赖；Agent 聚合超过 500 拒绝而不截断，预览不提供云正文。',
      'If no policy is selectable, a user with policies:write first creates a unique name at /policies, supplies valid conditions or code, explicitly enables it and saves manually; the server validates and signs it. For isolated practice, use Alert (server action: audit) and dry-run. Saving enabled policies affects subsequent platform requests without proving consumer loading. Then select up to 20 actual enabled, signed revisions for preview. The server checks every dependency, rejecting aggregate Agent counts over 500 without truncation; raw cloud content is not exposed.'],
    ['核对目标、源版本、基线 MD5、SHA256 与字节。预览 120 秒有效。分别确认发布和 MD5 upsert；Live 另确认云写，再发送一次。MD5 只保护内容，观察后被删除的 Data ID 可能被重建。',
      'Review the target, source revisions, baseline MD5, SHA256 and bytes. Previews last 120 seconds. Confirm publication and MD5 upsert separately, plus a live cloud write for Live, then send once. MD5 protects content only; a Data ID deleted after observation may be recreated.'],
    ['409 保留政策选择、原基线和原编号。先读取原回执，再刷新本地状态比较；只有明确采用最新观察才能换草稿基线。政策变版须明确重新选择，不自动重发原预览。',
      'HTTP 409 retains policy selections, the original baseline and request ID. Read the original receipt, then refresh local state to compare. Only explicit adoption changes the draft baseline. Reselect changed policy revisions explicitly; never resend the original preview automatically.'],
    ['回执分为云写、回读、本地审计发布三阶段。只有 accepted、matched、published 且 complete 才验证成功。消费者加载始终未知；原来源过期不代表当前政策已生效。',
      'Receipts separate cloud write, readback and local audit publication. Verification requires accepted, matched, published and complete. Consumer loading is always unknown; completing an old source does not establish current-policy effectiveness.'],
    ['pending_audit 时明确本地恢复，仅提交已有加密证据与本地审计，不调用云端。配置停用或变版仍可读原回执、本地恢复和归档。用原 UUID 或 publication_request_id 页面参数恢复，参数不会自动查询。',
      'For pending_audit, explicitly recover the local state using existing encrypted evidence and audit without calling the cloud. Disabled or changed configuration still allows receipt reads, local recovery and archive. Restore using the original UUID or publication_request_id URL parameter; the parameter does not query automatically.'],
    ['未知云写即使当前内容 matched 也不是 accepted。先按服务端允许动作明确恢复未完成的旧本地事实。若接受旧远端请求可能迟到，再待旧租约到期后重新观察，开始和完成都须晚于到期，承认原未知编号，并在新预览中再次确认重叠风险。这是独立的新写，不是安全重试。没有假取消按钮。',
      'An unknown write is not accepted even when current content matches. First explicitly recover the incomplete old local fact when the server permits. If you accept that the old remote request may finish late, wait for its lease to expire, obtain an observation that starts and finishes after expiry, acknowledge the old ID, and confirm overlap risk again in the new preview. This is an independent new write, not a safe retry. There is no pretend cancellation.'],
    ['可信历史可准备回滚：只选择服务端 verified/published 且保有正文的同目标来源，经新观察、新预览、新 UUID 发布；不降平台注册表版本。归档会移除此条回滚正文，明确确认数量和损失后才执行；永久编号与未知风险仍保留。',
      'Trusted history can prepare rollback only from server-verified/published same-target content that is retained. Publish with a new observation, preview and UUID without lowering registry revisions. Archive removes that record’s rollback content; confirm its count and loss explicitly. Permanent IDs and unknown-risk facts remain.'],
  ];
  return <>
    <Alert type="warning" showIcon message={text('阶段一已提供持久 Mock 与授权 loopback 测试；Live 协议、RAM、网络及消费者加载须独立验收。', 'Stage one provides persistent Mock and authorized loopback testing; Live protocol, RAM, networking and consumer loading require separate acceptance.')} />
    <Typography.Title level={5}>{text('隔离 Mock 示例（不代表实云目标）', 'Isolated Mock example (not a real cloud target)')}</Typography.Title>
    <Typography.Paragraph>{text('Mock 仅支持下面固定目标。请在隔离环境手动启用连接、勾选 Mock、填入字段，明确选择默认 namespace，再确认管理 upsert 并保存。示例不会自动填表、创建数据或请求；首次明确观察才初始化隔离 Mock 内容。真实云请使用自己的目标，不要复制示例地址。',
      'Mock supports only the fixed target below. In an isolated environment, manually enable the connection, select Mock, enter these fields, explicitly select the default namespace, reconfirm managed upsert and save. This example never fills forms, creates records or requests automatically; the first explicit observation initializes isolated Mock content. For Live, use your own target instead of this example origin.')}</Typography.Paragraph>
    <Typography.Paragraph copyable={{ text: mockTarget }} style={{ whiteSpace: 'pre-wrap' }}>{mockTarget}</Typography.Paragraph>
    {steps.map(([cn, en], index) => <Typography.Paragraph key={index}>{index + 1}. {text(cn, en)}</Typography.Paragraph>)}
    <Typography.Paragraph>{text('配置数据库后原事实跨实例持久；无数据库模式仅当前进程，不能承诺重启后幂等。无自动补传、云正文编辑、云删除或消费者热加载功能。',
      'With a configured database, original facts persist across instances. Without a database they exist only in the current process, without a restart idempotency guarantee. Automatic replay, raw cloud-content editing, cloud deletion and consumer hot loading are not provided.')}</Typography.Paragraph>
  </>;
}
