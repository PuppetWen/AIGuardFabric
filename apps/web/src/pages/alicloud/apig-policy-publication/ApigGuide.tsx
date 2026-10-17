import { Alert, List, Space, Typography } from 'antd';
import { useApigText } from './text';

export default function ApigGuide() {
  const text = useApigText();
  const steps = [
    text('企业按业务租户、云账号和地域分别配置；个人可用一个租户先走受控 Mock。账号/凭据在连接配置维护，平台 Key、回调 token 和 RAM 凭据不能互换。',
      'Enterprises configure each business tenant, cloud account and region separately. Individuals can start with owned Mock in one tenant. Maintain cloud credentials in Connection configuration; platform keys, callback tokens and RAM credentials are distinct.'),
    text('在“既有五 ID 绑定”填写真实 Model API、Gateway、Environment、独立 policy 和 attachment ID，核对来源与模式并明确确认。保存只做配置 CAS，不创建策略、部署或挂载。',
      'In Existing five-ID binding, enter the actual Model API, Gateway, Environment, independent policy and attachment IDs. Verify source and mode, then confirm. Saving uses configuration CAS and creates no policy, deployment or attachment.'),
    text('受控 Mock 示例：cn-hangzhou / api-agf-demo / gw-agf-demo / env-agf-demo / policy-agf-demo / attachment-agf-demo；不是实云目标。先明确 Mock，再填示例、确认并人工保存；之后勾选初始化且点击明确观察。GET 永不初始化。',
      'Owned Mock example: cn-hangzhou / api-agf-demo / gw-agf-demo / env-agf-demo / policy-agf-demo / attachment-agf-demo. These are not live targets. Explicitly choose Mock, fill the example, confirm and save manually, then consent to initialization and explicitly observe. GET never initializes it.'),
    text('准备配额：Tenant、Requests 或 Token、Minute、Deny、启用、1..2147483647 的整数额度、软阈值明确 0。复制真实配额 UUID；通用配额默认日窗口与80%软阈值不自动更改。',
      'Prepare an enabled Tenant quota for Requests or Tokens, Minute, Deny, an integer limit 1..2147483647 and explicit soft threshold 0. Copy its actual UUID; generic day-window and 80% soft-threshold defaults are not changed automatically.'),
    text('策略中心手工保存：Quota 动作，切到代码模式并选择 JSON（Structured），正文 {}，仅 AI gateway 拦截点、无条件/部门/Agent范围、关闭 dry-run、启用，并明确选关联配额。保存后等待服务端来源列表的实际 eligibility；其它动作/语言不能静默改写。',
      'Save manually in Policies: Quota action, code mode, JSON (Structured), body {}, only the AI gateway intercept point, no conditions, department or Agent scope, dry-run off, enabled and an explicitly linked quota. Use actual server eligibility afterward; other actions or languages are never silently rewritten.'),
    text('明确观察三个只读云接口，检查两类 slot 的真实阈值。Live 先勾选只读确认。选择服务端可投射的确切策略版本，再生成预览；预览不发送云写。分页/刷新保留原选择，最新基线须明确采用。',
      'Explicitly observe three read-only cloud APIs and inspect the actual thresholds. Live observation requires consent. Choose an exact server-eligible policy revision and prepare a preview without sending a cloud write. Paging/refresh retains selection; adopt a newer baseline explicitly.'),
    text('核对唯一 slot、原/新阈值、来源版本和 hash；分别确认平台与 API-global 周期差异、共享影响未知、无云 CAS，以及 Live/旧 Unknown 风险。点击发送一次新意图，保留原 UUID；失败不自动重复 POST。',
      'Review the single slot, previous/desired thresholds, source revisions and hashes. Separately confirm platform/API-global period differences, unknown shared impact, no cloud CAS and any Live/old Unknown risk. Send one new intent and retain its UUID; failure never repeats POST automatically.'),
    text('云 Accepted、独立回读 Matched、本地 Published 与消费者加载分别看。Unknown 不因后续观察匹配变成功；pending_audit 或过期 started 只明确本地恢复，再按新观察/承认旧编号/新预览准备新意图。',
      'Inspect cloud Accepted, separate readback Matched, local Published and consumer loading independently. Later matching observation does not upgrade Unknown. For pending_audit or expired started, recover locally first, then use a new observation, old-ID acknowledgement and a new preview for a separate intent.'),
    text('回滚仅取可信历史 previousThreshold 并保留当前其它配置；新观察、预览、确认和 UUID 都不可省。容量满时明确归档终态详情：永久事实与旧 UUID 可读，云配置不变，但这条回滚正文会丢失。',
      'Rollback uses only the trusted historical previous threshold while preserving other current configuration. A new observation, preview, confirmations and UUID are required. Explicitly archive terminal details when capacity is full: permanent facts and old UUIDs remain readable and cloud state is unchanged, but the rollback body is lost.'),
  ];
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Alert type="warning" message={text('首期只管理已有 AiTokenRateLimit 的唯一 Global RequestPerMinute 或 TokenPerMinute slot。',
      'The initial profile manages only an existing unique Global RequestPerMinute or TokenPerMinute slot in AiTokenRateLimit.')}
      description={text('已有配置需 enabled；非空 attachment 覆盖正文不可写。内容安全、模型路由、插件 Base64、任意 DSL 与整个云对象回滚不在此流程。',
        'Existing configuration must be enabled; nonempty attachment overrides cannot be written. Content safety, model routing, plugin Base64, arbitrary DSL and whole-object rollback are outside this workflow.')} />
    <List size="small" dataSource={steps} renderItem={(step, index) => <List.Item>{index + 1}. {step}</List.Item>} />
    <Typography.Paragraph>{text('查看需要 alicloud:read + policies:read；预览/发布/本地恢复/归档另需 alicloud:write。Mock 初始化也需 write；通用配额查看/配置、策略创建分别需 quotas:read/write 与 policies:write。',
      'Viewing requires alicloud:read + policies:read; preview, publication, local recovery and archive additionally require alicloud:write. Mock initialization also requires write. Generic quota inspection/editing and policy creation require quotas:read/write and policies:write respectively.')}</Typography.Paragraph>
    <Typography.Paragraph>{text('配置 PostgreSQL 才有跨实例、重启后的永久编号与审计事实；无数据库模式仅当前进程有效。环境变量用于部署；页面不会自动变更服务配置或外连。',
      'PostgreSQL configuration is required for permanent request/audit facts across instances and restarts; database-free mode lasts only for the current process. Deployment variables are maintained separately; this page never changes service deployment or contacts providers automatically.')}</Typography.Paragraph>
  </Space>;
}
