import { Alert, List, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { SchedulerCallbackPreparation } from './scheduler-registration/SchedulerCallbackPreparation';
import { SchedulerTaskMatrix } from './scheduler-registration/SchedulerTaskMatrix';

export function SchedulerGuide() {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh');
  const steps = zh ? [
    '个人或单机：保留 AGF_SCHEDULER_BACKEND=local-cron，按 UTC 本地日历运行，无需创建云任务。配置平台 API 地址、同租户服务 Key 和实际需要的任务目录/开关；数据库不可用时本地回执仅保留在进程内。',
    '企业云调度：先选择正确租户，在连接设置保存 SchedulerX3 区域、ClusterId、AppName 和云身份。保存这里只改变云 API 连接，不会部署调度器、注册六任务或替换部署环境变量。',
    '在云控制台选择实际 HTTP 应用，再用下面表单准备回调 URL。配置 HTTPS 反向代理转发到调度服务 9101，并从真实云执行器网络核查 TLS/连通性；不是主平台 API 的 8080 回调。',
    '部署管理员设置 AGF_SERVER_URL、AGF_SCHEDULER_TENANT_ID、AGF_SCHEDULER_API_KEY、32–256 字节独立 AGF_SCHEDULER_CALLBACK_TOKEN、实际 AGF_SCHEDULER_CALLBACK_APP_ID 和 schedulerx3 后端，配置数据库后重启。云 RAM/STS 管 Job、平台 Key 执行业务、callback token 验证回调，三者不能混用。',
    '在云控制台按实际 HTTP 执行器参数手工登记所选任务，分别配置日历、时区、依赖、超时与认证 header；云自动提供实际 AppId、JobId、JobExecutionId。此表单不给未验证的 CreateJob 模板，也不生成可用令牌。',
    '日志、红队、归档可以使用实际执行器支持的广播分片。汇总类用单实例；分片 index/total 必须成对、固定总数。云端须按下方依赖顺序触发；单次 HTTP 200 且 ok=true 才是此次 callback 成功。重复投递保留原执行编号，结果不确定时先核对回执和业务事实。',
    '在调度服务的 /tasks 查看实际后端、持久回执状态和最近执行结果。云任务创建成功只代表任务已登记，必须看到实际回调回执和业务产物后才能确认接入完成。',
  ] : [
    'For personal or single-host use, retain AGF_SCHEDULER_BACKEND=local-cron and UTC calendars; no cloud jobs are needed. Configure the platform API address, same-tenant service key and required directories/task flags. Without a database, local receipts survive only for the current process.',
    'For enterprise cloud scheduling, select the tenant and save SchedulerX3 region, ClusterId, AppName and cloud identity in Connection settings. Saving changes only the cloud API connection, not deployment variables or six-task registration.',
    'Choose the actual HTTP application in the cloud console, then prepare callback URLs below. Route an HTTPS reverse proxy to scheduler port 9101 and verify TLS/networking from the real cloud executor. The main platform API on port 8080 is a separate service.',
    'The deployment administrator sets AGF_SERVER_URL, AGF_SCHEDULER_TENANT_ID, AGF_SCHEDULER_API_KEY, a separate 32–256 byte AGF_SCHEDULER_CALLBACK_TOKEN, actual AGF_SCHEDULER_CALLBACK_APP_ID and schedulerx3 backend, configures a database and restarts. Cloud RAM/STS manages jobs, the platform key runs business operations, and the callback token authenticates callbacks.',
    'Register selected tasks manually in the cloud console using its actual HTTP executor controls. Configure calendars, timezone, dependencies, timeout and authentication headers. The cloud supplies actual AppId, JobId and JobExecutionId. This form provides no unverified CreateJob template or usable token.',
    'Use broadcast partitions for logs, red-team cases and archives only where the actual executor supports them. Summaries use one instance; partition index/total must be paired and totals fixed. Trigger cloud dependencies in the order below. HTTP 200 with ok=true proves this callback succeeded. Retain execution IDs for redeliveries and reconcile uncertain receipts/business facts first.',
    'Check /tasks for the effective backend, persistent receipt status and results. Registration alone does not prove execution; verify callback receipts and business artifacts.',
  ];
  return <>
    <Typography.Title level={4}>{zh ? '定时任务接入步骤' : 'Connect scheduled tasks'}</Typography.Title>
    <Typography.Paragraph><a href="/alicloud?tab=scheduler-native">{zh
      ? '观察实际云任务并保存本地关联（不会自动部署或注册云任务）'
      : 'Observe actual jobs and save local bindings (no automatic deployment or cloud registration)'}</a></Typography.Paragraph>
    <Typography.Paragraph><a href="/alicloud?tab=scheduler-managed">{zh
      ? '打开受管任务：预览修改、启停、原编号恢复与历史归档'
      : 'Open managed jobs: preview changes, enable/disable, original-ID recovery and history archive'}</a></Typography.Paragraph>
    <Alert type="info" showIcon message={zh ? '受管任务与实际部署分别核验' : 'Verify managed jobs and actual deployment separately'}
      description={zh ? '受管页支持六类停用 Mock 声明，以及已有 HTTP Job 的日历/重试修改和独立启停。Live 新建所需 HTTP 执行器载荷合同尚未验证，当前会拒绝创建；需先在实际云控制台登记。观察、保存关联、任务登记均不证明回调部署或业务执行成功。'
        : 'Managed jobs support six disabled Mock declarations and calendar/retry changes plus separate enable/disable for existing HTTP jobs. The Live HTTP creation payload contract remains unverified and creation is rejected; register it in the actual cloud console first. Observation, local binding and registration do not establish deployed callbacks or successful business execution.'} />
    <List size="small" dataSource={steps} renderItem={(step, index) => <List.Item>{index + 1}. {step}</List.Item>} />
    <Alert type="info" showIcon message={zh ? '当前执行器范围' : 'Current executor scope'} description={zh
      ? '下游要求上游最近批次全部分片成功（24 小时内）；本地会补跑，云端只等待。schedulerx3 只停止调度服务这六类本地周期，主服务 HTTP Pull 到期扫描、业务报表计划和每日资产快照仍独立运行；不是云日历接管全部自动任务。诊断 /tasks 不应直接暴露到公网，其 implemented 状态也不证明云登记。'
      : 'Dependencies require every shard of the latest upstream batch to succeed within 24 hours. Local timers fill missing work; cloud callbacks only wait. schedulerx3 stops these six local scheduler timers only. Main-service HTTP Pull scanning, business report plans and daily asset snapshots remain independent. Keep diagnostic /tasks off the public network; implemented does not prove cloud registration.'} />
    <SchedulerTaskMatrix />
    <SchedulerCallbackPreparation />
  </>;
}
