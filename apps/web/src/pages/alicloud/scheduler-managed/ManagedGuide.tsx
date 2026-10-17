import { Alert, Space, Table, Typography } from 'antd';
import { SCHEDULER_TASKS } from '../scheduler-registration/tasks';
import { useText } from './text';
export function ManagedGuide() {
  const t = useText();
  const steps: [string, string][] = [
    ['1. 在云连接设置手工保存并启用 SchedulerX3 来源 region_id、cluster_id、app_name、RPC 根地址和模式。account_id 只是未验证标签；真实云凭据在连接设置管理，不填写在任务表单。',
      '1. Manually save and enable a SchedulerX3 source in cloud connections: region_id, cluster_id, app_name, RPC root origin and mode. account_id is an unverified label; manage live credentials in connection settings, never in this job form.'],
    ['隔离 Mock 示例：cn-hangzhou / cluster-agf-demo / app-agf-demo。手工保存后明确初始化，再完整观察；不会自动填来源、种数据或请求云。原示例并非六任务都启用；此处可逐类创建停用声明，total 固定为 1。',
      'Isolated Mock example: cn-hangzhou / cluster-agf-demo / app-agf-demo. Save it manually, explicitly initialize, then observe completely; the page never autofills sources, seeds on GET or requests cloud automatically. The original fixture does not enable all six tasks; create disabled declarations per kind here, with total fixed to 1.'],
    ['2. 显式提交新编号的完整观察，失败读取本次原编号。Live 需确认真实云只读请求。原回执和分页只 GET，Job ID 始终是 int64 字符串；跨页选择保留，但换观察后需重新核实任务。',
      '2. Submit a complete observation with a new ID explicitly; read that original ID after failure. Live reads require confirmation. Receipt/paging use GET only and Job IDs remain int64 strings. Cross-page choices persist, while a new observation requires verifying the selected job again.'],
    ['3. 在完成后 300 秒内明确采用观察及当前绑定版本。选择六类任务之一。Mock 新建必须明确名称、时间类型/表达式、时区和重试，创建后仍停用；Live 没有可信 HTTP carrier 新建合同，严格拒绝。',
      '3. Explicitly adopt the observation/current binding revision within 300 seconds of completion and choose one of six kinds. Mock creation requires an explicit name, time type/expression, timezone and retry settings and remains disabled. Live HTTP carrier creation lacks a trusted contract and is strictly rejected.'],
    ['4. 修改已有 HTTP Job 只设置勾选的日历/重试字段，未勾选原样保留，明确空日历表示清空。启用中的 Job 必须先用独立意图停用，重新完整观察后再修改；启用也是另一个意图，绝不顺带执行。',
      '4. Update only checked calendar/retry fields on an existing HTTP job; unchecked fields remain unchanged and an explicit empty calendar clears it. Disable an enabled job in a separate intent, observe completely again, then update. Enable is another separate intent and is never implicit.'],
    ['5. 预览旧值与新值，确认无云 CAS、回调未强制执行/部署消费者未知，并按需确认 Live 或旧 Unknown 重叠。每个预览只尝试一次新请求；回包丢失、408/5xx 或不可信响应时锁住原意图，GET 原编号，404 也不能解锁重发。',
      '5. Review old/new values, confirm no cloud CAS and unenforced callbacks/unknown deployment and consumers, plus Live or older Unknown overlap when applicable. Attempt each preview once. Lost responses, 408/5xx or invalid replies lock the original intent; GET its ID, and even 404 never unlocks redispatch.'],
    ['6. Accepted 与独立读回 Matched 分开；Unknown 不因后来匹配升级。pending_audit 或过期 started 可以按服务端允许显式恢复本地终态/审计，不调用 provider。旧 Unknown 必须先本地结束，租约后新观察并独立确认新写风险；改变账号标签或端点不能避开围栏。',
      '6. Accepted and an independent Matched readback are separate; a later match never upgrades Unknown. Server-permitted pending_audit or expired started facts can be explicitly recovered locally without provider calls. End the old local fact, observe after its lease and separately confirm new-write risk; changing account labels/endpoints cannot bypass that fence.'],
    ['7. 创建/启用不等于绑定、部署或业务执行。去原生观察与关联页重新观察、人工采用并保存真实 Job 与六类 callback 的关系；资格被撤销后，即使重新启用也不会自动恢复。300 秒仅采用窗口，不是已保存绑定运行 TTL。',
      '7. Creation/enable is separate from binding, deployment and business execution. Use the native observation/association page to observe again and explicitly adopt/save actual jobs for the six callbacks. Revoked qualification never restores automatically after enable. The 300 seconds are an adoption window, not a saved binding runtime TTL.'],
    ['8. 企业部署由管理员核实真实租户 UUID、AppID、服务身份、独立 callback token 的 Secret 引用、可达 HTTPS 入口及各任务配置；个人单机分别运行 API/scheduler。默认 total=1；K8s 广播/分片不得靠此声明声称部署完成。当前生产 local-cron 与云 callback 分开验收。',
      '8. Enterprise administrators verify the actual tenant UUID, AppID, service identity, independent callback-token secret reference, reachable HTTPS ingress and per-task configuration. Personal installs run API/scheduler separately. total defaults to 1; this declaration never verifies K8s broadcast/shard deployment. Validate current production local-cron separately from cloud callbacks.'],
    ['9. 容量受限时手工选最多 48 条可归档正文，审查代次/数量并确认损失。旧值/新值/预览正文不可恢复，永久 UUID/原写结果/Unknown 风险保留。配置数据库才有跨实例持久事实；无数据库仅当前进程 Mock，Live 受管修改要求数据库。',
      '9. At capacity select at most 48 eligible bodies, review generation/count and confirm loss. Old/new values and preview bodies are irrecoverable; permanent UUIDs, original write results and Unknown risk remain. Cross-instance durability requires a database; without one Mock belongs to this process and Live management requires a database.'],
  ];
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Alert type="warning" message={t('受管任务配置不证明云激活、回调部署或消费者生效', 'Managed job configuration does not prove cloud activation, callback deployment or consumer activation')}
      description="callbackBindingEnforced=false · callbackConfigured=unknown · deploymentVerified=unknown · consumerApplied=unknown · cloudCasAvailable=false" />
    {steps.map(([cn, en], index) => <Typography.Paragraph key={index}>{t(cn, en)}</Typography.Paragraph>)}
    <Table size="small" rowKey="kind" pagination={false} dataSource={SCHEDULER_TASKS} columns={[
      { title: t('类型 / 执行器', 'Kind / executor'), render: (_, row) => `${row.kind} → ${row.runtimeName}` },
      { title: t('真实目标', 'Actual target'), render: (_, row) => t(...row.target) },
      { title: t('独立部署与配置', 'Separate deployment and configuration'), render: (_, row) => t(...row.setup) },
    ]} />
    <Typography.Link href="/alicloud?tab=scheduler-managed">{t('受管任务页面入口', 'Managed jobs page entry')}</Typography.Link>
    <Typography.Link href="/alicloud?tab=scheduler-native">{t('打开原生观察与本地关联', 'Open native observations and local associations')}</Typography.Link>
    <Typography.Link href="/alicloud">{t('打开云连接设置 → SchedulerX3 配置/接入指南', 'Open cloud connections → SchedulerX3 Configure / Guide')}</Typography.Link>
  </Space>;
}
