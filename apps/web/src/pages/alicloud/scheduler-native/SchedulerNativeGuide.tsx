import { Alert, Space, Table, Typography } from 'antd';
import { SCHEDULER_TASKS } from '../scheduler-registration/tasks';
import { useSchedulerText } from './text';

export function SchedulerNativeGuide() {
  const t = useSchedulerText();
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Alert type="warning" showIcon message={t('此处完成云端只读观察及平台本地关联；不是云注册向导或部署验证',
      'This page observes cloud state and saves local associations; it does not register cloud jobs or verify deployment')}
      description={t('callbackBindingEnforced=false。不要以关联成功判断回调授权、网络可达、服务就绪或任务已经执行。',
        'callbackBindingEnforced=false. A successful association does not verify callback authorization, reachability, service readiness or job execution.')} />
    <Typography.Paragraph>{t('1. 在上方 SchedulerX3 连接设置保存并启用明确来源：region_id、cluster_id、app_name、RPC 地址与模式；真实云填所需凭据。配置 account_id 只是标签，身份仍未验证。',
      '1. Save and enable an explicit SchedulerX3 connection above: region_id, cluster_id, app_name, RPC origin and mode; supply credentials for live cloud. A configured account_id is a label, not verified identity.')}</Typography.Paragraph>
    <Typography.Paragraph>{t('2. 手动“发起新观察”。真实云必须确认，隔离 Mock 示例须写权限并单独勾选初始化。每次新观察创建新编号；失败先“读取原编号”。分页仅 GET，不会重派观察。',
      '2. Manually observe. Live cloud requires confirmation; isolated Mock initialization requires write permission and a separate checkbox. Each new observation gets a new ID. Read the original ID after failure; paging uses GET and never redispatches the observation.')}</Typography.Paragraph>
    <Typography.Paragraph>{t('隔离 Mock 示例仅支持 region_id=cn-hangzhou、cluster_id=cluster-agf-demo、app_name=app-agf-demo；模式选 Mock 并手工保存来源后，再明确勾选初始化。示例含 6 条观察记录，其中只有一条启用 HTTP 任务，不能作为六任务全部已绑定或可运行的证明。',
      'The isolated Mock fixture supports only region_id=cn-hangzhou, cluster_id=cluster-agf-demo and app_name=app-agf-demo. Select Mock and manually save the source before explicitly initializing. Its six observed records include only one enabled HTTP job; they do not prove six associations or runnable tasks.')}</Typography.Paragraph>
    <Typography.Paragraph>{t('3. 明确采用最新本地版本和当前完整观察，在完成后 300 秒内逐页选择启用的 HTTP Job。JobId 按字符串保存；一个云 Job 只能关联一种平台任务。跨页选择保留，不自动按名字匹配。',
      '3. Explicitly adopt the latest local version and current complete observation within 300 seconds of completion. Select enabled HTTP jobs across pages. Job IDs stay strings; one cloud job serves one platform kind. Choices persist across pages; names never imply a binding.')}</Typography.Paragraph>
    <Typography.Paragraph>{t('4. 检查六类实际任务目标，确认整体替换并保存本地关联。空列表明确清空。409/412 后保留草稿，重新读取仅用于比较；人工采用最新版本后才手动提交新意图。停用本地关联不停止云任务或服务。',
      '4. Check the six actual task targets, confirm full replacement and save local associations. An empty list explicitly clears them. A 409/412 keeps the draft; reload only compares it. Explicitly adopt the latest version before submitting a new intent. Local disable does not stop cloud jobs or services.')}</Typography.Paragraph>
    <Typography.Paragraph>{t('在“已保存的逐任务资格”中查看 eligible / revoked / unverified、原因、决定观察和时间，再展开“查看资格证据”对照原始采用证明与最新完整存储证据。总体 current=false 不表示所有 Job 都失去资格；来源 / 版本一致性与每项资格需分别核查。旧关联无证明显示 unverified。',
      'Review eligible / revoked / unverified, reason and decision provenance in “Saved per-job qualifications”. Open “View qualification evidence” to compare the original adoption proof with the latest complete stored evidence. Overall current=false does not mean every job lost qualification; check source/version and each item separately. Legacy associations without proof are unverified.')}</Typography.Paragraph>
    <Typography.Paragraph>{t('完整新观察若发现应用改变、所选任务缺失、明确停用或非 HTTP，会撤销该项；类型 / 状态未知则未验证。即使后续证据恢复启用 HTTP，也不会自动恢复资格：重新发起完整观察，在 300 秒采用窗口内明确采用并保存新的本地意图。300 秒不是已保存资格的运行有效期，正文归档保留原采用证明与资格。当前尚未强制执行回调绑定。',
      'A complete new observation revokes an item if its app changes or the selected job is absent, explicitly disabled or non-HTTP; unknown type/status leaves it unverified. Later positive HTTP/enabled evidence never restores qualification automatically: explicitly observe again, adopt within 300 seconds and save a new local intent. Those 300 seconds are not a runtime TTL; body archive retains the original adoption proof and qualification. Callback binding remains unenforced.')}</Typography.Paragraph>
    <Table size="small" rowKey="kind" pagination={false} dataSource={SCHEDULER_TASKS} columns={[
      { title: t('任务 / 实际执行器', 'Kind / actual executor'), render: (_, task) => `${task.kind} / ${task.runtimeName}` },
      { title: t('真实目标', 'Actual target'), render: (_, task) => t(...task.target) },
      { title: t('服务身份与部署配置', 'Service identity and deployment'), render: (_, task) => t(...task.setup) },
      { title: t('执行证据', 'Execution evidence'), render: (_, task) => t(...task.evidence) },
    ]} />
    <Typography.Paragraph>{t('5. 企业部署由管理员单独部署 scheduler 服务，配置真实租户 UUID、服务身份、独立 callback token 的 Secret 引用、AppID、可达 HTTPS 回调和各任务目录/依赖。个人单机也须分别运行 API 与 scheduler，并检查网络入口；局域网地址不会自动成为云端可达地址。Token 不保存在本表单、SQL 关联或观察回执中。',
      '5. Enterprise administrators separately deploy the scheduler service with the actual tenant UUID, service identity, an independent callback-token secret reference, AppID, reachable HTTPS callbacks and each task’s directories/dependencies. A personal installation also runs API and scheduler separately and verifies ingress; a LAN address is not automatically reachable from cloud. Tokens are not stored in this form, SQL associations or observation receipts.')}</Typography.Paragraph>
    <Typography.Paragraph>{t('6. 参照“SchedulerX3 注册准备”生成部署配置并由管理员核验；/tasks 仅作诊断，不证明云注册。当前仍由服务 timer 执行的任务与云回调分开验收，观察不会控制所有 timer。检查真实 JobExecutionId、服务产物和平台回执后才能确认执行。',
      '6. Use “SchedulerX3 registration preparation” for deployment configuration and administrator review; /tasks is diagnostic, not proof of cloud registration. Validate service timers separately from cloud callbacks; observations do not control every timer. Confirm execution through real JobExecutionId, service artifacts and platform receipts.')}</Typography.Paragraph>
    <Typography.Paragraph>{t('7. 容量满时明确选择可归档正文并确认数量/台账代次，最多 100 条。原编号与永久事实仍可读取，归档不证明远端停止；正文归档不等同撤销已保存的本地关联，需单独停用关联。数据库配置后才有持久跨实例事实；无数据库仅当前进程。',
      '7. At capacity, explicitly select archivable bodies and review count/ledger generation, at most 100. Original IDs and permanent facts remain readable; archive does not prove remote work stopped. Archiving a body is separate from disabling saved local associations. Durable cross-instance facts require a database; without one, state belongs to the current process.')}</Typography.Paragraph>
  </Space>;
}
