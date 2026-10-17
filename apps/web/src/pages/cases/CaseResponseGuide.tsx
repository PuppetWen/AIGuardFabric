import { Alert, Steps, Typography } from 'antd';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Panel } from '@/components/Panel';

export function CaseResponseGuide() {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language ?? 'zh-CN').startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  return <Panel title={text('案件与 SOAR 操作', 'Cases and SOAR')}>
    <Alert type="info" showIcon style={{ marginBottom: 16 }}
      message={text('先用独立测试 Agent 和测试密钥验证', 'Start with a separate test Agent and key')}
      description={text('Agent 隔离和封禁只作用于平台流量；EDR 主机隔离是单独的外部调用，须先配置并审批。',
        'Agent isolation and blocking affect managed traffic. EDR host isolation is a separate external call that requires configuration and approval.')} />
    <Steps direction="vertical" items={[
      { title: text('绑定身份', 'Bind Agent identity'), description: <span>
        <Link to="/settings">{text('设置 → API Key', 'Settings → API keys')}</Link>
        {text('中创建密钥并绑定 Agent，再把密钥用于模型客户端和 MCP 代理；同一 Agent 更换会话仍受隔离和配额约束。',
          ': create a key bound to an Agent and use it in model clients and MCP proxies. New sessions retain Agent controls and quotas.')}
      </span> },
      { title: text('建立案件', 'Create a case'), description: <span>
        <Link to="/cases">{text('案件中心', 'Cases')}</Link>
        {text('中可手工新建案件；也可先在风险发现详情核对证据，再带发现编号打开预填表单，确认后建案。新案件会直接打开，并可回到原始发现。',
          ': create a case manually, or review evidence in a finding and open a prefilled case form. Confirm to create; the new case opens with a link back to its finding.')}
      </span> },
      { title: text('先演练', 'Run a dry run'), description: text(
        '点击“执行处置 / YAML 剧本”，选择动作、目标及原因。默认演练只检查编排，不产生副作用，也不证明目标已配置正确。',
        'Open Run action / YAML playbook, select a target and enter a reason. Dry runs check orchestration without effects; they do not validate live targets.') },
      { title: text('需要电脑隔离时接入 EDR', 'Connect EDR for host isolation'), description: <span>
        <Link to="/integrations">{text('集成中心', 'Integrations')}</Link>
        {text('先启用 edr-isolation Mock。在资产详情绑定经过核对的 EDR 主机编号；案件中选择关联资产后会自动读取编号。真实模式的 dry_run 默认开启，关闭前先用测试主机验证。',
          'Enable edr-isolation Mock first. Bind the verified EDR host ID in asset details; the case action reads it automatically. Live configuration defaults to dry_run until you verify it on a test host.')}
      </span> },
      { title: text('需要停用外部身份时接入 SCIM', 'Connect SCIM for external identity deactivation'), description: <span>
        <Link to="/integrations">{text('集成中心', 'Integrations')}</Link>
        {text('中先启用 iam-scim Mock；在凭据资产详情绑定核对过的 SCIM 用户 ID，关联案件后选择“通过 SCIM 停用外部身份”。真实停用只从已审批案件执行，需以身份平台的 active=false 核对。',
          ': enable iam-scim Mock first. Bind a verified SCIM user ID to a credential asset and link it to a case. Select Deactivate external identity through SCIM. Live execution requires approval; verify active=false in the identity provider.')}
      </span> },
      { title: text('让新告警生成待审批任务', 'Create approval runs from new alerts'), description: text(
        '在“告警自动响应”选 EDR 或 SCIM 模板，搜索已绑定资产，填写原因，预览匹配告警后启用。表单会读取远端编号和集成版本；新告警必须关联同一资产，审批前不会调用外部平台。',
        'Choose an EDR or SCIM template under Automatic alert response, search for the bound asset, enter a reason, preview a matching alert, then enable. The form reads the remote ID and integration version. New alerts must link the same asset; no external call occurs before approval.') },
      { title: text('审批并执行', 'Approve and execute'), description: text(
        '关闭演练并提交任务，在“审批与执行记录”中核对目标再批准。审批需要 cases:admin 及相应动作权限；可要求另一位管理员复核，API Key 不能人工审批。',
        'Disable dry run and submit. Review saved targets under Approvals and runs, then approve with cases:admin and action permissions. You can require another administrator; API keys cannot approve.') },
      { title: text('等待与恢复', 'Wait and resume'), description: text(
        '关闭网页后任务继续；PostgreSQL 保存等待与审批。执行中断且结果不明时会暂停，请先核对处置，再确认完成、明确重试或停止后续步骤。',
        'Runs continue after closing the page. PostgreSQL preserves waits and approvals. Interrupted actions with unknown outcomes pause for review: verify the effect, then confirm, explicitly retry, or stop remaining steps.') },
      { title: text('验证与解除', 'Verify and release'), description: text(
        '用测试客户端确认被拦截，在运行时记录中核对原因。可逆控制可在案件详情解除，再验证调用恢复。API Key 吊销不可撤销。',
        'Verify rejection from a test client and inspect runtime records. Release reversible controls from the case and verify access resumes. Revoked API keys cannot be restored.') },
      { title: text('配置通知', 'Configure notifications'), description: text(
        '通知使用系统设置中已启用渠道。离线先用站内信；未配置、投递失败、模拟模式中的外部渠道均不能当作实际发送成功。',
        'Use enabled channels in Settings. Start with in-app messages. Missing configuration, failed delivery and mocked external delivery are not actual success.') },
    ]} />
    <Typography.Paragraph style={{ marginTop: 16 }}>{text(
      'YAML 最多 100 步，异步总时限最多 7 天；wait_secs 保存等待，独立 require_approval 步骤需要新的审批。初始审批 24 小时过期，批准后开始执行计时。已完成步骤不会回滚。完整示例见 docs/case-response-guide.md。',
      'YAML supports 100 steps and a durable execution deadline up to 7 days. wait_secs persists a wait; a require_approval step requests a new decision. Initial approval expires after 24 hours; execution time starts on approval. Completed steps are not rolled back. See docs/case-response-guide.md.')}</Typography.Paragraph>
  </Panel>;
}
