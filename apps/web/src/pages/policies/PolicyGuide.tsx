import { Alert, Space, Typography } from 'antd';
import { usePolicyText } from './usePolicyText';

export function PolicyGuide() {
  const text = usePolicyText();
  return <Space direction="vertical" size={8}>
    <Typography.Paragraph>{text('打开 /policies。查看、比较和模拟需 policies:read；新建、保存和恢复需 policies:write；删除需 policies:delete。新建名称在当前租户必须唯一，同名409不会覆盖已有策略。编辑时策略名称保持不变。',
      'Open /policies. Viewing, comparing and simulation require policies:read; creation, saving and restore require policies:write; deletion requires policies:delete. A new name must be unique in the tenant; HTTP 409 never overwrites an existing name. Existing policy names remain unchanged.')}</Typography.Paragraph>
    <Alert showIcon type="warning" message={text('保存已启用策略会在平台后续实际请求中生效；dry-run仅观察命中，不执行处置。保存不是外部云发布，不能据此认为 MSE、API 网关或其他调用方已热加载。',
      'Saving an enabled policy takes effect on subsequent actual platform requests. Dry-run observes matches without enforcement. Saving is not an external cloud publication and does not prove MSE, API gateways or other consumers reloaded it.')} />
    <Typography.Paragraph>{text('配额处置 quota 与限流 throttle 为不同动作；仅编辑说明会保留原动作。人工审批与熔断也可编辑。未知动作可查看原值，但不能发布、采纳或恢复；请先核对服务端与客户端版本。',
      'Quota enforcement (quota) and throttling (throttle) are distinct actions. Editing only metadata preserves the original action. Manual approval and circuit break are also supported. Unknown actions show their original value but cannot be published, adopted or restored; verify server and client versions first.')}</Typography.Paragraph>
    <Typography.Paragraph>{text('保存、删除或恢复必须使用打开时核对的服务端版本。409保留本地草稿，不会自动更换版本或重发。点“读取最新版本并比较”，复制所需改动；明确采纳后重新编辑，再手动保存。比较读取不会覆盖草稿；400或404也不会清空输入。',
      'Save, delete and restore use the reviewed server revision. HTTP 409 keeps the draft without changing revisions or retrying. Load latest revision to compare, copy needed edits, then explicitly adopt, edit again and save manually. Comparison reads do not replace drafts; HTTP 400 or 404 also preserve inputs.')}</Typography.Paragraph>
    <Typography.Paragraph>{text('版本与模拟中可展开历史源码，模拟的是服务端当前策略，不是未保存草稿。恢复从可信历史复制并创建一个新签名版本；历史若为启用状态，恢复后在平台生效。恢复并非预览，须核对当前版本和所选历史后确认。删除在平台移除当前策略，不能凭历史列表假定已删除策略可以恢复。',
      'In Versions and simulation, expand historical source. Simulation evaluates the current server policy, not an unsaved draft. Restore copies trusted history into a new signed revision; an enabled historical revision becomes active on the platform. Restore publishes and requires reviewing the current and selected revisions. Delete removes the current platform policy; a history list does not establish that a deleted policy can be restored.')}</Typography.Paragraph>
  </Space>;
}
