import { useTranslation } from 'react-i18next';
import { Typography } from 'antd';

export function RuleGuide() {
  const zh = useTranslation().i18n.language.startsWith('zh');
  const steps = zh ? [
    '先确认当前组织。拥有 rules:read 的账号可查看规则、YAML 和版本；内置只读观察者不包含此权限。发布、启停、灰度、恢复及执行样本需要 rules:write；风险发现的状态修改另需 findings:write。',
    '新建规则会生成唯一 key，默认灰度为 0%。替换名称、检测条件及正负样本，保存后先运行样本回归，再按 5% → 25% → 100% 逐步扩大范围。0% 不会命中正常扫描/网关流量。',
    '编辑已有规则时保持 key 不变。保存会校验样本并生成新版本；网络或校验失败保留草稿。两人同时编辑时，旧版本提交返回冲突，请复制草稿、加载最新版本、合并并重新保存。',
    '版本历史保留最近 100 个版本。“查看内容”不改变线上版本；“恢复”会重新运行样本，并按当前版本生成一个新版本。请核对恢复内容中的启用状态和灰度比例。',
    '个人可自行管理规则与发现状态；企业建议由规则维护者发布，分析人员查看证据并处理发现。切换组织或重新登录会关闭旧表单，未发送的草稿不会带入另一组织。',
  ] : [
    'Confirm the current organization. Accounts with rules:read can inspect definitions, YAML and revisions; the built-in viewer role does not include it. Publishing, enablement, rollout, restoration and sample execution need rules:write; finding state changes need findings:write.',
    'New rules receive a unique key and start at 0% rollout. Replace the name, detection conditions and positive/negative samples. Save, run sample regression, then expand through 5%, 25% and 100%. At 0%, normal scanner/gateway traffic does not match the rule.',
    'Keep an existing rule key unchanged. Saving validates samples and creates a revision. Network and validation errors preserve the draft. Concurrent edits return a conflict: copy the draft, load the latest revision, merge and save again.',
    'The latest 100 revisions are retained. View contents does not change the active rule. Restore reruns samples and publishes a new revision. Check the enablement and rollout values in the restored content.',
    'Individuals can manage their own rules and findings. Organizations can separate rule maintenance from evidence review. Switching organizations or signing in again closes old forms; unsent drafts do not carry over.',
  ];
  return <Typography><ol>{steps.map(step => <li key={step}><Typography.Paragraph>{step}</Typography.Paragraph></li>)}</ol></Typography>;
}
