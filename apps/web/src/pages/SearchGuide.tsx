import { EscalationGuide } from './alerts/EscalationGuide';
import { useTranslation } from 'react-i18next';
import { Space, Typography } from 'antd';

export function SearchGuide() {
  const zh = useTranslation().i18n.language.startsWith('zh');
  const steps = zh ? [
    '先确认顶部的当前组织，再输入名称、编号、规则键或关键词。搜索只显示当前组织中你有读取权限的资产、风险发现、告警、案件、检测规则和红队用例。',
    '暂停输入约四分之一秒后显示最多 8 条结果，精确编号和名称优先，各类结果交错显示。↑/↓ 选择、回车打开；无结果时可以改用更精确的名称，或进入对应列表筛选。',
    '结果会直接打开对象详情。复制地址栏即可分享定位链接；接收人仍需登录且具备该组织和对象的权限。刷新、前进和返回均保留详情定位。',
    '网络错误会明确显示失败，按回车重试；切换组织或账号会清空旧搜索。规则详情为只读，查看红队用例也不会执行测试。',
    '在告警中心，严重等级、风险域和状态可多选，作用于全部记录。点击标题查看关联资产、发现和案件。批量处理需勾选告警，保存成功后才更新列表；失败项会保留选择并显示原因。',
  ] : [
    'Confirm the active organization, then enter a name, ID, rule key or keyword. Results include only assets, findings, alerts, cases, detection rules and red-team cases that you can read in that organization.',
    'After a short typing pause, up to eight results appear. Exact IDs and names come first; resource groups are interleaved. Use the arrow keys and Enter to open an item, or narrow the query and use the relevant list filters.',
    'Each result opens the exact detail. Copy the address to share it; recipients still need the appropriate organization and resource permissions. Refresh and browser navigation preserve the selected object.',
    'A failed request shows an error; press Enter to retry. Changing organization or account clears the previous search. Rule previews are read-only, and previewing a red-team case does not execute it.',
    'Alert severity, domain and state filters apply to all records. Open an alert title to inspect linked assets, findings and cases. Batch changes wait for persisted results; failed items stay selected with a reason so you can retry them.',
  ];
  return <Space direction="vertical"><Typography.Title level={5}>{zh ? '搜索、详情链接与告警处理' : 'Search, detail links and alert handling'}</Typography.Title>
    <ol>{steps.map(step => <li key={step}><Typography.Paragraph>{step}</Typography.Paragraph></li>)}</ol>
    <Typography.Title level={5}>{zh ? '自动升级路由' : 'Automatic escalation'}</Typography.Title><EscalationGuide />
  </Space>;
}
