import { useTranslation } from 'react-i18next';
import { Space, Typography } from 'antd';
import { Link } from 'react-router-dom';

export function ScanGuide() {
  const zh = useTranslation().i18n.language.startsWith('zh');
  return <Space direction="vertical">
    <ol>
      <li>{zh ? '个人用户打开风险发现 → 内容扫描与任务，填写名称，选择内容类型并粘贴文本，可不关联资产。' : 'Open Risk findings → Content scans. Name the task, choose a content type and paste text. Personal users may leave the asset empty.'}</li>
      <li>{zh ? '企业用户先核对顶部组织，再搜索并关联已登记资产。选择内容分级；资产的更高分级始终生效。读取任务需要 scans:read，执行/取消需要 scans:execute，关联资产需要 assets:read。' : 'Enterprise users should check the organization, then select a registered asset and data classification. Higher asset classification always applies. Task reads require scans:read, execution/cancellation scans:execute, and asset association assets:read.'}</li>
      <li>{zh ? '二次研判需要 models:write。先在模型网关配置当前组织的端点和默认路由。真实调用受策略、分级和配额约束；离线 Mock 使用明确标注的规则研判。每次研判跳过响应缓存。' : 'Secondary judgement requires models:write. Configure an endpoint and default route in Model Gateway. Live calls enforce policies, classification and quotas; offline Mock uses a labelled rule judge. Each judgement bypasses response caches.'}</li>
      <li>{zh ? '提交后每 3 秒刷新。展开任务查看评分、研判次数和降级提示，点击发现检查证据与修复建议。研判失败保留规则结果；无命中不能证明安全，内容分数不代表整项资产风险。' : 'Tasks refresh every 3 seconds. Expand one to inspect its score, judgement counts and degradation, then open findings for evidence and remediation. Judgement failures retain rule results. No matches do not prove safety; the score covers only this content.'}</li>
      <li>{zh ? '任务最多执行 2 分钟。取消或过期后不再提交发现；中断任务在期限后的查询中标为失败，不自动重放。先核对历史再重试。PostgreSQL 保存的摘要跨重启保留，原文不保存在任务中，但发现可能含证据。' : 'Tasks expire after 2 minutes. Cancellation/expiry prevents findings from being committed. Interrupted jobs fail on a read after expiry and are not replayed. Check history before retrying. PostgreSQL summaries survive restart; task rows exclude original text but findings may retain evidence.'}</li>
    </ol>
    <Typography.Paragraph>{zh ? '批量接入：POST /api/v1/scans，wait=false；用返回的 task_id 轮询 GET /api/v1/scans/{task_id}。每批 1–100 项，单项 1 MiB、总计 4 MiB。接口结构见 /openapi.json。' : 'Batch integration: POST /api/v1/scans with wait=false, then poll GET /api/v1/scans/{task_id}. Each batch allows 1–100 targets, 1 MiB each and 4 MiB total. Schemas are available in /openapi.json.'}</Typography.Paragraph>
    <Link to="/findings">{zh ? '打开风险发现' : 'Open risk findings'}</Link>
  </Space>;
}
