import { Space, Typography } from 'antd';
import { useTranslation } from 'react-i18next';

export function ApiRetryGuide() {
  const zh = useTranslation().i18n.language.startsWith('zh');
  return <Space direction="vertical">
    <Typography.Paragraph>{zh
      ? '接入自研 Agent、采集器或企业脚本时，每项独立写操作生成一个 Idempotency-Key（推荐 UUID）。网络中断后保留原键、账号、组织、方法、完整地址、请求内容和业务头重试。不要把凭据放在幂等键中。浏览器正常使用不需要手工设置。'
      : 'For custom Agents, collectors or enterprise scripts, generate one Idempotency-Key (a UUID is recommended) per mutation. After a network interruption, keep the original key, caller, organization, method, full URL, body and application headers. Never put credentials in the key. Normal browser use needs no manual header.'}</Typography.Paragraph>
    <Typography.Paragraph>{zh
      ? '409 表示参数或权限上下文改变、请求仍在执行，或结果不确定。先查询任务/资源状态，避免不断换键造成重复操作。401/403/412 需要处理当前认证、权限、MFA 或改密要求，旧回执不能绕过这些检查。429 后稍等再试。'
      : 'A 409 indicates changed inputs or authorization context, running work, or an uncertain outcome. Inspect the task or resource first; changing keys can duplicate work. Resolve current authentication, permission, MFA or password requirements for 401/403/412. Old receipts cannot bypass them. Back off after 429.'}</Typography.Paragraph>
    <Typography.Paragraph>{zh
      ? '普通接口的去重回执仅限同一服务进程，结束后保存 15 分钟；重启或切到另一实例后须依据业务记录核对。大响应和流式响应完整返回但不缓存。登录和凭据签发接口不接受通用幂等键；MCP 工具使用其协议，不把请求 ID 当成去重保证。'
      : 'Generic receipts belong to one server process and remain for 15 minutes after execution. Reconcile business records after restart or switching replicas. Large and streaming responses stay intact but are not cached. Authentication and credential issuance do not accept generic idempotency keys. MCP request IDs do not guarantee tool deduplication.'}</Typography.Paragraph>
    <Typography.Paragraph>{zh
      ? '红队提交另有 PostgreSQL 持久去重，可跨实例和重启返回原任务及原用例版本。只有明确标注持久去重的接口才有这项保证。完整容量和重试说明见项目 docs/http-retry-guide.md。'
      : 'Campaign submission has separate durable PostgreSQL deduplication across replicas and restarts, retaining the original task and case versions. This guarantee applies only where explicitly documented. See docs/http-retry-guide.md for limits and retry procedures.'}</Typography.Paragraph>
  </Space>;
}
