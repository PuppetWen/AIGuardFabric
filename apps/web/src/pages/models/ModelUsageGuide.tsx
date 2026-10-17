import { Collapse, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
export function ModelUsageGuide() {
  const zh = useTranslation().i18n.language.startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  return <Collapse style={{ marginBottom: 16 }} items={[{ key: 'usage',
    label: text('模型费用、预算和查询操作指南', 'Model costs, budgets and browsing guide'),
    children: <>
      <ol>
        <li>{text('先确认组织，再到模型接入配置选择厂商、填写准确的模型 ID 和厂商凭据。切换厂商会更新建议地址并清空旧模型 ID；手填地址会保留。Azure、Bedrock 和本地模型须填写自己的可达地址。',
          'Select the organization, then choose a provider in Gateway configuration and enter the exact model ID and provider credential. Changing provider updates the suggested URL and clears the old model ID; a URL you typed is preserved. Enter your own reachable URL for Azure, Bedrock and local models.')}</li>
        <li>{text('Docker 中的 127.0.0.1 不是工作站，Ollama/vLLM 请填容器可达的内网地址；确认受控网络后再开启对应开关。个人可先用模拟端点；企业应分配负责人、创建最小权限平台 API Key 并核对单价。历史 .env 厂商密钥变量不会接入网关，台账发现的模型也不会自动变成可调用端点。',
          'In Docker, 127.0.0.1 is the container, not your workstation. Use a container-reachable private address for Ollama/vLLM and enable the controlled-network switch only after verification. Individuals can start with a mock endpoint; enterprises should assign ownership, create a scoped platform API key and verify pricing. Historical vendor key variables in .env do not configure the gateway, and discovered inventory models are not automatically callable.')}</li>
        <li>{text('所有单价、费用和路由日预算使用 CNY 元；网关以微元整数计量。费用是调用时配置价格的估算，不是供应商账单，也不会自动换汇。零价格会产生零费用，但不能证明供应商免费；需配置正确单价。',
          'Prices, costs and daily route budgets use CNY. The gateway meters integer micro-yuan. Costs are estimates at the prices configured for the call, not provider invoices; no currency conversion occurs. Zero prices produce zero estimates and do not prove the provider is free. Configure accurate prices.')}</li>
        <li>{text('Anthropic 的总输入量含普通输入、缓存读取和缓存写入；缓存读取按端点缓存单价，5 分钟/1 小时写入分别按输入单价的 1.25/2 倍估算。在明细表悬停有下划线的输入数字可查看三类缓存 Token。',
          'Anthropic input totals include uncached tokens, cache reads and writes. Reads use the configured cache price; 5-minute and 1-hour writes use 1.25x and 2x the input price. Hover over an underlined input count in the detail table to see the cache breakdown.')}</li>
        <li>{text('日预算按 UTC 日重置，0 表示不限；提交前预留预估 Token 与费用，完成后结算。取消或上游缺少用量时可能保守计账。路由预算只约束经过该路由的请求；组织配额在设置与运行时策略中维护。',
          'Daily route budgets reset at UTC midnight; 0 means unlimited. Requests reserve estimated tokens and cost before dispatch and settle on completion. Cancellation or missing upstream usage can retain conservative charges. Route budgets apply only to requests using that route; manage tenant quotas in settings and runtime policies.')}</li>
        <li>{text('客户端应设置 max_tokens。模拟端点会按此截断并标记 length；真实上游若返回超出上限的用量或超过 4 MiB 的回复，网关拒绝该回复并记录实际用量与运行时事件。流式请求已发送的早期分片无法撤回，收到错误事件后不要把部分输出当作完整结果。',
          'Set max_tokens in clients. Mock endpoints truncate at that limit with a length finish reason. If a real provider exceeds the requested token limit or returns more than 4 MiB, the gateway rejects the response and records actual usage and a runtime event. Earlier streaming chunks cannot be recalled; discard partial output when an error event arrives.')}</li>
        <li>{text('Gemini 和 Bedrock 的请求都会传递 temperature、top_p、stop 和 max_tokens；Gemini 的停止序列最多 5 个，超出时触网前报错。请先用短请求核对厂商模型是否支持所选参数。',
          'Gemini and Bedrock requests forward temperature, top_p, stop and max_tokens. Gemini allows at most five stop sequences and rejects longer lists before contacting the provider. Verify model-specific support with a short test call.')}</li>
        <li>{text('上游报错时，客户端只收到厂商和 HTTP 状态，不会收到上游响应正文；流式错误也使用固定提示。可在运行时事件中按会话排查预筛、预算或端点调用失败；需要厂商细节时到厂商控制台核对同一请求。',
          'On upstream failure, clients see the provider and HTTP status without the upstream response body; streaming errors use a fixed message. Check runtime events by session for screening, budget, or endpoint failures, then use the provider console for vendor-specific details.')}</li>
        <li>{text('费用图和汇总覆盖当前保留的真实计量记录，排除模拟。明细显示模拟和缓存命中，可以翻页查看全部保留记录；模型台账搜索和分页在服务端执行。刷新会更新用量、明细、台账及路由。',
          'Cost charts and totals cover retained real metering records and exclude mock calls. Details identify mock/cache hits and paginate all retained records. Inventory search and pagination run on the server. Refresh reloads usage, details, inventory and routes.')}</li>
        <li>{text('计量条数是组件记录数，不是模型 HTTP 请求数；一条请求可有 embedding 与 chat 两条独立收费记录。当前节点累计投影若提示不完整，旧记录或证据的覆盖范围未确认；分组合并只改变显示粒度。费用图仍独立查询当前组织保留记录，不包含没有实际用量记录的所有保守费用。核对预算请看原请求的持久账本与结算回执，不能据投影小计重扣旧费用。',
          'Counts refer to component records, not model HTTP requests; one request can have separate embedding and chat charges. An incomplete node projection has unconfirmed historical coverage; merged groups affect display detail only. Charts independently query retained tenant records and do not include every conservative charge lacking actual usage. Verify budgets using the original durable ledgers and settlement receipts; never recharge historical fees based on projection subtotals.')}</li>
        <li>{text('只读账号可查看配置、路由和用量；添加、修改、启停、删除、试调用需要 models:write。真实试调用会消耗厂商额度。切换组织或账号会关闭原编辑窗口，错误不会替换成演示数据。',
          'Read-only accounts can inspect configuration, routes and usage. Creating, editing, enabling, deleting and test calls require models:write. Real test calls consume provider quota. Switching organization or account closes the previous editor. Errors do not become demo records.')}</li>
      </ol>
      <Typography.Paragraph><Link to="/settings?tab=apiKeys&createKey=1&scopes=models%3Aread%2Cmodels%3Awrite">
        {text('创建模型客户端 API Key（预选 models:read、models:write）',
          'Create a model client API key (models:read and models:write preselected)')}
      </Link></Typography.Paragraph>
      <Typography.Paragraph>{text('兼容旧 API 的 cost_usd / budget_usd_per_day 名称，但历史数值一直按 CNY 执行。新客户端应使用 cost_cny / budget_cny_per_day 和 currency=CNY；已有预算不换算、不放大。',
        'Legacy cost_usd / budget_usd_per_day API names remain compatible, but historical values were always executed as CNY. New clients should use cost_cny / budget_cny_per_day and currency=CNY. Existing budgets are not converted or scaled.')}</Typography.Paragraph>
    </>,
  }]} />;
}
