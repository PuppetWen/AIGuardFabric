import { Alert, Collapse, Typography } from 'antd';
import { useTranslation } from 'react-i18next';

export function SettlementGuide() {
  const zh = useTranslation().i18n.language.startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  return <Collapse items={[{ key: 'guide', label: text('费用结算查询与恢复指南', 'Settlement lookup and recovery guide'),
    children: <>
      <Typography.Paragraph>{text('1. 从原模型请求的 x-agf-attempt-id 响应头复制实际编号。这里不生成编号，也不会重新调用模型。首响应完全丢失且未保留编号时，本页不能找回那次请求。',
        '1. Copy the actual x-agf-attempt-id response header from the original model request. This page generates no ID and does not call a model. It cannot find an attempt whose entire initial response and ID were lost.')}</Typography.Paragraph>
      <Typography.Paragraph>{text('2. 使用原租户与原调用身份，粘贴编号并读取。读取需要 models:read。reserved 表示没有可安全恢复的已知结果；保守结算不证明模型成功。',
        '2. Use the original tenant and caller, paste the ID and read. Reading requires models:read. Reserved has no safe known result to recover; conservative settlement does not prove model success.')}</Typography.Paragraph>
      <Typography.Paragraph>{text('3. 只有 pending-audit 且服务器允许恢复时，原身份具备 models:write 才能明确恢复。恢复只提交已知用量、账本和审计，不再次发起模型或 embedding 请求。',
        '3. For pending-audit with recovery available, the original caller needs models:write to confirm recovery. This publishes known usage, ledgers and audit locally, with no new model or embedding request.')}</Typography.Paragraph>
      <Typography.Paragraph>{text('4. 恢复回复丢失时保留原编号，先读取原回执；404 不能证明没有提交。读取可信待恢复状态后可人工确认同一编号的本地恢复；已结算状态不提供重派按钮。',
        '4. After a lost recovery reply, keep the original ID and read its receipt. HTTP 404 does not prove no commit. A trusted pending receipt permits explicit local recovery of that same ID; settled offers no redispatch button.')}</Typography.Paragraph>
      <Typography.Paragraph>{text('身份要求：控制台仅能直接恢复由同一登录用户发起的原请求。服务 Key 请求请用原 Key 在客户端读取或恢复，管理员不能替代该身份。查询需要 models:read，恢复需要 models:write；账号、Key、租户与绑定 Agent 必须仍有效。',
        'Identity requirement: the console directly recovers only attempts originally made by this same signed-in user. For service Key attempts, use the original Key from the client; an administrator cannot replace that identity. Lookup needs models:read, recovery needs models:write, and the caller, Key, tenant and bound Agent must remain valid.')}</Typography.Paragraph>
      <Typography.Paragraph>{text('客户端对应 GET /api/v1/gateway/attempts/{原编号} 与明确 POST /api/v1/gateway/attempts/{原编号}/recover，恢复正文只能是 {}。保留原认证和租户请求头；不要重发模型请求来修复计费。',
        'Client operations are GET /api/v1/gateway/attempts/{original-id} and explicit POST /api/v1/gateway/attempts/{original-id}/recover with only {}. Retain the original authentication and tenant headers; do not repeat a model call to repair accounting.')}</Typography.Paragraph>
      <Typography.Paragraph>{text('流式调用可显示部分用量；主调用之外，最多显示七个有序回退和一个 embedding 的独立用量编号。已发送但最终用量未知的组件按保守规则结算，不能把部分费用当作最终账单。流失败或取消后先查原编号，再按回执明确恢复本地结算；不要重放业务请求。',
        'Streams may report partial usage. In addition to the primary call, up to seven ordered fallback calls and one embedding have separate usage IDs. Dispatched components with unknown final usage settle conservatively; partial costs are not final bills. After a stream failure or cancellation, read the original ID and explicitly recover local settlement when allowed; do not replay the business request.')}</Typography.Paragraph>
      <Alert type="info" message={text('费用是已知实际用量或明确的保守估算，不是厂商账单。缓存命中不会抹除已经发生的 embedding 费用。',
        'Charges reflect known usage or explicit conservative estimates, not a vendor invoice. A cache hit does not erase already consumed embedding fees.')} />
    </> }]} />;
}
