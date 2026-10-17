import { Alert, Collapse } from 'antd';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';

export function SemanticProfileGuide() {
  const zh = useTranslation().i18n.language.startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  return <Collapse size="small" items={[{ key: 'guide', label: text('语义缓存配置与接入指南', 'Semantic cache configuration and connection guide'), children: <>
    <ol>
      <li>{text('在上方模型接入配置中添加聊天端点与向量端点。模拟模式需选择两个 Mock 端点；真实向量端点使用已保存凭据的 OpenAI 或兼容协议 HTTPS 根地址或 /v1 地址。',
        'Add chat and embedding endpoints in Gateway configuration above. Mock mode requires two Mock references. Live embeddings require a saved credential and an OpenAI-compatible HTTPS root or /v1 URL.')}</li>
      <li>{text('选择端点并填写两个模型的固定版本标签；向量维度、单价和 Token 上限按实际服务填写。先使用模拟模式核对流程。',
        'Select endpoints and pin both model revision labels. Set dimensions, price and the token limit for the actual service. Check the flow in mock mode first.')}</li>
      <li>{text('保存成功只表示配置已保存。每次调用还须通过租户、Agent 分级、权限、配额和当前规则检查；不满足条件时不会使用语义缓存。',
        'A successful save confirms configuration only. Each call must still pass tenant, Agent classification, permission, quota and current rule checks before semantic caching can apply.')}</li>
      <li>{text('客户端仍使用平台的 /v1 地址和平台 API Key，选择所配置聊天端点。向量凭据由服务器保管，客户端不需要填写。',
        'Clients keep the platform /v1 address and platform API key, selecting the configured chat endpoint. The server keeps the embedding credential; clients do not enter it.')}</li>
      <li>{text('若保存结果未知或版本冲突，先点“读取当前配置”查看服务器版本；草稿不会改变。确认后点“采用当前配置”丢弃草稿，再手动保存新修改。',
        'For an unknown save result or version conflict, read the current configuration first. Your draft is retained. Explicitly adopt the current configuration to discard it, then save new changes manually.')}</li>
    </ol>
    <Alert type="info" showIcon message={text('模拟向量用于本地流程验证，不代表厂商模型语义质量；缓存命中仍使用当前响应安全检查。',
      'Mock vectors validate the local flow, not provider semantic quality. Cache hits still use current response screening.')} />
    <Link to="/guide?tab=platforms">{text('查看各平台客户端接入步骤', 'View platform client connection steps')}</Link>
  </> }]} />;
}
