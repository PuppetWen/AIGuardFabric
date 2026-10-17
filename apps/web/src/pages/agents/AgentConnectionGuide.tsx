import { Collapse, Typography } from 'antd';
import { useTranslation } from 'react-i18next';

export function AgentConnectionGuide() {
  const zh = useTranslation().i18n.language.startsWith('zh');
  const text = (cn: string, en: string) => zh ? cn : en;
  return <Collapse style={{ marginBottom: 16 }} items={[{
    key: 'connection', label: text('Agent 接入：个人试用、企业上线与验证', 'Agent connection: personal trial, enterprise rollout and verification'),
    children: <Typography>
      <Typography.Paragraph>{text('个人用户：选择当前租户，在设置中创建专用 API Key。首次接入无需已有 Agent；选择目标系统生成通用计划。下载已发布制品或在该系统源码构建，先单次采集，再检查资产台账和接入日志。',
        'Personal use: select your tenant and create a dedicated API key in Settings. No existing agent is required. Generate a generic plan for the target OS, download a published build or compile on that OS, collect once, then inspect inventory and ingestion logs.')}</Typography.Paragraph>
      <Typography.Paragraph>{text('企业用户：按组织、终端或应用分配独立 Key。采集需要 sources:write；模型验证需要 models:read 和 models:write。先在测试设备验证退出码、资产身份、模型用量和策略，再按既有变更流程分批上线。服务器地址应为目标设备可访问的地址。',
        'Enterprise use: issue separate keys by tenant, endpoint or application. Collection needs sources:write; model validation needs models:read and models:write. Verify exit codes, asset identity, usage and policies on a test device before staged rollout. Use a server address reachable from that device.')}</Typography.Paragraph>
      <Typography.Paragraph>{text('采集模式发现终端配置；它不会自动代理应用流量。启动注入包装明确的 Python/Node CommonJS Task/Call 边界，不记录 Message；Message 需要显式 SDK。模型网关分别提供 OpenAI /v1 与 Anthropic 根地址，MCP stdio 保留原 command/args，HTTP MCP 使用登记、探测和模板。环境变量是否生效取决于原应用。',
        'Collector mode discovers endpoint configuration and does not automatically proxy application traffic. Startup injection wraps explicit Python/Node CommonJS Task/Call boundaries; Message needs the explicit SDK. The model gateway separates OpenAI /v1 and the Anthropic origin. MCP stdio retains the original command/args; HTTP MCP uses registration, probing and templates. Environment-variable support depends on the original application.')}</Typography.Paragraph>
      <Typography.Paragraph>{text('项目级 Claude Code/MCP 配置：运行前设置 AGF_AGENT_PROJECT_ROOTS，填项目根目录的绝对路径。Windows 多目录用分号，Linux/macOS 用冒号，最多 8 个；采集器只读固定 MCP 配置文件，不遍历仓库。单次采集后到 MCP 管理页核对服务器名与来源路径。',
        'For project-scoped Claude Code/MCP settings, set AGF_AGENT_PROJECT_ROOTS to absolute project roots before running. Separate roots with semicolons on Windows or colons on Linux/macOS, up to eight. The collector reads only fixed MCP configuration files, without walking the repository. After a one-time collection, verify the server and source path in MCP management.')}</Typography.Paragraph>
      <Typography.Paragraph>{text('生成计划不改变纳管状态，也不承诺零停机。没有发布制品时不会提供失效下载。回退时停止采集或恢复原应用配置，保留本地数据目录并撤销此次专用 Key。离线设备、权限失败、未知指标和 Mock 必须分别核对。本机实际 Claude CLI 曾在连接平台前被受管理策略阻断；Mock 协议响应不能替代 Claude CLI 实测。',
        'A plan does not change management status or guarantee zero downtime. Unpublished builds have no download link. To roll back, stop collection or restore application settings, retain the data directory and revoke the dedicated key. Check offline devices, permission failures, unknown measurements and Mock usage separately. The actual local Claude CLI was blocked by managed policy before connecting; a Mock protocol response does not prove CLI acceptance.')}</Typography.Paragraph>
    </Typography>,
  }]} />;
}
