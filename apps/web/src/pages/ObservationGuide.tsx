import { Collapse, Typography } from 'antd';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';

export function ObservationGuide() {
  const { i18n } = useTranslation();
  const text = (zh: string, en: string) => i18n.language.startsWith('zh') ? zh : en;
  return <Collapse style={{ marginBottom: 16 }} items={[{ key: 'observations',
    label: text('如何核对接入状态与未知指标', 'Check connection status and unknown measurements'),
    children: <>
      <Typography.Paragraph>{text(
        '近期观察只说明采集器或端点探测最近提交过资产信息。配置文件被发现，不证明应用正在运行或工具调用成功。最近观察不使用资料编辑时间；没有采集时间显示未知。观察窗口为已上报间隔的 3 倍，未设置时为 5 分钟；超时或生命周期不可用显示“未近期观察”。',
        'Recently observed means a collector or endpoint probe submitted asset data recently. Finding a configuration does not prove the application is running or tool calls succeed. Editing inventory never creates an observation. Missing timestamps stay Unknown. The window is three reported intervals, or five minutes when unspecified. Expired observations or unavailable lifecycle states show Not recently observed.')}</Typography.Paragraph>
      <ol>
        <li>{text('个人用户先确认当前组织，完成终端上报后刷新列表，核对资产名称和最近观察时间。若未出现，检查采集器上报结果及凭据所属组织。',
          'Select your organization, submit endpoint discovery, refresh, and check the name and observation time. If missing, check the upload result and the organization of the credential.')}</li>
        <li>{text('企业用户为不同组织配置对应采集身份和周期。MCP HTTP 端点在“HTTP 接入”中保存后执行发现，查看实际工具清单；具体业务还需用测试账号验证调用。',
          'Enterprises should configure collection identities and schedules for each organization. Save an MCP HTTP endpoint under HTTP connection, then Discover to inspect its actual tool list. Verify business calls separately with a test account.')}</li>
        <li>{text('会话数、工具数、Skill 挂载数、模型单价、优先级和延迟缺少来源时显示未知。0 只用于已保存的真实零值；未知单价不能用于估算免费调用。检查采集端是否提供对应指标，更新后刷新。',
          'Session, tool and attached-Agent counts, model prices, priority and latency stay Unknown without source data. Zero means a saved zero value; unknown pricing does not mean free calls. Check whether the collector supplies the metric, update it, then refresh.')}</li>
      </ol>
      <Typography.Paragraph>{text('未提供模型部署方式、模拟标记和主备角色时同样显示未知。MCP 的“未标记明文”仅表示台账没有明文标记，不保证凭据已托管或已经检查。',
        'Missing model deployment, simulation and fallback flags stay Unknown. An MCP No plaintext flag label only describes inventory metadata; it does not prove credentials are vaulted or have been inspected.')}</Typography.Paragraph>
      <Link to="/guide">{text('打开完整接入指南', 'Open the full onboarding guide')}</Link>
    </>,
  }]} />;
}
