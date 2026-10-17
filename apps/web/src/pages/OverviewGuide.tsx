import { useTranslation } from 'react-i18next';
import { Space, Typography } from 'antd';
import { Link } from 'react-router-dom';

export function OverviewGuide() {
  const zh = useTranslation().i18n.language.startsWith('zh');
  return <Space direction="vertical">
    <Typography.Paragraph>{zh ? '总览按顶部组织展示当前账号有权读取的资产、告警、发现、红队与模型计量。未知可能表示未观测或缺少权限；真实零值会显示 0。快捷入口只提供已授权操作。' : 'Overview shows the selected organization’s assets, alerts, findings, red-team results and model usage according to your permissions. Unknown can mean no observations or no permission; a measured zero stays 0. Quick actions follow your access.'}</Typography.Paragraph>
    <Typography.Paragraph>{zh ? '费用使用已保留的真实调用记录和端点价格估算，单位人民币，排除 Mock，不等于供应商账单。没有可比的历史数据时不显示昨日变化率。红队成功率仅统计明确为真实执行且已完成的战役，排除模拟及模式未知的历史；没有真实执行时未知。' : 'Costs estimate retained live calls using endpoint prices in CNY, exclude Mock, and are not provider invoices. No yesterday comparison is shown without comparable history. Red-team success rate includes only completed, explicitly live runs; simulated and unknown historical runs are excluded. Without live runs it is unknown.'}</Typography.Paragraph>
    <Typography.Paragraph>{zh ? '风险趋势每小时保留最近一次实际观测的未关闭高危/严重发现数，没有观测时不补零。默认每 5 分钟保存本实例最近 168 点。旧版含零值占位的历史先完整归档再重新采样；长期及多副本趋势请使用监控平台。' : 'Risk trends retain the latest hourly observation of open high/critical findings without inventing zero points. This instance saves up to 168 points every 5 minutes by default. Legacy histories with artificial zeros are archived before observation restarts. Use monitoring for long-term or multi-instance trends.'}</Typography.Paragraph>
    <Link to="/">{zh ? '打开总览' : 'Open overview'}</Link>
  </Space>;
}
