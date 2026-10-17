import { Alert, List, Space, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { SCHEDULER_TASKS } from './tasks';

export function SchedulerTaskMatrix() {
  const { i18n } = useTranslation();
  const language = (i18n.resolvedLanguage ?? i18n.language).startsWith('zh') ? 0 : 1;
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={5}>{language === 0 ? '六类任务：真实目标与验收' : 'Six tasks: actual targets and verification'}</Typography.Title>
    <Alert type="info" showIcon message={language === 0 ? '这里的权限属于部署服务 Key' : 'These permissions belong to the deployed service key'}
      description={language === 0 ? '控制台登录权限和云 RAM 权限不能替代平台服务 Key。每个 callback 都验证其租户和身份；各业务接口继续检查权限。'
        : 'Console login and cloud RAM permissions do not replace the platform service key. Each callback verifies its tenant and identity, and each business API still checks permissions.'} />
    <List dataSource={SCHEDULER_TASKS} renderItem={task => <List.Item>
      <Space direction="vertical" size={2}>
        <Typography.Text strong>{task.kind} — {task.title[language]}</Typography.Text>
        <Typography.Text>{task.target[language]}</Typography.Text>
        <Typography.Text>{task.setup[language]}</Typography.Text>
        <Typography.Text code>AGF_SCHEDULER_{task.runtimeName.replaceAll('-', '_').toUpperCase()}_ENABLED</Typography.Text>
        <Typography.Text type="secondary">{language === 0 ? '部署任务开关，缺省 true；填写 true/false 后重启。回调别名与部署名称可能不同。'
          : 'Deployment task flag; defaults to true. Set true/false and restart. Callback aliases and deployment names may differ.'}</Typography.Text>
        <Typography.Text>{language === 0 ? '检查结果：' : 'Check outputs: '}{task.evidence[language]}</Typography.Text>
        <Typography.Text type="secondary">{language === 0 ? '上游：' : 'Dependencies: '}
          {task.dependencies.join(' + ') || (language === 0 ? '无' : 'none')}</Typography.Text>
      </Space>
    </List.Item>} />
  </Space>;
}
