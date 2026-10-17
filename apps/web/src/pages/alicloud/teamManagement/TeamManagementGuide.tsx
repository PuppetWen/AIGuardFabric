import { useTranslation } from 'react-i18next';
import { Alert, Collapse, Typography } from 'antd';

export default function TeamManagementGuide() {
  const { t } = useTranslation();
  return <Collapse items={[{ key: 'guide', label: t('teamManagement.guide'), children: <>
    <ol>{['guidePrepare', 'guideDraft', 'guideConfirm', 'guideRecover', 'guideLimits'].map(key =>
      <li key={key}><Typography.Paragraph>{t(`teamManagement.${key}`)}</Typography.Paragraph></li>)}</ol>
    <Alert type="warning" showIcon message={t('teamManagement.noCas')} />
  </> }]} />;
}
