import { Collapse, Space, Typography } from 'antd';
import { useTranslation } from 'react-i18next';

export function ReceiptRecoveryGuide() {
  const { t } = useTranslation();
  return <Collapse items={[{ key: 'receipts', label: t('receipt.guide'), children:
    <Space direction="vertical">
      {['read', 'pending', 'recover', 'unknown', 'disabled'].map(step =>
        <Typography.Paragraph key={step}>{t(`receipt.guide.${step}`)}</Typography.Paragraph>)}
    </Space>,
  }]} />;
}
