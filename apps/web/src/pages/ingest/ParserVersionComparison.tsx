import { Alert, Col, Input, Popconfirm, Row, Space, Typography, Button } from 'antd';
import { useTranslation } from 'react-i18next';
import type { ParserPreview } from '@/api/parsers';

export interface ParserDraft {
  definition: string; sample: string; priority: number; enabled: boolean; expectedVersion?: number;
}
export function ParserVersionComparison({ draft, latest, busy, onAdopt }: {
  draft: ParserDraft; latest: ParserPreview; busy: boolean; onAdopt: () => void;
}) {
  const { t } = useTranslation();
  const server = { definition: latest.definitionJson, sample: latest.sampleRaw,
    priority: latest.priority, enabled: latest.enabled, version: latest.version };
  return <Space direction="vertical" style={{ width: '100%' }}>
    <Typography.Title level={5}>{t('parserEditor.comparison')}</Typography.Title>
    <Alert type="info" message={t('parserEditor.comparisonHint')} />
    {latest.version === draft.expectedVersion && <Alert type="info" message={t('parserEditor.sameVersion')} />}
    <Row gutter={[12, 12]} style={{ width: '100%' }}>
      <Col xs={24} md={12}><Typography.Text strong>{t('parserEditor.draft')}</Typography.Text>
        <Input.TextArea aria-label={t('parserEditor.draft')} readOnly rows={12} value={JSON.stringify(draft, null, 2)} /></Col>
      <Col xs={24} md={12}><Typography.Text strong>{t('parserEditor.latest', { version: latest.version })}</Typography.Text>
        <Input.TextArea aria-label={t('parserEditor.latestLabel')} readOnly rows={12} value={JSON.stringify(server, null, 2)} /></Col>
    </Row>
    {!latest.editable && <Alert type="warning" message={t('parserEditor.notEditable')} />}
    <Popconfirm title={t('parserEditor.adoptTitle')} description={t('parserEditor.adoptHint')}
      okText={t('parserEditor.confirmAdopt')} cancelText={t('parserEditor.cancelAdopt')} onConfirm={onAdopt}>
      <Button disabled={busy || !latest.editable}>{t('parserEditor.adopt')}</Button>
    </Popconfirm>
  </Space>;
}
