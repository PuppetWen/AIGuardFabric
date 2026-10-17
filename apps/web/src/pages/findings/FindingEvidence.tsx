import { Space, Tag, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import type { EvidenceItem } from '@/types/domain';
import { EventEvidenceLink } from '@/components/EventEvidenceLink';
import { formatDateTime } from '@/utils/format';
import { useAppLocale } from '@/app/AppLocaleProvider';

export function FindingEvidence({ items }: { items: EvidenceItem[] }) {
  const { t, i18n } = useTranslation();
  const locale = useAppLocale();
  const zh = i18n.language.startsWith('zh');
  return <Space direction="vertical" size={12} style={{ width: '100%' }}>
    {items.map((item) => <div key={item.id} style={{ width: '100%', overflowWrap: 'anywhere' }}>
      <Space size={6} wrap>
        <Tag color="blue">{t(`findings.evidence.${item.kind}`, { defaultValue: item.kind })}</Tag>
        <span>{item.label}</span>
        <span className="agf-tertiary">{formatDateTime(item.capturedAt, locale)}</span>
      </Space>
      <pre className="agf-code" style={{ marginTop: 6, whiteSpace: 'pre-wrap' }}>{item.content}</pre>
      {item.contentHash && <Typography.Paragraph copyable={{ text: item.contentHash }}>
        SHA-256: <code>{item.contentHash}</code>
      </Typography.Paragraph>}
      {item.artifactRef && <Space wrap><span>{zh ? '证据引用' : 'Evidence reference'}:</span>
        <EventEvidenceLink reference={item.artifactRef} />
      </Space>}
    </div>)}
  </Space>;
}
