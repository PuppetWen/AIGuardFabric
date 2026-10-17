import { useTranslation } from 'react-i18next';

import { Badge, Button, Select, Space, Typography } from 'antd';

import { Panel } from '@/components/Panel';
import type { LogSource } from '@/types/domain';
import { ingestProtocolKey } from '@/utils/labels';

interface ReplayPanelProps {
  sources: LogSource[];
  source: string;
  index: number;
  playing: boolean;
  samples: string[];
  onSelectSource: (value: string) => void;
  onToggle: () => void;
  onReset: () => void;
}

/** Raw-event replay pane driving the ingest preview animation. */
export function ReplayPanel({
  sources,
  source,
  index,
  playing,
  samples,
  onSelectSource,
  onToggle,
  onReset,
}: ReplayPanelProps) {
  const { t } = useTranslation();

  const sourceOptions = sources.map((item) => ({
    value: item.id,
    label: `${item.name} · ${t(ingestProtocolKey(item.protocol))}`,
  }));

  return (
    <Panel
      title={t('ingest.replay.title')}
      extra={
        <Space size={8}>
          <Select
            size="small"
            style={{ width: 210 }}
            placeholder={t('ingest.replay.select')}
            value={source || undefined}
            onChange={(value: string) => {
              onSelectSource(value);
            }}
            options={sourceOptions}
          />
          <Button
            size="small"
            type={playing ? 'default' : 'primary'}
            disabled={!source}
            onClick={onToggle}
          >
            {playing ? t('ingest.replay.pause') : t('ingest.replay.play')}
          </Button>
          <Button
            size="small"
            disabled={!source}
            onClick={onReset}
          >
            {t('ingest.replay.reset')}
          </Button>
        </Space>
      }
    >
      {source && samples.length > 0 ? (
        <Space direction="vertical" size={10} style={{ width: '100%' }}>
          <div className="agf-meter__head">
            <span>{t('ingest.replay.raw')}</span>
            <span className="agf-mono">
              {t('ingest.replay.progress', { current: index + 1, total: samples.length })}
            </span>
          </div>
          <pre className="agf-code agf-code--compact">{samples[index]}</pre>
          <Badge status={playing ? 'processing' : 'default'} text={playing ? t('runtime.stream.live') : t('runtime.stream.paused')} />
        </Space>
      ) : (
        <Typography.Text className="agf-tertiary">{t('ingest.replay.empty')}</Typography.Text>
      )}
    </Panel>
  );
}
