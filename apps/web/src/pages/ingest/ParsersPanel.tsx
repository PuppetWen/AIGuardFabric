import { useTranslation } from 'react-i18next';

import { Button, Input, Progress, Select, Space, Table, Tag, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';

import { useAppLocale } from '@/app/AppLocaleProvider';
import { DataState } from '@/components/DataState';
import { Panel } from '@/components/Panel';
import type { Parser, ParserEngine } from '@/types/domain';
import { formatDateTime, formatPercent } from '@/utils/format';
import { parserEngineKey } from '@/utils/labels';

import { ENGINES } from './ingest.data';

interface ParsersPanelProps {
  loading: boolean;
  error: unknown;
  parsers: Parser[];
  onSelectParser: (parser: Parser) => void;
  onEdit: (parser?: Parser) => void;
  page: number; total: number; query: string; engine: string;
  onPage: (page: number) => void; onQuery: (query: string) => void; onEngine: (engine: string) => void;
}

/** Parser catalog; opening a row shows its raw/parsed sample pair. */
export function ParsersPanel({ loading, error, parsers, onSelectParser, onEdit, page, total, query, engine, onPage, onQuery, onEngine }: ParsersPanelProps) {
  const { t } = useTranslation();
  const locale = useAppLocale();

  const parserColumns: ColumnsType<Parser> = [
    {
      title: t('ingest.parsers.column.name'),
      dataIndex: 'name',
      width: 240,
      render: (name: string, record) => (
        <Space direction="vertical" size={2}>
          <Typography.Link onClick={() => onSelectParser(record)}>{name}</Typography.Link>
          <span className="agf-tertiary agf-mono" style={{ fontSize: 11 }}>
            {record.id} · {record.version}
          </span>
        </Space>
      ),
    },
    {
      title: t('ingest.parsers.column.engine'),
      dataIndex: 'engine',
      width: 150,
      render: (value: ParserEngine) => <Tag color="purple">{t(parserEngineKey(value), { defaultValue: value })}</Tag>,
    },
    {
      title: t('ingest.parsers.column.successRate'),
      dataIndex: 'successRate',
      width: 200,
      render: (value: number, record) => record.sampleCount === 0 ? '—' : (
        <Progress
          percent={Math.round(value * 10_000) / 100}
          size="small"
          strokeColor={value >= 0.99 ? '#3dd68c' : value >= 0.95 ? '#f0cc6a' : '#ff8b90'}
          format={() => formatPercent(value)}
        />
      ),
    },
    {
      title: t('ingest.parsers.column.samples'),
      dataIndex: 'sampleCount',
      width: 140,
      align: 'right',
      render: (value: number) => value.toLocaleString(),
    },
    {
      title: t('ingest.parsers.column.version'),
      dataIndex: 'updatedAt',
      width: 168,
      render: (value: string) => <span className="agf-mono">{formatDateTime(value, locale)}</span>,
    },
    {
      title: t('common.actions'),
      key: 'actions',
      width: 160,
      render: (_value, record) => (
        <Space><Button size="small" type="link" onClick={() => onSelectParser(record)}>
          {t('common.preview')}
        </Button><Button size="small" type="link" onClick={() => onEdit(record)}>{t('parserEditor.manage')}</Button></Space>
      ),
    },
  ];

  return (
    <Panel title={t('ingest.parsers')} padded={false}>
      <div style={{ padding: 14 }}>
        <Button style={{ marginBottom: 12 }} onClick={() => onEdit()}>{t('parserEditor.create')}</Button>
        <Space wrap style={{ marginBottom: 12 }}>
          <Input.Search aria-label={t('parserEditor.search')} placeholder={t('parserEditor.searchHint')} defaultValue={query}
            allowClear onSearch={onQuery} style={{ width: 250 }} />
          <Select aria-label={t('parserEditor.engineFilter')} style={{ width: 160 }} allowClear placeholder={t('parserEditor.engine')}
            value={engine || undefined} onChange={value => onEngine(value ?? '')}
            options={ENGINES.map(value => ({ value, label: t(parserEngineKey(value), { defaultValue: value }) }))} />
        </Space>
        <Typography.Paragraph type="secondary">{t('parserEditor.statistics')}</Typography.Paragraph>
        <DataState loading={loading} error={error} skeletonRows={5}>
          <Table<Parser>
            rowKey="id"
            size="small"
            columns={parserColumns}
            dataSource={parsers}
            pagination={{ current: page, total, pageSize: 10, showSizeChanger: false, onChange: onPage }}
            scroll={{ x: 1000 }}
          />
        </DataState>
      </div>
    </Panel>
  );
}
