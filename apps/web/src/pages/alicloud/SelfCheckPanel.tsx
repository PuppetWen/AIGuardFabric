import { useTranslation } from 'react-i18next';

import { Alert, Button, Descriptions, Space, Statistic, Table, Tag, Tooltip } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { CloudSyncOutlined } from '@ant-design/icons';

import { useAppLocale } from '@/app/AppLocaleProvider';
import { DataState } from '@/components/DataState';
import { Panel } from '@/components/Panel';
import { Chip } from '@/components/Tags';
import type { SelfCheckItem } from '@/types/domain';
import { ADAPTER_CATEGORY_FALLBACK } from '@/utils/aliyunFallback';
import { formatDateTime } from '@/utils/format';
import { selfCheckCategoryKey, selfCheckResultKey } from '@/utils/labels';

const RESULT_COLOR: Record<SelfCheckItem['result'], string> = {
  pass: '#3dd68c',
  warn: '#f0cc6a',
  fail: '#ff8b90',
};

interface SelfCheckPanelProps {
  loading: boolean;
  error: unknown;
  items: SelfCheckItem[];
  summary: { pass: number; warn: number; fail: number };
  checking: boolean;
  onRun: () => void;
}

/** Aliyun connectivity / least-privilege / quota self-check results. */
export function SelfCheckPanel({ loading, error, items, summary, checking, onRun }: SelfCheckPanelProps) {
  const { t } = useTranslation();
  const locale = useAppLocale();
  const latestCheckedAt = items.reduce<string | null>(
    (latest, item) => item.checkedAt && (!latest || item.checkedAt > latest) ? item.checkedAt : latest,
    null,
  );

  const checkColumns: ColumnsType<SelfCheckItem> = [
    {
      title: t('alicloud.selfcheck.category'),
      dataIndex: 'category',
      width: 130,
      filters: (['connectivity', 'least-privilege', 'quota'] as SelfCheckItem['category'][]).map((value) => ({
        text: t(selfCheckCategoryKey(value)),
        value,
      })),
      onFilter: (value, record) => record.category === value,
      render: (value: SelfCheckItem['category']) => <Chip color={ADAPTER_CATEGORY_FALLBACK[value]}>{t(selfCheckCategoryKey(value))}</Chip>,
    },
    { title: t('alicloud.selfcheck.item'), dataIndex: 'name', width: 260 },
    {
      title: t('alicloud.selfcheck.result'),
      dataIndex: 'result',
      width: 110,
      render: (value: SelfCheckItem['result']) => (
        <Chip color={RESULT_COLOR[value]}>{t(selfCheckResultKey(value))}</Chip>
      ),
    },
    {
      title: t('alicloud.selfcheck.value'),
      dataIndex: 'value',
      width: 148,
      render: (value: string) => <span className="agf-mono">{value}</span>,
    },
    {
      title: t('alicloud.selfcheck.requirement'),
      dataIndex: 'requirement',
      width: 180,
      render: (value: string) => <span className="agf-mono agf-tertiary">{value}</span>,
    },
    { title: t('alicloud.selfcheck.detail'), dataIndex: 'detail', width: 420 },
    {
      title: t('common.createdAt'),
      dataIndex: 'checkedAt',
      width: 168,
      render: (value: string | null) => <span className="agf-mono">{value ? formatDateTime(value, locale) : t('alicloud.selfcheck.notChecked')}</span>,
    },
  ];

  return (
    <Panel
      title={t('alicloud.selfcheck.title')}
      extra={
        <Space size={16}>
          <Statistic
            title={t('alicloud.selfcheck.result.pass')}
            value={summary.pass}
            valueStyle={{ fontSize: 16, color: RESULT_COLOR.pass }}
          />
          <Statistic
            title={t('alicloud.selfcheck.result.warn')}
            value={summary.warn}
            valueStyle={{ fontSize: 16, color: RESULT_COLOR.warn }}
          />
          <Statistic
            title={t('alicloud.selfcheck.result.fail')}
            value={summary.fail}
            valueStyle={{ fontSize: 16, color: RESULT_COLOR.fail }}
          />
          <Tooltip title={t('alicloud.selfcheck.run')}>
            <Button
              icon={<CloudSyncOutlined />}
              loading={checking}
              onClick={onRun}
            >
              {t('alicloud.selfcheck.run')}
            </Button>
          </Tooltip>
        </Space>
      }
    >
      <DataState loading={loading} error={error}>
        <Alert type="info" showIcon message={t('alicloud.selfcheck.hint')} style={{ marginBottom: 12 }} />
        <Table<SelfCheckItem>
          rowKey="id"
          size="small"
          columns={checkColumns}
          dataSource={items}
          pagination={false}
          scroll={{ x: 1620 }}
        />
      </DataState>
      <Descriptions size="small" column={1} style={{ marginTop: 10 }}>
        <Descriptions.Item label={t('alicloud.selfcheck.checkedAt', {
          time: latestCheckedAt ? formatDateTime(latestCheckedAt, locale) : t('alicloud.selfcheck.notChecked'),
        })}>
          <Space size={8}>
            <Tag color="green">{t('alicloud.selfcheck.category.connectivity')}</Tag>
            <Tag color="gold">{t('alicloud.selfcheck.category.least-privilege')}</Tag>
            <Tag color="blue">{t('alicloud.selfcheck.category.quota')}</Tag>
          </Space>
        </Descriptions.Item>
      </Descriptions>
    </Panel>
  );
}
