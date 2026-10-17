import { useCallback, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';

import {
  Alert,
  Badge,
  Button,
  Descriptions,
  Drawer,
  Input,
  Progress,
  Select,
  Space,
  Statistic,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd';
import type { ColumnsType, TableProps } from 'antd/es/table';
import { SearchOutlined } from '@ant-design/icons';

import { api, useApiQuery } from '@/api/client';
import { ApiRequestError } from '@/api/transport';
import { useAppLocale } from '@/app/AppLocaleProvider';
import { DataState, PageHeader } from '@/components/DataState';
import { Panel } from '@/components/Panel';
import { Chip, ExposureTag } from '@/components/Tags';
import type {
  Asset,
  AssetFilter,
  AssetKind,
  DataClassification,
  ExposureSurface,
  LifecycleState,
  ListQuery,
} from '@/types/domain';
import { ASSET_KIND_HEX, CLASSIFICATION_HEX, LIFECYCLE_HEX } from '@/utils/palette';
import { formatDateTime, formatPercent } from '@/utils/format';
import { classificationKey, exposureKey, lifecycleKey } from '@/utils/labels';
import { useAuthStore } from '@/stores/authStore';
import { AssetGovernance } from './AssetGovernance';
import { AssetGuide } from './AssetGuide';
import { AssetActions } from './AssetActions';

const KINDS: AssetKind[] = [
  'agent',
  'mcp',
  'skill',
  'model',
  'tool',
  'datasource',
  'credential',
  'endpoint',
];
const CLASSIFICATIONS: DataClassification[] = ['public', 'internal', 'confidential', 'restricted'];
const LIFECYCLES: LifecycleState[] = ['planned', 'onboarding', 'active', 'deprecated', 'retired'];
const EXPOSURES: ExposureSurface[] = ['public-internet', 'partner', 'intranet', 'isolated', 'unknown'];

export default function AssetsPage() {
  const tenantId = useAuthStore(state => state.tenant?.id ?? '');
  return <AssetInventory key={tenantId} />;
}

function AssetInventory() {
  const { t } = useTranslation();
  const locale = useAppLocale();

  const [filter, setFilter] = useState<AssetFilter>({});
  const [keyword, setKeyword] = useState('');
  const [query, setQuery] = useState<ListQuery>({ page: 1, pageSize: 10, sortBy: 'riskScore', sortOrder: 'desc' });
  const updateFilter = (patch: Partial<AssetFilter>) => {
    setFilter(previous => ({...previous, ...patch}));
    setQuery(previous => ({...previous, page: 1}));
  };
  const { assetId } = useParams();
  const navigate = useNavigate();
  const [search, setSearch] = useSearchParams();
  const selectedId = assetId ?? search.get('asset');
  const setSelectedId = useCallback((id: string | null) => {
    const next = new URLSearchParams(search);
    if (id) next.set('asset', id); else next.delete('asset');
    if (assetId) navigate({ pathname: '/assets', search: next.toString() });
    else setSearch(next);
  }, [assetId, navigate, search, setSearch]);

  const assets = useApiQuery(
    'assets',
    () => api.assets(filter, query),
    { key: [filter, query] },
  );
  const profile = useApiQuery('asset-profile', () => api.assetProfile(selectedId ?? ''), {
    key: [selectedId],
    enabled: Boolean(selectedId),
  });

  const columns = useMemo<ColumnsType<Asset>>(
    () => [
      {
        title: t('assets.column.name'),
        dataIndex: 'name',
        fixed: 'left',
        width: 230,
        render: (name: string, record) => (
          <Space direction="vertical" size={2}>
            <Typography.Link href={`/assets/${record.id}`} onClick={event => {
              if (event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
              event.preventDefault(); setSelectedId(record.id);
            }}>{name}</Typography.Link>
            <span className="agf-tertiary agf-mono" style={{ fontSize: 11 }}>
              {record.id}
            </span>
          </Space>
        ),
      },
      {
        title: t('assets.column.kind'),
        dataIndex: 'kind',
        width: 108,
        render: (kind: AssetKind) => <Chip color={ASSET_KIND_HEX[kind]}>{t(`assets.kind.${kind}`)}</Chip>,
      },
      { title: t('assets.column.department'), dataIndex: 'department', width: 116 },
      {
        title: t('assets.column.classification'),
        dataIndex: 'classification',
        width: 108,
        render: (value: DataClassification) => (
          <Chip color={CLASSIFICATION_HEX[value]}>{t(classificationKey(value))}</Chip>
        ),
      },
      {
        title: t('assets.column.lifecycle'),
        dataIndex: 'lifecycle',
        width: 108,
        render: (value: LifecycleState) => (
          <Chip color={LIFECYCLE_HEX[value]}>{t(lifecycleKey(value))}</Chip>
        ),
      },
      {
        title: t('assets.column.exposure'),
        dataIndex: 'exposure',
        width: 130,
        render: (value: ExposureSurface) => <ExposureTag exposure={value} />,
      },
      {
        title: t('assets.column.risk'),
        dataIndex: 'riskScore',
        width: 132,
        sorter: true,
        sortOrder: query.sortOrder === 'asc' ? 'ascend' : 'descend',
        sortDirections: ['descend', 'ascend', 'descend'],
        render: (score: number | null) => score === null ? <span className="agf-tertiary">{t('common.unknown')}</span> : (
          <Tooltip title={`${t('common.riskScore')} ${score}`}>
            <Progress
              percent={score}
              size="small"
              strokeColor={score >= 80 ? '#ff8b90' : score >= 60 ? '#ffab7a' : '#8fbaff'}
              format={(value) => `${value}`}
            />
          </Tooltip>
        ),
      },
      {
        title: t('assets.column.findings'),
        dataIndex: 'openFindings',
        width: 108,
        align: 'right',
        render: (count: number | null) => count === null ? <span className="agf-tertiary">{t('common.unknown')}</span> :
          count > 0 ? <Badge count={count} color="#e5484d" /> : <span className="agf-tertiary">0</span>,
      },
      { title: t('assets.column.owner'), dataIndex: 'owner', width: 96 },
      {
        title: t('assets.column.lastSeen'),
        dataIndex: 'lastSeenAt',
        width: 168,
        render: (value: string) => <span className="agf-mono">{formatDateTime(value, locale)}</span>,
      },
      {
        title: t('common.actions'),
        key: 'actions',
        fixed: 'right',
        width: 92,
        render: (_value, record) => (
          <Button size="small" type="link" onClick={() => setSelectedId(record.id)}>
            {t('common.detail')}
          </Button>
        ),
      },
    ],
    [locale, setSelectedId, t, query.sortOrder],
  );

  const onTableChange: NonNullable<TableProps<Asset>['onChange']> = (pagination, _filters, sorter) => {
    const selectedSort = Array.isArray(sorter) ? sorter[0] : sorter;
    setQuery({
      page: pagination.current ?? 1,
      pageSize: pagination.pageSize ?? 10,
      sortBy: 'riskScore',
      sortOrder: selectedSort?.order === 'ascend' ? 'asc' : 'desc',
    });
  };

  const profileData = profile.data?.data;

  return (
    <>
      <PageHeader
        title={t('assets.title')}
        subtitle={t('assets.subtitle')}
        actions={
          <AssetActions refresh={assets.refetch} onRegistered={async id => { setSelectedId(id); await assets.refetch(); }} />
        }
      />

      <AssetGuide />
      <div className="agf-toolbar">
        <Input
          allowClear
          style={{ width: 260 }}
          prefix={<SearchOutlined />}
          placeholder={t('assets.filter.keyword')}
          value={keyword}
          onChange={(event) => {setKeyword(event.target.value); if (!event.target.value) updateFilter({keyword: ''});}}
          onPressEnter={() => updateFilter({keyword})}
          aria-label={t('assets.filter.keyword')}
        />
        <Select
          mode="multiple"
          allowClear
          style={{ minWidth: 190 }}
          placeholder={t('assets.filter.kind')}
          aria-label={t('assets.filter.kind')}
          value={filter.kinds}
          options={KINDS.map((kind) => ({ value: kind, label: t(`assets.kind.${kind}`) }))}
          onChange={(kinds: AssetKind[]) => updateFilter({kinds})}
        />
        <Select
          mode="tags"
          allowClear
          style={{ minWidth: 170 }}
          placeholder={t('assets.filter.department')}
          aria-label={t('assets.filter.department')}
          value={filter.departments}
          options={[...new Set(assets.data?.data.items.map(asset => asset.department).filter(value => value && value !== '—') ?? [])].map(value => ({value, label: value}))}
          onChange={(departments: string[]) => updateFilter({departments})}
        />
        <Select
          mode="multiple"
          allowClear
          style={{ minWidth: 170 }}
          placeholder={t('assets.filter.classification')}
          aria-label={t('assets.filter.classification')}
          value={filter.classifications}
          options={CLASSIFICATIONS.map((value) => ({ value, label: t(classificationKey(value)) }))}
          onChange={(classifications: DataClassification[]) =>
            updateFilter({classifications})
          }
        />
        <Select
          mode="multiple"
          allowClear
          style={{ minWidth: 170 }}
          placeholder={t('assets.filter.lifecycle')}
          aria-label={t('assets.filter.lifecycle')}
          value={filter.lifecycles}
          options={LIFECYCLES.map((value) => ({ value, label: t(lifecycleKey(value)) }))}
          onChange={(lifecycles: LifecycleState[]) => updateFilter({lifecycles})}
        />
        <Select
          mode="multiple"
          allowClear
          style={{ minWidth: 170 }}
          placeholder={t('assets.filter.exposure')}
          aria-label={t('assets.filter.exposure')}
          value={filter.exposures}
          options={EXPOSURES.map((value) => ({ value, label: t(exposureKey(value)) }))}
          onChange={(exposures: ExposureSurface[]) => updateFilter({exposures})}
        />
        <Button
          onClick={() => {
            setFilter({});
            setKeyword('');
            setQuery({ page: 1, pageSize: 10, sortBy: 'riskScore', sortOrder: 'desc' });
          }}
        >
          {t('common.reset')}
        </Button>
        <span className="agf-header__spacer" />
        <span className="agf-muted">{t('common.total', { count: assets.data?.data.total ?? 0 })}</span>
      </div>

      <DataState loading={assets.isLoading} error={assets.error} skeletonRows={6}>
        <Table<Asset>
          rowKey="id"
          size="middle"
          columns={columns}
          dataSource={assets.data?.data.items ?? []}
          scroll={{ x: 1420 }}
          onChange={onTableChange}
          pagination={{
            current: assets.data?.data.page ?? 1,
            pageSize: assets.data?.data.pageSize ?? 10,
            total: assets.data?.data.total ?? 0,
            showSizeChanger: true,
            showTotal: (total) => t('common.total', { count: total }),
          }}
        />
      </DataState>

      <Drawer
        width={620}
        open={Boolean(selectedId)}
        onClose={() => setSelectedId(null)}
        title={t('assets.drawer.title', { name: profileData?.asset.name ?? '' })}
        loading={profile.isLoading}
        destroyOnClose
      >
        {!profile.isLoading && profile.error && <Alert showIcon style={{ marginBottom: 16 }}
          type={profile.error instanceof ApiRequestError && profile.error.status === 404 ? 'warning' : 'error'}
          message={profile.error instanceof ApiRequestError && profile.error.status === 404
            ? t('assets.drawer.missing') : t('assets.drawer.loadError')}
          description={profile.error instanceof ApiRequestError && profile.error.status === 404 ? undefined : profile.error.message}
          action={<Button size="small" onClick={() => setSelectedId(null)}>{t('common.back')}</Button>} />}
        {profileData ? (
          <>
            <AssetGovernance key={profileData.asset.id} profile={profileData}
              onSaved={async () => { await Promise.all([profile.refetch(), assets.refetch()]); }}
              onRemoved={async () => { setSelectedId(null); await assets.refetch(); }} />
            <div className="agf-drawer-section">
              <div className="agf-drawer-section__title">{t('assets.drawer.profile')}</div>
              <Descriptions size="small" column={2} bordered>
                <Descriptions.Item label={t('common.type')}>
                  <Chip color={ASSET_KIND_HEX[profileData.asset.kind]}>
                    {t(`assets.kind.${profileData.asset.kind}`)}
                  </Chip>
                </Descriptions.Item>
                <Descriptions.Item label={t('assets.column.owner')}>
                  {profileData.asset.owner}
                </Descriptions.Item>
                <Descriptions.Item label={t('assets.column.department')}>
                  {profileData.asset.department}
                </Descriptions.Item>
                <Descriptions.Item label={t('assets.column.classification')}>
                  <Chip color={CLASSIFICATION_HEX[profileData.asset.classification]}>
                    {t(classificationKey(profileData.asset.classification))}
                  </Chip>
                </Descriptions.Item>
                <Descriptions.Item label={t('assets.column.lifecycle')}>
                  <Chip color={LIFECYCLE_HEX[profileData.asset.lifecycle]}>
                    {t(lifecycleKey(profileData.asset.lifecycle))}
                  </Chip>
                </Descriptions.Item>
                <Descriptions.Item label={t('assets.column.exposure')}>
                  <ExposureTag exposure={profileData.asset.exposure} />
                </Descriptions.Item>
              </Descriptions>
              <Typography.Paragraph className="agf-muted" style={{ marginTop: 10, marginBottom: 0 }}>
                {profileData.asset.description}
              </Typography.Paragraph>
              <Space wrap size={6} style={{ marginTop: 8 }}>
                {profileData.asset.tags.map((tag) => (
                  <Tag key={tag}>{tag}</Tag>
                ))}
              </Space>
            </div>

            <div className="agf-drawer-section">
              <div className="agf-drawer-section__title">{t('assets.drawer.profile')}</div>
              <div className="agf-grid" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))' }}>
                <Statistic
                  title={t('assets.drawer.invocations')}
                  value={profileData.runtime?.invocations24h ?? '—'}
                  groupSeparator=","
                />
                <Statistic
                  title={t('assets.drawer.errorRate')}
                  value={formatPercent(profileData.runtime?.errorRate)}
                />
                <Statistic
                  title={t('assets.drawer.latency')}
                  value={profileData.runtime?.avgLatencyMs ?? '—'}
                  suffix={t('unit.msShort')}
                />
                <Statistic title={t('assets.drawer.callers')} value={profileData.runtime?.distinctCallers ?? '—'} />
              </div>
            </div>

            <div className="agf-drawer-section">
              <div className="agf-drawer-section__title">{t('assets.drawer.dependencies')}</div>
              <Descriptions size="small" column={1} bordered>
                <Descriptions.Item label={t('assets.drawer.upstream')}>
                  <DependencyList items={profileData.dependencies.upstream} empty={t('assets.drawer.noDependency')} />
                </Descriptions.Item>
                <Descriptions.Item label={t('assets.drawer.downstream')}>
                  <DependencyList
                    items={profileData.dependencies.downstream}
                    empty={t('assets.drawer.noDependency')}
                  />
                </Descriptions.Item>
                <Descriptions.Item label={t('assets.drawer.models')}>
                  <DependencyList items={profileData.dependencies.models} empty={t('assets.drawer.noDependency')} />
                </Descriptions.Item>
                <Descriptions.Item label={t('assets.drawer.datasources')}>
                  <DependencyList
                    items={profileData.dependencies.datasources}
                    empty={t('assets.drawer.noDependency')}
                  />
                </Descriptions.Item>
              </Descriptions>
            </div>

            <div className="agf-drawer-section">
              <div className="agf-drawer-section__title">{t('assets.drawer.sources')}</div>
              <Space direction="vertical" size={8} style={{ width: '100%' }}>
                {profileData.sources.map((source) => (
                  <div key={`${source.source}-${source.at}`} className="agf-panel agf-panel--pad" style={{ padding: 10 }}>
                    <Space size={8} wrap>
                      <Tag color="blue">{t(`assets.source.${source.source}`)}</Tag>
                      <span className="agf-tertiary" style={{ fontSize: 12 }}>
                        {formatDateTime(source.at, locale)}
                      </span>
                    </Space>
                    <div className="agf-muted" style={{ fontSize: 13, marginTop: 4 }}>
                      {source.detail}
                    </div>
                  </div>
                ))}
              </Space>
            </div>

            <div className="agf-drawer-section">
              <div className="agf-drawer-section__title">{t('assets.drawer.penalties')}</div>
              {profileData.exposurePenalties.length === 0 ? (
                <Typography.Text className="agf-tertiary">
                  {t('assets.drawer.noExposureAssessment')}
                </Typography.Text>
              ) : (
                <Space direction="vertical" size={8} style={{ width: '100%' }}>
                  {profileData.exposurePenalties.map((penalty) => (
                    <div
                      key={penalty.code}
                      className="agf-panel agf-panel--pad"
                      style={{ padding: 10, display: 'flex', gap: 10, alignItems: 'flex-start' }}
                    >
                      <Tag color="red" style={{ marginInlineEnd: 0 }}>
                        {t('assets.drawer.penaltyPoints', { points: penalty.points })}
                      </Tag>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <Space size={6}>
                          <span className="agf-mono agf-tertiary">{penalty.code}</span>
                          <Typography.Text strong style={{ fontSize: 13 }}>
                            {penalty.label}
                          </Typography.Text>
                        </Space>
                        <div className="agf-muted" style={{ fontSize: 13, marginTop: 2 }}>
                          {penalty.remediation}
                        </div>
                      </div>
                    </div>
                  ))}
                </Space>
              )}
            </div>
          </>
        ) : null}
      </Drawer>
    </>
  );
}

function DependencyList({
  items,
  empty,
}: {
  items: { id: string; name: string; kind: string }[];
  empty: string;
}) {
  if (items.length === 0) {
    return <span className="agf-tertiary">{empty}</span>;
  }
  return (
    <span className="agf-inline-list">
      {items.map((item) => (
        <Chip key={item.id} color={ASSET_KIND_HEX[item.kind as AssetKind] ?? '#6f7683'}>
          {item.name}
        </Chip>
      ))}
    </span>
  );
}

export { Panel };
