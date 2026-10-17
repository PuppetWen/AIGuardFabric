import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';

import { AutoComplete, Input, Space, Tag } from 'antd';
import { SearchOutlined } from '@ant-design/icons';

import { api } from '@/api/client';
import { NaturalSearch } from './NaturalSearch';
import type { SearchHit } from '@/api/demo';
import type { DefaultOptionType } from 'antd/es/select';
import { useAuthStore } from '@/stores/authStore';

const KIND_COLOR: Record<SearchHit['kind'], string> = {
  asset: '#5fa8ff',
  alert: '#ff8b90',
  finding: '#ffab7a',
  rule: '#f0cc6a',
  case: '#3dd68c',
  mcp: '#12a594',
  agent: '#8fbaff',
  redteam: '#d896ff',
};

/** Top-bar global search over assets, alerts and findings. */
export function GlobalSearch() {
  const tenant = useAuthStore(state => state.tenant?.id ?? '');
  const session = useAuthStore(state => state.sessionGeneration);
  return <Space key={`${tenant}:${session}`}><SearchBox /><NaturalSearch /></Space>;
}

function SearchBox() {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const [keyword, setKeyword] = useState('');
  const [hits, setHits] = useState<SearchHit[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const pending = useRef<{ sequence: number; timer?: ReturnType<typeof setTimeout>; controller?: AbortController }>({ sequence: 0 });
  useEffect(() => {
    const request = pending.current;
    return () => { request.sequence += 1; clearTimeout(request.timer); request.controller?.abort(); };
  }, []);

  const options = useMemo(
    () =>
      hits.map((hit) => ({
        value: `${i18n.language.startsWith('zh') ? ({ asset: '资产', alert: '告警', finding: '风险发现', rule: '检测规则', case: '案件', mcp: 'MCP', agent: 'Agent', redteam: '红队用例' })[hit.kind] : hit.kind}:${hit.id}`,
        label: (
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Tag color={KIND_COLOR[hit.kind]} style={{ marginInlineEnd: 0 }}>
              {i18n.language.startsWith('zh') ? ({ asset: '资产', alert: '告警', finding: '风险发现', rule: '检测规则', case: '案件', mcp: 'MCP', agent: 'Agent', redteam: '红队用例' })[hit.kind] : hit.kind}
            </Tag>
            <span title={hit.label} style={{ flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {hit.label}
            </span>
            <span title={hit.hint} className="agf-tertiary" style={{ fontSize: 12, maxWidth: 170, overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {hit.hint}
            </span>
          </div>
        ),
        hit,
      })),
    [hits, i18n.language],
  );

  const runSearch = (value: string, immediate = false): void => {
    const request = pending.current;
    const sequence = ++request.sequence;
    clearTimeout(request.timer); request.controller?.abort();
    setKeyword(value); setHits([]); setError(''); setLoading(Boolean(value.trim()));
    if (!value.trim()) return;
    const controller = new AbortController(); request.controller = controller;
    const perform = async () => {
      try {
        const result = await api.search(value.trim(), controller.signal);
        if (request.sequence === sequence) setHits(result.data);
      } catch (cause) {
        if (request.sequence === sequence && !controller.signal.aborted) {
          setError(cause instanceof Error ? cause.message : String(cause));
        }
      } finally { if (request.sequence === sequence) setLoading(false); }
    };
    if (immediate) void perform();
    else request.timer = setTimeout(() => void perform(), 250);
  };
  const status = loading ? (i18n.language.startsWith('zh') ? '搜索中…' : 'Searching…')
    : error ? (i18n.language.startsWith('zh') ? '搜索失败，按回车重试。' : 'Search failed. Press Enter to retry.')
      : t('layout.search.empty');
  const displayed = options.length || !keyword.trim() ? options : [{ value: '__search-status', disabled: true,
    label: <span role={error ? 'alert' : 'status'} title={error || undefined} style={error ? { color: '#ff8b90' } : undefined}>{status}</span> }];

  return (
    <AutoComplete<string, DefaultOptionType & { hit?: SearchHit }>
      className="agf-search"
      value={keyword}
      options={displayed}
      defaultActiveFirstOption={false}
      onSearch={(value) => {
        void runSearch(value);
      }}
      onSelect={(_value, option) => {
        const hit = (option as { hit?: SearchHit }).hit;
        if (!hit) return;
        navigate(hit.to);
        runSearch('');
      }}
      popupMatchSelectWidth={420}
    >
      <Input
        allowClear
        prefix={<SearchOutlined />}
        placeholder={t('layout.search.placeholder')}
        aria-label={t('layout.search.placeholder')}
        onKeyDownCapture={event => {
          if (event.key === 'Enter' && !event.nativeEvent.isComposing && !hits.length && keyword.trim()) {
            event.preventDefault(); event.stopPropagation();
            if (!loading) runSearch(keyword, true);
          }
        }}
        maxLength={128}
      />
    </AutoComplete>
  );
}

export default GlobalSearch;
