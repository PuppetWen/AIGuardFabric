import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';

import { Button, Col, Form, Row, Space } from 'antd';
import { PlusOutlined, ReloadOutlined } from '@ant-design/icons';

import { api, useApiQuery } from '@/api/client';
import { PageHeader } from '@/components/DataState';
import type { LogSource, Parser } from '@/types/domain';

import { NewSourceWizard } from './ingest/NewSourceWizard';
import { ParserSampleDrawer } from './ingest/ParserSampleDrawer';
import { ParsersPanel } from './ingest/ParsersPanel';
import { ParserEditor } from './ingest/ParserEditor';
import { SourceReplay } from './ingest/SourceReplay';
import { SourcesPanel } from './ingest/SourcesPanel';
import { EventDeliveryStatus } from './ingest/EventDeliveryStatus';
import type { NewSourceValues } from './ingest/ingest.data';
import { useAuthStore } from '@/stores/authStore';

export default function IngestPage() {
  const tenant = useAuthStore(state => state.tenant?.id);
  return <IngestContent key={tenant ?? 'none'} />;
}

function IngestContent() {
  const queryClient = useQueryClient();
  const { t } = useTranslation();
  const [wizardOpen, setWizardOpen] = useState(false);
  const [editing, setEditing] = useState<LogSource>();
  const [page, setPage] = useState(1);
  const [query, setQuery] = useState('');
  const [step, setStep] = useState(0);
  const [replaySource, setReplaySource] = useState<string>('');
  const [selectedParser, setSelectedParser] = useState<Parser | null>(null);
  const [parserEditor, setParserEditor] = useState<{parser?: Parser} | null>(null);
  const [parserPage, setParserPage] = useState(1);
  const [parserQuery, setParserQuery] = useState('');
  const [parserEngine, setParserEngine] = useState('');
  const [parserOptionQuery, setParserOptionQuery] = useState('');
  const [form] = Form.useForm<NewSourceValues>();

  const sources = useApiQuery('log-sources', () => api.logSources({ page, pageSize: 10, keyword: query }), { key: [page, query], refetchInterval: 30_000 });
  const parsers = useApiQuery('parsers', () => api.parsers({ page: parserPage, pageSize: 10, keyword: parserQuery,
    engine: parserEngine }), { key: [parserPage, parserQuery, parserEngine] });
  const parserOptions = useApiQuery('parser-options', () => api.parsers({ pageSize: 200, keyword: parserOptionQuery }),
    { key: [parserOptionQuery], enabled: wizardOpen });
  const canWriteSources = sources.data?.data.canWrite === true;
  return (
    <>
      <PageHeader
        title={t('ingest.title')}
        subtitle={t('ingest.subtitle')}
        actions={
          <Space>
            <Button icon={<ReloadOutlined />} onClick={() => { void sources.refetch(); void parsers.refetch(); }}>
              {t('common.refresh')}
            </Button>
            <Button
              type="primary"
              disabled={!canWriteSources}
              icon={<PlusOutlined />}
              onClick={() => {
                setEditing(undefined);
                form.resetFields();
                setWizardOpen(true);
                setStep(0);
              }}
            >
              {t('ingest.wizard.button')}
            </Button>
          </Space>
        }
      />

      <Space direction="vertical" size={14} style={{ width: '100%' }}>
        <EventDeliveryStatus />
        <SourcesPanel
          canWrite={canWriteSources}
          loading={sources.isLoading}
          error={sources.error}
          sources={sources.data?.data?.items ?? []}
          total={sources.data?.data?.total ?? 0} page={page} onPage={setPage}
          query={query} onQuery={(value) => { setQuery(value); setPage(1); }}
          onRefetch={() => void sources.refetch()}
          onEdit={(value) => { setEditing(value); setStep(1); setWizardOpen(true); }}
          onSelectReplay={setReplaySource}
        />

        <Row gutter={[14, 14]}>
          <Col xs={24} xl={13}>
            <ParsersPanel
              loading={parsers.isLoading}
              error={parsers.error}
              parsers={parsers.data?.data?.items ?? []}
              onSelectParser={setSelectedParser}
              onEdit={(parser) => setParserEditor({ parser })}
              page={parserPage} total={parsers.data?.data.total ?? 0} query={parserQuery} engine={parserEngine}
              onPage={setParserPage} onQuery={value => { setParserQuery(value); setParserPage(1); }}
              onEngine={value => { setParserEngine(value); setParserPage(1); }}
            />
          </Col>
          <Col xs={24} xl={11}>
            <SourceReplay key={replaySource} sources={sources.data?.data?.items ?? []} source={replaySource} onSelect={setReplaySource} />
          </Col>
        </Row>
      </Space>

      {/* ---------------- new source wizard ---------------- */}
      {wizardOpen && <NewSourceWizard
        open={wizardOpen}
        editing={editing}
        form={form}
        step={step}
        setStep={setStep}
        parsers={parserOptions.data?.data?.items ?? []}
        onParserSearch={setParserOptionQuery} parserLoading={parserOptions.isFetching}
        onClose={() => setWizardOpen(false)}
        onResetForm={() => {
          form.resetFields();
          setStep(0);
        }}
        onRefetch={() => void sources.refetch()}
      />}

      {/* ---------------- parser sample drawer ---------------- */}
      <ParserSampleDrawer parser={selectedParser} onClose={() => setSelectedParser(null)} />
      {parserEditor && <ParserEditor key={parserEditor.parser?.id ?? 'new'} parser={parserEditor.parser} onClose={() => setParserEditor(null)}
        onSaved={() => {
          void queryClient.invalidateQueries({ predicate: query => query.queryKey[0] === 'agf'
            && ['parsers', 'parser-options', 'parser-preview', 'parser-history'].includes(String(query.queryKey[1])) });
          void sources.refetch();
        }} />}
    </>
  );
}
