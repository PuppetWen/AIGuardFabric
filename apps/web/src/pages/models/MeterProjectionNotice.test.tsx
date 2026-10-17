import { act, cleanup, render, screen } from '@testing-library/react';
import { afterEach, expect, it } from 'vitest';
import i18n from '@/locales/i18n';
import type { ModelMeterProjectionStatus } from '@/api/modelMeterProjection';
import { MeterProjectionNotice } from './MeterProjectionNotice';
afterEach(async () => { cleanup(); await act(async () => { await i18n.changeLanguage('zh-CN'); }); });
const status: ModelMeterProjectionStatus = { scope: 'node', readOnly: true,
  committedProjectionIncomplete: false, committedGroupsMerged: false,
  maxUsageRecordsPerTenant: 512, maxFactsPerTenant: 512, maxWitnessBytesPerTenant: 8_388_608 };
it.each(['en-US', 'zh-CN'])('shows incomplete coverage and actual billing distinction in %s', async language => {
  await i18n.changeLanguage(language);
  render(<MeterProjectionNotice status={{ ...status, committedProjectionIncomplete: true }} loading={false} failed={false} />);
  expect(screen.getByText(language === 'en-US' ? 'This node’s cumulative projection is incomplete' : '当前节点累计投影不完整')).toBeInTheDocument();
  expect(screen.getByText(language === 'en-US' ? /original durable ledgers and settlement receipts/ : /预算以原请求的持久账本和结算回执为准/)).toBeInTheDocument();
  expect(screen.getByText(language === 'en-US' ? /record count is not the number of model HTTP requests/ : /记录数不是模型 HTTP 请求次数/)).toBeInTheDocument();
});
it('keeps healthy coverage distinct from merged display detail without claiming an authoritative bill', async () => {
  await i18n.changeLanguage('en-US');
  const view = render(<MeterProjectionNotice status={status} loading={false} failed={false} />);
  expect(screen.queryByText('This node’s cumulative projection is incomplete')).not.toBeInTheDocument();
  expect(screen.queryByText('Cumulative projection coverage is unknown')).not.toBeInTheDocument();
  view.rerender(<MeterProjectionNotice status={{ ...status, committedGroupsMerged: true }} loading={false} failed={false} />);
  expect(screen.getByText('Some cumulative projection groups were merged')).toBeInTheDocument();
  expect(screen.getByText(/does not delete durable metering records/)).toBeInTheDocument();
  expect(screen.queryByText('This node’s cumulative projection is incomplete')).not.toBeInTheDocument();
});
it('marks a failed read unknown and never reports complete or authoritative zero', async () => {
  await i18n.changeLanguage('en-US');
  const view = render(<MeterProjectionNotice loading failed={false} />);
  expect(screen.queryByText('Cumulative projection coverage is unknown')).not.toBeInTheDocument();
  view.rerender(<MeterProjectionNotice loading={false} failed />);
  expect(screen.getByText('Cumulative projection coverage is unknown')).toBeInTheDocument();
  expect(screen.getByText(/Do not treat displayed subtotals as a complete historical ledger/)).toBeInTheDocument();
});
