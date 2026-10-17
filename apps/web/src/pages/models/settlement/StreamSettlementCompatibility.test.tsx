import { cleanup, render, screen } from '@testing-library/react';
import { ConfigProvider } from 'antd';
import { afterEach, expect, it } from 'vitest';
import i18n from '@/locales/i18n';
import { type SettlementReceipt as Receipt } from '@/api/gatewaySettlement';
import { validReceipt } from './validation';
import { SettlementReceipt } from './SettlementReceipt';
import { attempt, audit, receipt } from './testFixtures';

afterEach(async () => { cleanup(); await i18n.changeLanguage('zh-CN'); });
const components = (count: number): NonNullable<Receipt['components']> => Array.from({ length: count }, (_, index) => ({
  usageId: audit.slice(0, -2) + (index + 16).toString(16), evidence: 'sent-usage-partial', costMicro: index * 1_000_000,
}));
it('accepts eight additional usage anchors and partial primary usage, while rejecting a ninth and unknown evidence', () => {
  const value = receipt({ outcomeEvidence: 'sent-usage-partial', components: components(8) });
  expect(validReceipt(value, attempt)).toBe(true);
  expect(validReceipt({ ...value, components: components(9) }, attempt)).toBe(false);
  expect(validReceipt({ ...value, outcomeEvidence: 'made-up' } as never, attempt)).toBe(false);
  expect(validReceipt({ ...value, components: [{ ...components(1)[0], costMicro: Number.MAX_SAFE_INTEGER + 1 }] }, attempt)).toBe(false);
});
it.each(['en-US', 'zh-CN'])('shows partial usage and its lower bound without claiming successful execution in %s', async language => {
  await i18n.changeLanguage(language);
  const value = receipt({ state: 'settled', chargeState: 'conservative', recoveryAvailable: false,
    auditId: audit, outcomeEvidence: 'sent-usage-partial', components: components(8) });
  render(<ConfigProvider theme={{ token: { motion: false } }}><SettlementReceipt value={value} /></ConfigProvider>);
  expect(screen.getAllByText(language === 'en-US' ? 'Partial usage observed; final usage unknown' : '仅有部分用量，最终用量未知')).toHaveLength(9);
  expect(screen.getByText(language === 'en-US' ? /Known costs are lower bounds/ : /已知费用只是下限/)).toBeInTheDocument();
  for (const component of value.components!) expect(screen.getByText(component.usageId)).toBeInTheDocument();
  expect(screen.getByText('7.000000')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /retry|重试/i })).not.toBeInTheDocument();
});
