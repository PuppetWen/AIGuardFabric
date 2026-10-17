import { asset, assetProfile } from './assets';
import { campaign, finding, policy, rule } from './governance';
import { parser, source } from './ingest';
import { alert, audit, caseTimeline, caseView, chainCheck, report } from './operations';
import { object, page, type ApiObject } from './shared';

const PAGED: Record<string, (value: ApiObject) => unknown> = {
  '/api/v1/assets': asset,
  '/api/v1/findings': finding,
  '/api/v1/rules': rule,
  '/api/v1/policies': policy,
  '/api/v1/redteam/campaigns': campaign,
  '/api/v1/alerts': alert,
  '/api/v1/cases': caseView,
  '/api/v1/ingest/sources': source,
  '/api/v1/ingest/parsers': parser,
  '/api/v1/audit': audit,
  '/api/v1/reports': report,
};

/** Runs only on successful server responses; offline fixtures keep their own contract. */
export function adaptResponse(path: string, value: unknown): unknown {
  const pathname = path.split('?')[0];
  const record = object(value);
  if (PAGED[pathname] && Array.isArray(record.items)) return page(record, PAGED[pathname]);
  if (/^\/api\/v1\/ingest\/sources(?:\/[^/]+)?$/.test(pathname)) return source(record.source ? object(record.source) : record);
  if (/^\/api\/v1\/assets\/[^/]+$/.test(pathname) && record.asset) return assetProfile(record);
  if (pathname === '/api/v1/audit/verify') return chainCheck(record);
  if (/^\/api\/v1\/cases\/[^/]+\/timeline$/.test(pathname)) return caseTimeline(value);
  if (/^\/api\/v1\/cases\/[^/]+$/.test(pathname) && record.case) return { ...record, case: caseView(object(record.case)) };
  if (/^\/api\/v1\/policies(?:\/[^/]+)?$/.test(pathname) && record.policy) return policy(object(record.policy));
  if (pathname === '/api/v1/reports' && record.report) return report(object(record.report));
  if (/^\/api\/v1\/redteam\/campaigns\/[^/]+\/report$/.test(pathname)) return { ...object(record.report), ...record };
  if (/^\/api\/v1\/findings\/[^/]+(?:\/(?:state|status))?$/.test(pathname)) return finding(record.finding ? object(record.finding) : record);
  if (/^\/api\/v1\/alerts\/[^/]+(?:\/(?:state|status))?$/.test(pathname) && record.alert) return { ...record, alert: alert(object(record.alert)) };
  return value;
}
