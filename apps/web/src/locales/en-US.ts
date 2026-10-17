import type { LocaleResource } from './zh-CN';

import { enUSControl } from './en-US/control';
import { enUSCore } from './en-US/core';
import { enUSOperations } from './en-US/operations';
import { enUSTeamManagement } from './en-US/teamManagement';
import { enUSParserEditor } from './en-US/parserEditor';
import { enUSReceiptRecovery } from './en-US/receiptRecovery';

/**
 * en-US mirrors `zh-CN.ts` key-for-key. The `satisfies` clause below makes any
 * missing or extra key a compile-time error, and `locales.test.ts` re-checks the
 * same invariant at runtime.
 *
 * The key/value pairs live in `./en-US/*` and are assembled here; the spread
 * order is the original single-object order, so the assembled object is
 * identical key-for-key.
 */
export const enUS = {
  'common.configReadOnly': 'This configuration is managed in server configuration files and is read-only here.',
  'common.retry': 'Retry',
  'cases.timeline.kind.comment': 'Comment',
  'settings.users.role.unknown': 'Unknown',
  'reports.type.posture': 'Security posture report',
  'reports.type.drift': 'Drift report',
  'reports.type.billing': 'Billing report',
  'reports.type.custom': 'Custom report',
  'ingest.protocol.http-pull': 'HTTP pull',
  'ingest.protocol.object-storage': 'Object storage',
  'ingest.protocol.jdbc': 'JDBC',
  'ingest.protocol.snmp-trap': 'SNMP Trap',
  'ingest.protocol.pulsar': 'Pulsar',
  'ingest.protocol.mcp': 'MCP',
  'ingest.parsers.engine.leef': 'LEEF',
  'ingest.parsers.engine.csv': 'CSV',
  'ingest.parsers.engine.syslog': 'Syslog',
  'cases.timeline.kind.created': 'Created',
  'cases.timeline.kind.state-changed': 'State changed',
  'cases.timeline.kind.assigned': 'Assigned',
  'cases.timeline.kind.evidence-added': 'Evidence added',
  'cases.timeline.kind.containment': 'Containment',
  'cases.timeline.kind.isolation': 'Isolation',
  'cases.timeline.kind.credential-revoked': 'Credential revoked',
  'cases.timeline.kind.blocklisted': 'Blocklisted',
  'status.escalated': 'Escalated',
  'cases.timeline.kind.escalated': 'Escalated',
  'cases.timeline.kind.closed': 'Closed',
  'cases.timeline.kind.playbook-run': 'Playbook run',
  'layout.pageError': 'This page could not be displayed',
  'layout.pageErrorHint': 'Retry or use the sidebar to visit another page.',
  'common.noData': 'No data available',
  'status.unknown': 'Unknown',
  'role.unknown': 'Unknown',
  'assets.classification.unknown': 'Unclassified',
  'assets.exposure.unknown': 'Unknown',
  'assets.drawer.noExposureAssessment': 'No exposure assessment details are available; this does not establish absence of risk.',
  'reports.type.findings': 'Findings report',
  'reports.type.assets': 'Asset report',
  'reports.type.alerts': 'Alert report',
  'reports.type.audit': 'Audit report',
  ...enUSCore,
  ...enUSControl,
  ...enUSOperations,
  ...enUSTeamManagement,
  ...enUSParserEditor,
  ...enUSReceiptRecovery,
} satisfies LocaleResource;

export default enUS;
