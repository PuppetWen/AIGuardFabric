/**
 * zh-CN is the default locale and therefore the canonical key set.
 * `en-US.ts` mirrors this structure exactly — `src/locales/locales.test.ts`
 * asserts full key parity in both directions.
 *
 * The object is deliberately flat with dotted keys so that key coverage can be
 * compared mechanically; i18next resolves `t('nav.overview')` through `nsSeparator`
 * disabled + `keySeparator` enabled.
 *
 * The key/value pairs live in `./zh-CN/*` and are assembled here; the spread
 * order is the original single-object order, so the assembled object is
 * identical key-for-key.
 */

import { zhCNControl } from './zh-CN/control';
import { zhCNCore } from './zh-CN/core';
import { zhCNOperations } from './zh-CN/operations';
import { zhCNTeamManagement } from './zh-CN/teamManagement';
import { zhCNParserEditor } from './zh-CN/parserEditor';
import { zhCNReceiptRecovery } from './zh-CN/receiptRecovery';

export const zhCN = {
  'common.configReadOnly': '当前配置由服务端配置文件管理，此处只读。',
  'common.retry': '重试',
  'cases.timeline.kind.comment': '评论',
  'settings.users.role.unknown': '未知',
  'reports.type.posture': '安全态势报表',
  'reports.type.drift': '漂移报表',
  'reports.type.billing': '计费报表',
  'reports.type.custom': '自定义报表',
  'ingest.protocol.http-pull': 'HTTP 拉取',
  'ingest.protocol.object-storage': '对象存储',
  'ingest.protocol.jdbc': 'JDBC',
  'ingest.protocol.snmp-trap': 'SNMP Trap',
  'ingest.protocol.pulsar': 'Pulsar',
  'ingest.protocol.mcp': 'MCP',
  'ingest.parsers.engine.leef': 'LEEF',
  'ingest.parsers.engine.csv': 'CSV',
  'ingest.parsers.engine.syslog': 'Syslog',
  'cases.timeline.kind.created': '创建',
  'cases.timeline.kind.state-changed': '状态变更',
  'cases.timeline.kind.assigned': '指派',
  'cases.timeline.kind.evidence-added': '添加证据',
  'cases.timeline.kind.containment': '处置',
  'cases.timeline.kind.isolation': '隔离',
  'cases.timeline.kind.credential-revoked': '吊销凭据',
  'cases.timeline.kind.blocklisted': '封禁',
  'status.escalated': '已升级',
  'cases.timeline.kind.escalated': '升级',
  'cases.timeline.kind.closed': '关闭',
  'cases.timeline.kind.playbook-run': '执行剧本',
  'layout.pageError': '此页面暂时无法显示',
  'layout.pageErrorHint': '可以重试，或通过左侧菜单访问其他页面。',
  'common.noData': '暂无数据',
  'status.unknown': '未知',
  'role.unknown': '未知',
  'assets.classification.unknown': '未分类',
  'assets.exposure.unknown': '未知',
  'assets.drawer.noExposureAssessment': '尚无暴露面评估明细，不能据此判定没有风险。',
  'reports.type.findings': '风险发现报表',
  'reports.type.assets': '资产报表',
  'reports.type.alerts': '告警报表',
  'reports.type.audit': '审计报表',
  ...zhCNCore,
  ...zhCNControl,
  ...zhCNOperations,
  ...zhCNTeamManagement,
  ...zhCNParserEditor,
  ...zhCNReceiptRecovery,
} as const;

export type TranslationKey = keyof typeof zhCN;
export type LocaleResource = Record<string, string>;

export default zhCN;
