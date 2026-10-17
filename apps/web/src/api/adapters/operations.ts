import { list, mapped, measurement, number, object, riskDomain, strings, text, type ApiObject } from './shared';

export function alert(raw: ApiObject): ApiObject {
  const assetId = text(raw.assetId ?? strings(raw.assetIds)[0]);
  return {
    ...raw, domain: riskDomain(raw.domain),
    status: mapped(raw.status ?? raw.state, { acked: 'acknowledged', closed: 'resolved', merged: 'suppressed' }),
    source: text(raw.source, '—'), assetId,
    assetName: text(raw.assetName, assetId),
    findingId: raw.findingId ?? strings(raw.findingIds)[0] ?? null,
    aggregateCount: number(raw.aggregateCount ?? raw.dedupCount),
    assignee: raw.assignee ?? raw.owner ?? null,
    escalationTier: number(raw.escalationTier, Math.min(3, number(raw.escalationLevel))),
  };
}

export function caseView(raw: ApiObject): ApiObject {
  return {
    ...raw, state: mapped(raw.state, { investigating: 'triaged', resolved: 'recovered' }),
    assetNames: raw.assetNames ?? strings(raw.assetIds),
    alertIds: strings(raw.alertIds), findingIds: strings(raw.findingIds), owner: text(raw.owner, '—'),
    dueAt: text(raw.dueAt ?? raw.slaDueAt),
  };
}

export function caseTimeline(value: unknown): unknown[] {
  const events = Array.isArray(value) ? value : list(object(value).events);
  return events.map((value) => {
    const event = object(value);
    return {
      ...event, title: text(event.title ?? event.note),
      detail: typeof event.detail === 'string' ? event.detail : JSON.stringify(event.detail ?? {}),
    };
  });
}

export function audit(raw: ApiObject): ApiObject {
  const actor = object(raw.actor);
  const target = object(raw.target);
  return {
    ...raw, ts: text(raw.ts ?? raw.at),
    actor: typeof raw.actor === 'string' ? raw.actor : text(actor.name ?? actor.id, '—'),
    actorRole: text(raw.actorRole ?? actor.role, 'unknown'),
    sensitive: raw.sensitive === true || ['grant', 'export', 'contain', 'configure'].includes(text(raw.action)),
    resourceKind: text(raw.resourceKind ?? target.kind),
    resourceId: text(raw.resourceId ?? target.id),
    resourceName: text(raw.resourceName ?? target.name ?? target.id),
    result: mapped(raw.result ?? raw.outcome, { failed: 'failure' }),
    ip: text(raw.ip ?? actor.sourceIp, '—'), userAgent: text(raw.userAgent ?? actor.userAgent),
    detail: text(raw.detail ?? raw.note), hash: text(raw.hash ?? raw.entryHash),
  };
}

export function chainCheck(raw: ApiObject): ApiObject {
  return {
    ...raw, verdict: raw.verdict ?? (raw.passed ? 'valid' : 'broken'),
    checkedEntries: number(raw.checkedEntries ?? raw.checked),
    from: text(raw.from), to: text(raw.to), firstSequence: raw.firstSequence ?? null,
    lastSequence: raw.lastSequence ?? null, checkedAt: text(raw.checkedAt ?? raw.verifiedAt),
    issues: raw.issues ?? list(raw.violations).map((value) => {
      const violation = object(value);
      return { ...violation, ts: text(violation.at), expectedHash: '', actualHash: '', reason: text(violation.detail ?? violation.kind) };
    }),
  };
}

export function report(raw: ApiObject): ApiObject {
  const range = object(raw.range);
  const duration = Date.parse(text(range.to)) - Date.parse(text(range.from));
  return {
    ...raw, name: text(raw.name ?? raw.title), type: text(raw.type ?? raw.kind),
    status: mapped(raw.status ?? raw.state, { completed: 'ready', running: 'generating', pending: 'scheduled', queued: 'scheduled' }),
    format: text(raw.format, 'json'), schedule: raw.schedule ?? 'manual',
    windowDays: raw.windowDays ?? (Number.isFinite(duration) ? Math.max(1, Math.ceil(duration / 86400000)) : null),
    sizeKb: raw.sizeKb ?? (measurement(raw.artifactBytes) === null ? null : number(raw.artifactBytes) / 1024),
    recipients: strings(raw.recipients), createdBy: text(raw.createdBy ?? raw.requestedBy, '—'),
    preview: text(raw.preview ?? raw.body),
  };
}
