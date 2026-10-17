import type { PolicyAction } from '@/types/domain';
import { policyWireAction } from '@/api/policyActions';

import type { ConditionRow } from './policies.data';

export interface CodeValidation {
  ok: boolean;
  reason?: string;
}

/**
 * Cheap structural validation for the Rego/CEL code pane.
 *
 * This is intentionally a syntax *pre-check* (it cannot compile Rego in the
 * browser); the backend remains authoritative. It catches the mistakes people
 * actually make while typing: unbalanced delimiters, a missing `package`
 * header in Rego, and an empty body.
 */
export function validatePolicyCode(code: string, language: 'rego' | 'cel' | 'structured'): CodeValidation {
  const trimmed = code.trim();
  if (language === 'structured') {
    try { const value: unknown = JSON.parse(trimmed); return { ok: !!value && typeof value === 'object' && !Array.isArray(value) }; }
    catch { return { ok: false, reason: '请输入有效的条件 JSON / Invalid condition JSON' }; }
  }
  if (!trimmed) {
    return { ok: false, reason: 'empty' };
  }
  // 字符串中的括号（正则、路径等）不参与语法分隔符计数。
  const structural = trimmed.replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, '""');
  const pairs: [string, string][] = [
    ['{', '}'],
    ['(', ')'],
    ['[', ']'],
  ];
  for (const [open, close] of pairs) {
    const opens = (structural.match(new RegExp(`\\${open}`, 'g')) ?? []).length;
    const closes = (structural.match(new RegExp(`\\${close}`, 'g')) ?? []).length;
    if (opens !== closes) {
      return { ok: false, reason: `unbalanced ${open}${close} (${opens} vs ${closes})` };
    }
  }
  if (language === 'rego') {
    if (!/^\s*package\s+agf\s*$/m.test(trimmed)) {
      return { ok: false, reason: 'package must be agf' };
    }
    if (!/\b(action|reason|redact)\s*:?=/.test(structural)) {
      return { ok: false, reason: 'define action, reason or redact' };
    }
  }
  if (trimmed.length > 20_000) {
    return { ok: false, reason: 'body too large' };
  }
  return { ok: true };
}

/** Compose Rego/CEL source from the form-mode rows. */
export function composePolicyCode(
  language: 'rego' | 'cel' | 'structured',
  action: PolicyAction,
  conditions: ConditionRow[],
): string {
  if (language === 'structured') throw new Error('表单生成请选择 CEL 或 Rego / Select CEL or Rego for the form');
  const fields: Record<string, string> = {
    'request.host': 'domain', 'request.tool': 'tool_name', 'request.command': 'command',
    'request.path': 'path', 'request.bytes': 'payload_bytes', 'agent.id': 'agent_id',
    'agent.department': 'department', 'session.id': 'session_id',
    'session.classification': 'data_class',
  };
  const wireAction = policyWireAction(action);
  const clauses = conditions.map((row) => {
    const field = fields[row.field];
    if (!field || !row.value.trim()) throw new Error('请选择有效字段并填写条件值 / Select a field and enter a value');
    const reference = `input.${field}`;
    const literal = field === 'payload_bytes' ? String(Number(row.value)) : JSON.stringify(row.value);
    if (field === 'payload_bytes' && !Number.isFinite(Number(row.value))) throw new Error('请求字节数必须为数字 / Bytes must be numeric');
    const functions: Record<string, string> = { contains: 'contains', startswith: 'startsWith', matches: 'matches' };
    if (row.operator in functions) {
      if (field === 'payload_bytes') throw new Error('数字字段请选择比较运算符 / Use a numeric comparison');
      if (language === 'cel') return `${reference} != null && ${reference}.${functions[row.operator]}(${literal})`;
      const regoFunction = ({ contains: 'contains', startswith: 'startswith', matches: 'regex.match' } as Record<string, string>)[row.operator];
      return row.operator === 'matches' ? `${regoFunction}(${literal}, ${reference})` : `${regoFunction}(${reference}, ${literal})`;
    }
    if (!['==', '!=', '>', '>=', '<', '<='].includes(row.operator)) throw new Error('无效运算符 / Invalid operator');
    return `${reference} ${row.operator} ${literal}`;
  });
  if (language === 'cel') return `(${clauses.join(' && ') || 'true'}) ? {"action":${JSON.stringify(wireAction)}} : {}`;
  return ['package agf', '', `action := ${JSON.stringify(wireAction)} if {`,
    ...(clauses.length ? clauses.map((clause) => `  ${clause}`) : ['  true']), '}'].join('\n');
}

/** Best-effort parse of a stored expression back into form rows. */
export function parseExpressionToConditions(expression: string): ConditionRow[] {
  return expression
    .split(/&&|\bAND\b/)
    .map((part, index) => {
      const match = /^\s*([\w.]+)\s*(==|!=|contains|startsWith|matches|>=|<=|>|<)\s*"?([^"]*)"?\s*$/.exec(part);
      if (!match) {
        return null;
      }
      const operatorMap: Record<string, string> = { startsWith: 'startswith' };
      return {
        id: `c${index + 1}`,
        field: match[1] ?? 'request.host',
        operator: operatorMap[match[2] ?? ''] ?? match[2] ?? '==',
        value: match[3] ?? '',
      } satisfies ConditionRow;
    })
    .filter((row): row is ConditionRow => row !== null);
}
