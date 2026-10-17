/** Display names for the rules referenced by the seeded findings. */
export const RULE_NAMES: Record<string, string> = {
  'RULE-RT-001': '高危工具暴露检测（命令执行 / 文件写入）',
  'RULE-RT-002': 'MCP 工具越权参数检测',
  'RULE-RT-003': '越狱与护栏绕过语义检测',
  'RULE-RT-004': '系统提示词泄露检测',
  'RULE-ID-001': '日志与响应中的凭据明文泄露检测',
  'RULE-ID-002': '配置/命令行明文凭据检测',
  'RULE-ID-003': '令牌重放与绑定缺失检测',
  'RULE-DATA-001': '敏感数据出域（外传路径）检测',
  'RULE-DATA-002': '字段级脱敏绕过检测',
  'RULE-AST-002': '未纳管 AI 资产检测',
  'RULE-AST-003': '内部拦截点 mTLS 缺失检测',
  'RULE-AST-004': '模型路由降级出域检测',
  'RULE-CMP-001': 'Skill 供应链版本与签名校验',
  'RULE-CMP-003': '高权限 Skill 白名单基线校验',
};

/**
 * Display name for a rule id.
 *
 * Declared before `demoFindings` runs so the module has no temporal-dead-zone
 * hazard while the findings array is being built.
 */
export function ruleNameFor(ruleId: string): string {
  return RULE_NAMES[ruleId] ?? ruleId;
}
