//! 由 `discovery.rs` 拆分：`parse_mcp_config`/`impl_NetworkScanTarget` 等 10 项（纯搬移，逻辑不变）。
use super::*;

/// 解析 MCP 配置 JSON，返回 `(名称, 传输, 脱敏命令, 脱敏参数, 脱敏 URL, env 键名)` 列表。
///
/// 兼容三种常见结构：`{"mcpServers": {...}}`、顶层直接是服务器映射、以及
/// Cursor 的 `{"mcpServers": {...}}`（结构相同）。
///
/// # Errors
/// JSON 非法时返回错误描述。
pub fn parse_mcp_config(
    content: &str,
) -> Result<Vec<(String, McpTransport, Option<String>, Vec<String>, Option<String>, Vec<String>)>, String> {
    parse_mcp_config_details(content).map(|servers| {
        servers.into_iter().map(|s| (s.name, s.transport, s.command, s.args, s.url, s.env_keys)).collect()
    })
}

/// Git 扫描使用的脱敏事实；私密原值只在本函数栈内存在。
pub(super) struct ParsedMcpConfig {
    pub name: String,
    pub transport: McpTransport,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub url: Option<String>,
    pub env_keys: Vec<String>,
    pub has_plaintext_secret: bool,
    pub auth_configured: bool,
}

pub(super) fn parse_mcp_config_details(content: &str) -> Result<Vec<ParsedMcpConfig>, String> {
    use agf_core::mcp_config_safety::{
        has_auth_settings, looks_like_plaintext_secret, redact_arguments, safe_report_command, safe_report_url,
    };
    let value: serde_json::Value = serde_json::from_str(content).map_err(|e| format!("非法 JSON: {e}"))?;
    let servers =
        value.get("mcpServers").or_else(|| value.get("mcp_servers")).or_else(|| value.get("servers")).unwrap_or(&value);
    let Some(obj) = servers.as_object() else {
        return Err("配置中未找到 mcpServers 对象".to_string());
    };
    let mut out = Vec::new();
    for (name, cfg) in obj {
        let Some(entry) = cfg.as_object() else { continue };
        let (url, url_sensitive) = entry
            .get("url")
            .and_then(|v| v.as_str())
            .and_then(safe_report_url)
            .map_or((None, false), |(safe, sensitive)| (Some(safe), sensitive));
        let raw_command = entry.get("command").and_then(|v| v.as_str());
        let (command, command_sensitive) =
            raw_command.map(safe_report_command).map_or((None, false), |(safe, sensitive)| (Some(safe), sensitive));
        // 只有含 command/url 之一才视为 MCP 服务器定义
        if url.is_none() && command.is_none() {
            continue;
        }
        let transport_raw = entry.get("type").or_else(|| entry.get("transport")).and_then(|v| v.as_str());
        let transport = match (transport_raw, &url) {
            (Some(t), _) => McpTransport::parse(t).unwrap_or(McpTransport::Stdio),
            (None, Some(u)) if u.contains("/sse") => McpTransport::Sse,
            (None, Some(_)) => McpTransport::Http,
            (None, None) => McpTransport::Stdio,
        };
        let raw_args = entry
            .get("args")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(ToString::to_string)).collect())
            .unwrap_or_default();
        let (args, args_sensitive) = redact_arguments(raw_args);
        let env = entry.get("env").and_then(|v| v.as_object());
        let env_keys = env.map(|o| o.keys().cloned().collect()).unwrap_or_default();
        let env_sensitive = env.is_some_and(|items| {
            items.iter().any(|(key, value)| value.as_str().is_some_and(|text| looks_like_plaintext_secret(key, text)))
        });
        let header_sensitive = entry.get("headers").and_then(|v| v.as_object()).is_some_and(|items| {
            items.iter().any(|(key, value)| {
                value.as_str().is_some_and(|text| {
                    looks_like_plaintext_secret(key, text)
                        || (key.eq_ignore_ascii_case("authorization")
                            && !text.trim().is_empty()
                            && !agf_core::secret::is_placeholder(text))
                })
            })
        });
        out.push(ParsedMcpConfig {
            name: name.clone(),
            transport,
            command,
            args,
            url,
            env_keys,
            has_plaintext_secret: env_sensitive
                || header_sensitive
                || url_sensitive
                || command_sensitive
                || args_sensitive,
            auth_configured: has_auth_settings(entry),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    if out.is_empty() {
        return Err("配置中没有可识别的 MCP 服务器定义（需要 command 或 url）".to_string());
    }
    Ok(out)
}

impl NetworkScanTarget {
    /// 构造。
    #[must_use]
    pub fn new(host: impl Into<String>, ports: Vec<u16>) -> Self {
        Self { host: host.into(), ports }
    }
}

impl Default for NetworkScanner {
    fn default() -> Self {
        Self { timeout_ms: 800, mock: true, common_ports: Self::default_ai_ports() }
    }
}

impl NetworkScanner {
    /// 构造。
    #[must_use]
    pub fn new(mock: bool, timeout_ms: u64) -> Self {
        Self { timeout_ms, mock, common_ports: Self::default_ai_ports() }
    }

    /// 常见 AI 服务端口（MCP / 模型推理 / 向量库 / 网关）。
    #[must_use]
    pub fn default_ai_ports() -> Vec<u16> {
        vec![
            80, 443, 3000, 5000, 8000, 8080, 8081, 8888,  // 通用 HTTP / 网关
            11434, // Ollama
            1234,  // LM Studio
            7860,  // Gradio
            19530, // Milvus
            6333,  // Qdrant
            8086,  // InfluxDB（常被误用为指标面）
            8091,  // AGF MCP 代理
            9000,  // MinIO / 通用
            4222,  // NATS
        ]
    }

    /// 探测单个目标（返回发现的资产）。
    ///
    /// Mock 模式下按"端口开放 → 推断为 MCP/模型端点"生成确定性的结果。
    pub async fn probe(&self, tenant: TenantId, target: &NetworkScanTarget) -> DiscoveryBatch {
        let start = std::time::Instant::now();
        let mut batch = DiscoveryBatch::new(tenant, DiscoverySource::NetworkScan);
        batch.scope.push(format!("{}:{:?}", target.host, target.ports));

        for port in &target.ports {
            let open = if self.mock {
                // 确定性 Mock：端口号哈希决定是否"开放"，保证可复现
                let h = agf_core::secret::content_hash(&format!("{}:{}", target.host, port));
                !u8::from_str_radix(&h[..2], 16).unwrap_or(0).is_multiple_of(3)
            } else {
                self.tcp_probe(&target.host, *port).await
            };
            if !open {
                continue;
            }
            let endpoint = format!("http://{}:{}", target.host, *port);
            let kind = infer_kind_for_port(*port);
            let fp = asset_fingerprint(kind, &["network-scan", &endpoint]);
            let mut asset =
                DiscoveredAsset::new(kind, format!("{}:{}", target.host, port), fp, DiscoverySource::NetworkScan);
            asset.endpoint = Some(endpoint.clone());
            asset.host = Some(target.host.clone());
            asset.protocol = Some(Protocol::McpHttp);
            asset.vendor = Some("unknown".to_string());
            asset.evidence_ref = format!("net-scan:{}:{}", target.host, port);
            asset.requires_auth = false;
            asset.attributes = serde_json::json!({ "open_port": port, "mock": self.mock });
            asset.apply_exposure(&ExposureInput {
                publicly_reachable: crate::fingerprint::is_public_endpoint(&endpoint),
                unauthenticated: true,
                plaintext: true,
                write_capable: false,
                touches_restricted_data: false,
                critical_findings: 0,
                high_findings: 0,
                known_vulnerable_version: false,
                unreviewed: true,
            });
            batch.assets.push(asset);
        }

        batch.elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        batch
    }

    /// 真实 TCP 连通性探测。
    pub async fn tcp_probe(&self, host: &str, port: u16) -> bool {
        let addr = format!("{host}:{port}");
        match tokio::time::timeout(
            std::time::Duration::from_millis(self.timeout_ms),
            tokio::net::TcpStream::connect(&addr),
        )
        .await
        {
            Ok(Ok(_)) => true,
            Ok(Err(e)) => {
                debug!(%addr, error = %e, "端口不可达");
                false
            }
            Err(_) => {
                warn!(%addr, "端口探测超时");
                false
            }
        }
    }

    /// 是否处于 Mock 模式。
    #[must_use]
    pub const fn is_mock(&self) -> bool {
        self.mock
    }

    /// 常见端口列表。
    #[must_use]
    pub fn common_ports(&self) -> &[u16] {
        &self.common_ports
    }

    /// 扫描一组目标。
    pub async fn scan(&self, tenant: TenantId, targets: &[NetworkScanTarget]) -> DiscoveryBatch {
        let start = std::time::Instant::now();
        let mut merged = DiscoveryBatch::new(tenant, DiscoverySource::NetworkScan);
        for t in targets {
            let b = self.probe(tenant, t).await;
            merged.assets.extend(b.assets);
            merged.warnings.extend(b.warnings);
            merged.scope.extend(b.scope);
        }
        merged.elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        merged
    }
}

/// 依据端口号推断服务类型。
#[must_use]
pub fn infer_kind_for_port(port: u16) -> AssetKind {
    match port {
        11434 | 1234 | 7860 | 8000 => AssetKind::ModelEndpoint,
        19530 | 6333 => AssetKind::VectorStore,
        8080 | 8081 | 8091 => AssetKind::McpServer,
        4222 => AssetKind::DataSource,
        _ => AssetKind::Other,
    }
}

/// 汇总多个发现批次（去重：同指纹保留信息量最大的一条）。
#[must_use]
pub fn merge_batches(batches: &[DiscoveryBatch]) -> DiscoveryBatch {
    let mut merged = DiscoveryBatch::default();
    let mut by_fp: BTreeMap<String, DiscoveredAsset> = BTreeMap::new();
    for b in batches {
        if merged.tenant_id.is_none() {
            merged.tenant_id = b.tenant_id;
        }
        merged.scope.extend(b.scope.iter().cloned());
        merged.warnings.extend(b.warnings.iter().cloned());
        merged.credentials.extend(b.credentials.iter().cloned());
        for a in &b.assets {
            match by_fp.get(&a.fingerprint) {
                Some(existing) if existing.exposure_score >= a.exposure_score => {}
                _ => {
                    by_fp.insert(a.fingerprint.clone(), a.clone());
                }
            }
        }
    }
    merged.assets = by_fp.into_values().collect();
    merged.elapsed_ms = batches.iter().map(|b| b.elapsed_ms).sum();
    merged
}

/// 从模型端点配置构造发现结果（供 `agf-aigw` 与手工登记复用）。
#[must_use]
pub fn model_endpoint_discovered(
    provider: &str,
    base_url: &str,
    model: &str,
    local: bool,
    source: DiscoverySource,
) -> DiscoveredAsset {
    let (endpoint, private_url) = agf_core::mcp_config_safety::safe_report_url(base_url.trim())
        .map_or((None, false), |(safe, sensitive)| (Some(safe), sensitive));
    let fingerprint_url =
        endpoint.clone().unwrap_or_else(|| format!("invalid:{}", agf_core::secret::content_hash(base_url)));
    let fp = model_endpoint_fingerprint(provider, &fingerprint_url, model);
    let mut asset = DiscoveredAsset::new(AssetKind::ModelEndpoint, format!("{provider}:{model}"), fp, source);
    asset.vendor = Some(provider.to_string());
    asset.endpoint = endpoint;
    asset.has_plaintext_secret = private_url;
    asset.protocol = Some(Protocol::OpenAiCompat);
    asset.requires_auth = !local;
    asset.attributes = serde_json::json!({ "local_deployment": local, "model": model });
    asset.apply_exposure(&ExposureInput {
        publicly_reachable: !local && asset.endpoint.as_deref().is_some_and(crate::fingerprint::is_public_endpoint),
        unauthenticated: false,
        plaintext: asset.endpoint.as_deref().is_some_and(|url| url.starts_with("http://")),
        write_capable: false,
        touches_restricted_data: true,
        critical_findings: 0,
        high_findings: 0,
        known_vulnerable_version: false,
        unreviewed: true,
    });
    asset
}

/// 便捷：把发现结果转为 `agf-core` 的 [`Asset`]（统一落库前转换）。
#[must_use]
pub fn to_asset(discovered: &DiscoveredAsset, tenant: TenantId) -> agf_core::asset::Asset {
    use agf_core::enums::LifecycleState;
    let mut a =
        agf_core::asset::Asset::new(tenant, discovered.kind, discovered.name.clone(), discovered.fingerprint.clone());
    // The discovery ID has no tenant context. SQL asset IDs are global primary keys,
    // so identical endpoints discovered by two tenants require distinct canonical IDs.
    // Ingest first looks up the tenant/fingerprint pair and retains any existing ID.
    a.id = agf_core::ids::deterministic_id(agf_core::ids::NS_ASSET, &format!("{tenant}:{}", discovered.fingerprint));
    a.vendor.clone_from(&discovered.vendor);
    a.version.clone_from(&discovered.version);
    a.protocol = discovered.protocol;
    a.endpoint.clone_from(&discovered.endpoint);
    a.owner.clone_from(&discovered.owner);
    a.department.clone_from(&discovered.department);
    a.discovery_source = discovered.discovery_source;
    a.exposure_score = discovered.exposure_score;
    a.attributes = match &discovered.attributes {
        serde_json::Value::Object(o) => o
            .iter()
            .filter(|(key, _)| !key.starts_with("agf_") && key.as_str() != "whitelist")
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        _ => BTreeMap::new(),
    };
    // 发现即"试用"状态，需人工评审后才进入生产（§4.1 生命周期）
    a.lifecycle = LifecycleState::Trial;
    a.last_seen_at = Some(discovered.discovered_at);
    a
}

/// 便捷：批量转换。
#[must_use]
pub fn batch_to_assets(batch: &DiscoveryBatch, tenant: TenantId) -> Vec<agf_core::asset::Asset> {
    batch.assets.iter().map(|d| to_asset(d, tenant)).collect()
}

/// 扫描目录时的忽略规则（供 `agf-agent` 复用，避免两处规则漂移）。
#[must_use]
pub fn default_skip_dirs() -> Vec<PathBuf> {
    ["node_modules", ".git", "target", "dist", "build", ".venv", "vendor", "__pycache__"]
        .iter()
        .map(PathBuf::from)
        .collect()
}
