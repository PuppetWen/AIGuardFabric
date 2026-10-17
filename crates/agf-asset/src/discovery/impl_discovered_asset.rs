//! 由 `discovery.rs` 拆分：`impl_DiscoveredAsset`/`impl_DiscoveryBatch` 等 6 项（纯搬移，逻辑不变）。
use super::*;

impl DiscoveredAsset {
    /// 构造。
    #[must_use]
    pub fn new(kind: AssetKind, name: impl Into<String>, fingerprint: String, source: DiscoverySource) -> Self {
        let id = asset_id_from_fingerprint(&fingerprint);
        Self {
            id,
            kind,
            name: name.into(),
            fingerprint,
            vendor: None,
            version: None,
            protocol: None,
            endpoint: None,
            host: None,
            owner: None,
            department: None,
            discovery_source: source,
            evidence_ref: String::new(),
            exposure_score: 0,
            exposure_items: Vec::new(),
            has_plaintext_secret: false,
            requires_auth: false,
            attributes: serde_json::Value::Null,
            discovered_at: Timestamp::now(),
        }
    }

    /// 应用暴露面评分（就地更新）。
    pub fn apply_exposure(&mut self, input: &ExposureInput) {
        let (score, items) = score_exposure(input);
        self.exposure_score = score;
        self.exposure_items = items.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    }
}

impl DiscoveryBatch {
    /// 新建批次。
    #[must_use]
    pub fn new(tenant: TenantId, source: DiscoverySource) -> Self {
        Self { tenant_id: Some(tenant), source: Some(source), ..Self::default() }
    }

    /// 由终端 Agent 上报转换为发现结果。
    ///
    /// 终端只上报事实（路径、命令、URL、env 键名），服务端在此做：
    /// 1. 生成指纹（多终端上报同一 MCP 会归并为同一资产）；
    /// 2. 推断资产类型与协议；
    /// 3. 计算暴露面评分（明文凭据、公网可达、无认证都会加权）；
    /// 4. 汇总凭据命中（终端侧已脱敏为掩码）。
    #[must_use]
    pub fn from_agent_report(tenant: TenantId, report: &AgentReport) -> Self {
        let mut batch = Self::new(tenant, DiscoverySource::AgentReport);
        batch.scope.push(format!("collector:{}", report.collector_id));
        batch.scope.extend(report.scan_scope.iter().cloned());

        for detected in &report.agents {
            let flavor = detected.flavor.as_str();
            let fp = agent_fingerprint(flavor, &report.hostname, report.os_user.as_deref());
            let mut asset = DiscoveredAsset::new(
                AssetKind::Agent,
                format!("{}@{}", flavor, report.hostname),
                fp,
                DiscoverySource::AgentReport,
            );
            asset.vendor = Some(flavor.to_string());
            asset.version.clone_from(&detected.version);
            asset.host = Some(report.hostname.clone());
            asset.owner.clone_from(&report.os_user);
            asset.evidence_ref = detected
                .config_dir
                .clone()
                .or_else(|| detected.binary_path.clone())
                .unwrap_or_else(|| report.collector_id.clone());
            asset.attributes = serde_json::json!({
                "flavor": flavor,
                "os": report.os,
                "os_user": report.os_user,
                "binary_path": detected.binary_path,
                "config_dir": detected.config_dir,
                "config_hash": detected.config_hash,
                "collector_id": report.collector_id,
                "agent_version": report.agent_version,
            });
            let input = ExposureInput {
                plaintext: false,
                publicly_reachable: false,
                unauthenticated: false,
                write_capable: true, // Agent 天然具备工具调用能力
                touches_restricted_data: true,
                critical_findings: 0,
                high_findings: 0,
                known_vulnerable_version: false,
                unreviewed: true,
            };
            asset.apply_exposure(&input);
            batch.assets.push(asset);
        }

        for mcp in &report.mcp_configs {
            let asset = mcp_to_discovered(mcp, report);
            if asset.has_plaintext_secret {
                batch.warnings.push(format!("MCP 配置 {} 中存在疑似明文凭据，请检查源配置", mcp.source_file));
            }
            batch.assets.push(asset);
        }

        for hit in &report.credential_hits {
            batch.credentials.push(CredentialMatch {
                pattern: hit.kind.clone(),
                kind: agf_core::credential::CredentialKind::GenericPassword,
                masked: hit.masked.clone(),
                start: 0,
                end: 0,
                length: hit.masked.chars().count(),
                confidence: hit.confidence,
            });
        }

        batch
    }
}

/// 把检测到的 MCP 配置转换为发现结果。
#[must_use]
pub fn mcp_to_discovered(mcp: &DetectedMcp, report: &AgentReport) -> DiscoveredAsset {
    let mut safe = mcp.clone();
    agf_core::mcp_config_safety::sanitize_detected_mcp(&mut safe);
    let transport = McpTransport::parse(&mcp.transport).unwrap_or(McpTransport::Stdio);
    let fp = mcp_fingerprint(transport, safe.command.as_deref(), safe.url.as_deref(), &safe.server_name);
    let mut asset =
        DiscoveredAsset::new(AssetKind::McpServer, mcp.server_name.clone(), fp, DiscoverySource::AgentReport);
    asset.protocol = Some(transport.as_protocol());
    asset.vendor = Some("mcp".to_string());
    asset.endpoint = if transport == McpTransport::Stdio {
        safe.command.as_ref().map(|c| {
            if safe.args.is_empty() { format!("stdio:{c}") } else { format!("stdio:{c} {}", safe.args.join(" ")) }
        })
    } else {
        safe.url.clone()
    };
    asset.host = Some(report.hostname.clone());
    asset.owner.clone_from(&report.os_user);
    asset.evidence_ref = format!("{}#{}", mcp.source_file, mcp.server_name);
    asset.has_plaintext_secret = safe.has_plaintext_secret;
    asset.requires_auth = transport.is_remote()
        && (safe.auth_configured || safe.env_keys.iter().any(|k| k.to_ascii_lowercase().contains("token")));
    asset.attributes = serde_json::json!({
        "transport": safe.transport,
        "command": safe.command,
        "args": safe.args,
        "url": safe.url,
        "env_keys": safe.env_keys,
        "auth_configured": safe.auth_configured,
        "collector_id": report.collector_id,
    });
    let publicly_reachable = asset.endpoint.as_deref().is_some_and(crate::fingerprint::is_public_endpoint);
    let plaintext = transport.is_remote() && asset.endpoint.as_deref().is_some_and(|e| !e.starts_with("https://"));
    asset.apply_exposure(&ExposureInput {
        publicly_reachable,
        unauthenticated: !asset.requires_auth && transport.is_remote(),
        plaintext,
        write_capable: true, // 未知工具集时按"可能可写"计，保守
        touches_restricted_data: asset.has_plaintext_secret,
        critical_findings: 0,
        high_findings: 0,
        known_vulnerable_version: false,
        unreviewed: true,
    });
    asset
}

impl ConfigFileKind {
    /// 依据文件名判断类型。
    #[must_use]
    pub fn detect(path: &Path) -> Self {
        let name = path.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
        if name == "claude_desktop_config.json" {
            return Self::ClaudeDesktop;
        }
        if name == ".mcp.json" || name == "mcp.json" {
            return Self::McpJson;
        }
        if name == ".env" || name.starts_with(".env.") {
            return Self::DotEnv;
        }
        match path.extension().and_then(|e| e.to_str()) {
            Some("json" | "yaml" | "yml" | "toml") => Self::GenericJson,
            _ => Self::SourceCode,
        }
    }

    /// 是否为"配置文件"（参与 MCP 解析）。
    #[must_use]
    pub const fn is_config(&self) -> bool {
        matches!(self, Self::McpJson | Self::ClaudeDesktop | Self::CursorMcp | Self::GenericJson)
    }
}

impl Default for GitScanner {
    fn default() -> Self {
        Self {
            max_file_bytes: 1024 * 1024,
            skip_dirs: ["node_modules", ".git", "target", "dist", "build", ".venv", "vendor", "__pycache__"]
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            source_extensions: [
                "rs", "py", "js", "ts", "tsx", "jsx", "java", "go", "rb", "php", "sh", "ps1", "yml", "yaml", "json",
                "toml", "env", "ini", "conf",
            ]
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        }
    }
}

impl GitScanner {
    /// 构造。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 单文件最大读取字节。
    #[must_use]
    pub const fn with_max_file_bytes(mut self, bytes: u64) -> Self {
        self.max_file_bytes = bytes;
        self
    }

    /// 扫描本地目录。
    ///
    /// # Errors
    /// 目录不可读时返回错误；单个文件读取失败只记入 `warnings`。
    pub fn scan_local(
        &self,
        tenant: TenantId,
        root: impl AsRef<Path>,
    ) -> agf_core::error::DomainResult<DiscoveryBatch> {
        let start = std::time::Instant::now();
        let root = root.as_ref();
        if !root.exists() {
            return Err(agf_core::error::DomainError::NotFound { entity: "directory", id: root.display().to_string() });
        }
        let mut batch = DiscoveryBatch::new(tenant, DiscoverySource::GitScan);
        batch.scope.push(root.display().to_string());

        let walker = walkdir::WalkDir::new(root).follow_links(false).into_iter().filter_entry(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            !self.skip_dirs.iter().any(|s| s == &name)
        });

        for entry in walker.filter_map(Result::ok) {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            if entry.metadata().map(|m| m.len()).unwrap_or(0) > self.max_file_bytes {
                batch.warnings.push(format!("跳过过大文件: {}", path.display()));
                continue;
            }
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
            if !self.source_extensions.iter().any(|s| s == &ext) && ext != "env" && !ext.is_empty() {
                continue;
            }
            match std::fs::read_to_string(path) {
                Ok(content) => self.scan_content(&mut batch, path, &content),
                Err(e) => {
                    debug!(path = %path.display(), error = %e, "文件不可读（非 UTF-8 或权限不足），跳过");
                    batch.warnings.push(format!("不可读: {} ({e})", path.display()));
                }
            }
        }

        batch.elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        info!(
            assets = batch.assets.len(),
            credentials = batch.credentials.len(),
            ms = batch.elapsed_ms,
            "本地目录扫描完成"
        );
        Ok(batch)
    }

    /// 扫描单个文件内容（供测试与增量扫描复用）。
    pub fn scan_content(&self, batch: &mut DiscoveryBatch, path: &Path, content: &str) {
        let kind = ConfigFileKind::detect(path);
        let rel = path.display().to_string();

        // 1) MCP 配置解析
        if kind.is_config() {
            match parse_mcp_config::parse_mcp_config_details(content) {
                Ok(servers) => {
                    for parse_mcp_config::ParsedMcpConfig {
                        name,
                        transport,
                        command,
                        args,
                        url,
                        env_keys,
                        has_plaintext_secret,
                        auth_configured,
                    } in servers
                    {
                        let fp = mcp_fingerprint(transport, command.as_deref(), url.as_deref(), &name);
                        let mut asset =
                            DiscoveredAsset::new(AssetKind::McpServer, name.clone(), fp, DiscoverySource::GitScan);
                        asset.protocol = Some(transport.as_protocol());
                        asset.endpoint = if transport == McpTransport::Stdio {
                            command.as_ref().map(|c| {
                                if args.is_empty() {
                                    format!("stdio:{c}")
                                } else {
                                    format!("stdio:{c} {}", args.join(" "))
                                }
                            })
                        } else {
                            url.clone()
                        };
                        asset.vendor = Some("mcp".to_string());
                        asset.evidence_ref = rel.clone();
                        asset.has_plaintext_secret = has_plaintext_secret;
                        asset.requires_auth = transport.is_remote()
                            && (auth_configured
                                || env_keys.iter().any(|key| key.to_ascii_lowercase().contains("token")));
                        asset.attributes = serde_json::json!({
                            "config_file": rel,
                            "config_kind": format!("{kind:?}"),
                            "env_keys": env_keys,
                            "command": command,
                            "args": args,
                            "url": url,
                            "auth_configured": auth_configured,
                        });
                        let publicly = asset.endpoint.as_deref().is_some_and(crate::fingerprint::is_public_endpoint);
                        asset.apply_exposure(&ExposureInput {
                            publicly_reachable: publicly,
                            unauthenticated: transport.is_remote() && !asset.requires_auth,
                            plaintext: transport.is_remote()
                                && asset.endpoint.as_deref().is_some_and(|e| !e.starts_with("https://")),
                            write_capable: true,
                            touches_restricted_data: has_plaintext_secret,
                            critical_findings: 0,
                            high_findings: 0,
                            known_vulnerable_version: false,
                            unreviewed: true,
                        });
                        batch.assets.push(asset);
                        if has_plaintext_secret {
                            batch.warnings.push(format!("{rel}: MCP 配置 {name} 含疑似明文凭据，请检查源配置"));
                        }
                    }
                }
                Err(e) => batch.warnings.push(format!("{rel}: MCP 配置解析失败（{e}）")),
            }
        }

        // 2) 硬编码凭据扫描（所有文本文件都做）
        let hits = scan_credentials(content, &[]);
        let line_of = |offset: usize| -> u32 {
            u32::try_from(content[..offset.min(content.len())].matches('\n').count() + 1).unwrap_or(1)
        };
        for hit in hits {
            if kind == ConfigFileKind::DotEnv && hit.confidence < 0.6 {
                continue;
            }
            batch.warnings.push(format!(
                "{rel}:{} 发现疑似 {} 凭据（{}）",
                line_of(hit.start),
                hit.pattern,
                hit.masked
            ));
            batch.credentials.push(hit);
        }
    }
}
