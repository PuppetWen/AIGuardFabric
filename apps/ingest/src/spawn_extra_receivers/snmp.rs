//! SNMP 装配段（由 `spawn_extra_receivers.rs` 按块拆分，纯搬移、逻辑不变）。
//!
//! 覆盖 SNMP Trap 监听（v1/v2c/v3 共用同一份 PDU 解析与 UDP 接收循环）与 v3 安全级别的运行态标注。
use super::*;

impl ExtraReceiverCtx<'_> {
    /// ---- SNMP Trap ----
    pub(super) async fn snmp_trap(&mut self) {
        let source_identity = self.identity.clone();
        let pipeline = self.pipeline;
        let metrics = self.metrics;
        let listeners = &mut *self.listeners;
        let snmp_listen = env_or("AGF_INGEST_SNMP_LISTEN", "");
        if snmp_listen.is_empty() {
            listeners.note("SNMP Trap 未启用：未配置 AGF_INGEST_SNMP_LISTEN".to_string());
        } else {
            let source = source_with(&source_identity, IngestProtocol::SnmpTrap, "snmp-trap", |connection| {
                connection.listen = Some(snmp_listen.clone());
                connection.headers.insert("community".to_string(), env_or("AGF_INGEST_SNMP_COMMUNITY", "public"));
                connection.headers.insert("version".to_string(), env_or("AGF_INGEST_SNMP_VERSION", "v2c"));
                // v3（USM）：用户名 / 安全级别 / 认证协议 / 认证口令——只在 version=v3 时被 from_source 读取。
                // 口令只进内存配置，**不落日志**（UsmConfig::describe 也不含口令）。
                connection.headers.insert("user".to_string(), env_or("AGF_INGEST_SNMP_V3_USER", ""));
                connection
                    .headers
                    .insert("security-level".to_string(), env_or("AGF_INGEST_SNMP_V3_SECURITY_LEVEL", "noAuthNoPriv"));
                connection
                    .headers
                    .insert("auth-protocol".to_string(), env_or("AGF_INGEST_SNMP_V3_AUTH_PROTOCOL", "md5"));
                connection.headers.insert("auth-password".to_string(), env_or("AGF_INGEST_SNMP_V3_AUTH_PASSWORD", ""));
                // authPriv（DES/AES 加密）：隐私协议 + 隐私口令——同样只在 version=v3 且
                // security-level=authPriv 时被 from_source 使用；未配置隐私协议 ⇒ 默认 aes。
                // 口令只进内存配置，**不落日志**（UsmConfig 的 Debug/describe 都不回显口令）。
                connection
                    .headers
                    .insert("priv-protocol".to_string(), env_or("AGF_INGEST_SNMP_V3_PRIV_PROTOCOL", "aes"));
                connection.headers.insert("priv-password".to_string(), env_or("AGF_INGEST_SNMP_V3_PRIV_PASSWORD", ""));
            });
            match SnmpTrapReceiver::from_source(Arc::clone(pipeline), &source) {
                Ok(receiver) => match receiver.bind().await {
                    Ok(socket) => {
                        let usm = receiver.usm_config().map(agf_ingest::snmp::UsmConfig::describe);
                        let receiver = Arc::new(receiver.with_counters(metrics.counters("snmp-trap")));
                        tracing::info!(
                            listen = %snmp_listen,
                            version = %source.connection.headers.get("version").cloned().unwrap_or_default(),
                            usm = usm.as_deref().unwrap_or("<v1/v2c 无 USM>"),
                            "SNMP Trap 监听已启动（v1/v2c Trap+Inform；v3 noAuthNoPriv / authNoPriv(HMAC-MD5-96|HMAC-SHA-96) / authPriv(CBC-DES|CFB128-AES-128)）"
                        );
                        listeners.snmp_trap = Some(snmp_listen);
                        tokio::spawn(async move {
                            if let Err(e) = receiver.serve(socket).await {
                                tracing::warn!(error = %e, "SNMP Trap 监听退出");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "SNMP Trap 未启用（绑定失败，其余能力不受影响）");
                        listeners.note(format!("SNMP Trap 未启用：{e}"));
                    }
                },
                Err(e) => {
                    tracing::warn!(error = %e, "SNMP Trap 未启用（配置非法）");
                    listeners.note(format!("SNMP Trap 未启用：{e}"));
                }
            }
        }
    }

    /// === SNMP v3 ===（v3 安全级别运行态标注）
    pub(super) fn annotate_snmp_v3(&mut self) {
        let listeners = &mut *self.listeners;
        // v3 的 USM 解析/校验落在 `agf_ingest::snmp`（与 v1/v2c 共用同一份 PDU 解析与 UDP 接收循环）：
        //   * `noAuthNoPriv`（msgFlags=0x00）；
        //   * `authNoPriv`（msgFlags=0x01，HMAC-MD5-96 / HMAC-SHA-96 + RFC3414 §3.2 的 150s 时限窗口）；
        //   * **`authPriv`（msgFlags=0x03）已实现**：RFC3414 §8 CBC-DES 与 RFC3826 §3
        //     CFB128-AES-128 解密（`agf_ingest::snmp::privacy`），认证/解密失败**分类计数**
        //     （usmStats 6 个对象 + priv 细分计数），绝不静默丢弃。
        // 本段落只把"本进程这次到底按什么安全级别收 v3"如实标注进 /readyz 的 notes。
        if !env_or("AGF_INGEST_SNMP_LISTEN", "").is_empty() {
            let version = env_or("AGF_INGEST_SNMP_VERSION", "v2c");
            if version.trim().eq_ignore_ascii_case("v3") {
                let level = env_or("AGF_INGEST_SNMP_V3_SECURITY_LEVEL", "noAuthNoPriv");
                let protocol = env_or("AGF_INGEST_SNMP_V3_AUTH_PROTOCOL", "md5");
                let user = env_or("AGF_INGEST_SNMP_V3_USER", "");
                let configured = agf_ingest::snmp::V3SecurityLevel::parse(&level).unwrap_or_default();
                let user_label = if user.trim().is_empty() { "<不校验用户名>" } else { user.as_str() };
                let priv_detail = match configured {
                    agf_ingest::snmp::V3SecurityLevel::AuthPriv => {
                        let priv_text = env_or("AGF_INGEST_SNMP_V3_PRIV_PROTOCOL", "aes");
                        let priv_label = agf_ingest::snmp::PrivProtocol::parse(&priv_text)
                            .map(|protocol| protocol.as_str().to_string())
                            .unwrap_or_else(|| format!("{priv_text}（非法，接收器不会启动）"));
                        tracing::info!(
                            security_level = configured.as_str(),
                            auth_protocol = %protocol,
                            priv_protocol = %priv_label,
                            user = %user_label,
                            "SNMP v3 authPriv 接收器已启用；解密指标：agf_ingest_snmp_usm_priv_decrypt_ok_total / \
                             _accepted_priv_total / _priv_padding_errors_total（失败另计 usmStatsDecryptionErrors）"
                        );
                        format!("，priv={priv_label}（RFC3414 CBC-DES / RFC3826 CFB128-AES-128）")
                    }
                    _ => {
                        tracing::info!(
                            security_level = configured.as_str(),
                            auth_protocol = %protocol,
                            user = %user_label,
                            "SNMP v3 接收器已启用（USM）；usmStats 指标：agf_ingest_snmp_usm_wrong_digests_total / \
                             _unknown_user_names_total / _not_in_time_windows_total / _unsupported_sec_levels_total"
                        );
                        String::new()
                    }
                };
                listeners.note(format!(
                    "SNMP v3 已启用：{}（auth={protocol}，user={user_label}）{priv_detail}；authPriv（DES/AES）已实现",
                    configured.as_str()
                ));
            } else {
                listeners.note(format!(
                    "SNMP {version} 已启用（community 校验）；v3 需 AGF_INGEST_SNMP_VERSION=v3 + AGF_INGEST_SNMP_V3_*"
                ));
            }
        }
    }
}
