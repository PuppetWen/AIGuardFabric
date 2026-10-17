//! Connectivity checks never send business payloads; publication is audited and guarded.
use super::*;
use agf_core::audit::{AuditActor, AuditOutcome};

pub async fn probe(state: &AppState, tenant: TenantId, name: &str) -> DomainResult<Probe> {
    probe_audited(state, tenant, name, crate::integration_receipts::internal_actor("integration-probe")).await
}

pub async fn probe_audited(state: &AppState, tenant: TenantId, name: &str, actor: AuditActor) -> DomainResult<Probe> {
    let started_at = Timestamp::now();
    let row = load(state, tenant, name)
        .await?
        .filter(|row| row.enabled)
        .ok_or_else(|| DomainError::PreconditionFailed("请先保存并启用适配器".into()))?;
    let private = decrypt(state, tenant, &row)?;
    let adapter = adapter(state, tenant, &row, &private)?;
    let mut result = Probe {
        version: row.version,
        checked_at: started_at,
        mocked: state.config.mock_mode || row.mock,
        tcp_reachable: None,
        host: None,
        port: None,
        note: String::new(),
    };
    if result.mocked {
        result.note = "模拟配置已校验；没有建立网络连接，不证明真实服务可达".into();
    } else {
        inspect(&mut result, name, &private, &adapter.metadata()).await?;
    }
    result.checked_at = Timestamp::now();
    let report = crate::probe_publication::publish(
        state,
        tenant,
        crate::probe_publication::Publication {
            configuration_kind: KIND,
            report_kind: "integration-probe",
            name,
            version: row.version,
            mocked: result.mocked,
            started_at,
            report: serde_json::to_value(&result)?,
            outcome: if result.tcp_reachable == Some(false) { AuditOutcome::Failure } else { AuditOutcome::Success },
        },
        actor,
    )
    .await?;
    Ok(serde_json::from_value(report)?)
}

async fn inspect(result: &mut Probe, name: &str, private: &Private, meta: &AdapterMetadata) -> DomainResult<()> {
    let smtp_endpoint = if name == "email" {
        let host = private.settings.get("smtp_host").and_then(Value::as_str).unwrap_or("");
        let port = private.settings.get("smtp_port").and_then(Value::as_u64).unwrap_or(587);
        Some(format!("smtp://{host}:{port}"))
    } else {
        None
    };
    let endpoint = smtp_endpoint
        .as_deref()
        .or_else(|| {
            meta.endpoint_key
                .as_ref()
                .and_then(|key| private.settings.get(key))
                .and_then(Value::as_str)
                .or_else(|| private.secrets.get("webhook_url").map(String::as_str))
        })
        .ok_or_else(|| DomainError::Validation("适配器未配置可探测地址".into()))?;
    let url = url::Url::parse(endpoint).map_err(|_| DomainError::Validation("适配器地址无效".into()))?;
    if url.scheme() == "udp"
        || (name == "syslog-forwarder"
            && url.scheme() == "syslog"
            && private.settings.get("protocol").and_then(Value::as_str) != Some("tcp"))
    {
        result.note = "UDP 无连接握手；配置已校验，需在接收端验证实际日志到达".into();
        return Ok(());
    }
    let host = url.host_str().ok_or_else(|| DomainError::Validation("地址缺少主机".into()))?.trim_matches(['[', ']']);
    let port = url
        .port_or_known_default()
        .or_else(|| match url.scheme() {
            "smtp" => Some(25),
            "smtps" => Some(465),
            _ => None,
        })
        .ok_or_else(|| DomainError::Validation("地址缺少端口".into()))?;
    result.host = Some(host.into());
    result.port = Some(port);
    result.tcp_reachable = Some(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(5), tokio::net::TcpStream::connect((host, port))).await,
        Ok(Ok(_))
    ));
    result.note = if result.tcp_reachable == Some(true) {
        "TCP 连接成功；未发送业务消息，也未验证 TLS 证书、账号权限或投递回执"
    } else {
        "TCP 连接失败或超时；请检查地址、端口、防火墙和服务监听"
    }
    .into();
    Ok(())
}
