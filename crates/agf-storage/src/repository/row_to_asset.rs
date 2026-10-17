//! 由 `repository.rs` 拆分：`row_to_asset`/`parse_protocol` 等 6 项（纯搬移，逻辑不变）。
use super::*;

use crate::db::{TenantTransaction, map_sqlx_err};
use agf_core::asset::Asset;
use agf_core::enums::{AssetKind, DataClass, DiscoverySource, LifecycleState, RiskDomain, Severity};
use agf_core::error::{DomainError, DomainResult};
use agf_core::ids::{Id, TenantId};
use agf_core::pagination::{Page, PageRequest};
use agf_core::risk::Finding;
use std::collections::BTreeMap;

pub(crate) fn row_to_asset(row: &sqlx::postgres::PgRow) -> DomainResult<Asset> {
    let kind_raw: String = row.try_get("kind").map_err(|e| DomainError::Internal(e.to_string()))?;
    let lc_raw: String = row.try_get("lifecycle").unwrap_or_default();
    let dc_raw: String = row.try_get("data_class").unwrap_or_default();
    let ds_raw: String = row.try_get("discovery_source").unwrap_or_default();
    let proto_raw: Option<String> = row.try_get("protocol").unwrap_or(None);
    Ok(Asset {
        id: uuid_col(row, "id")?,
        tenant_id: TenantId::from_uuid(row.try_get("tenant_id").map_err(|e| DomainError::Internal(e.to_string()))?),
        kind: AssetKind::parse(&kind_raw).map_err(|e| DomainError::Parse(format!("kind: {e}")))?,
        name: row.try_get("name").unwrap_or_default(),
        fingerprint: row.try_get("fingerprint").unwrap_or_default(),
        vendor: row.try_get("vendor").unwrap_or(None),
        version: row.try_get("version").unwrap_or(None),
        protocol: proto_raw.as_deref().and_then(parse_protocol),
        endpoint: row.try_get("endpoint").unwrap_or(None),
        owner: row.try_get("owner").unwrap_or(None),
        department: row.try_get("department").unwrap_or(None),
        data_class: parse_data_class(&dc_raw).map_err(DomainError::Parse)?,
        lifecycle: parse_lifecycle(&lc_raw).map_err(DomainError::Parse)?,
        discovery_source: parse_discovery(&ds_raw).map_err(DomainError::Parse)?,
        exposure_score: u8::try_from(row.try_get::<i16, _>("exposure_score").unwrap_or(0)).unwrap_or(0),
        runtime: row.try_get("runtime").unwrap_or(None),
        network_zone: row.try_get("network_zone").unwrap_or(None),
        cloud_resource_id: row.try_get("cloud_resource_id").unwrap_or(None),
        tags: serde_json::from_value(json_from(row, "tags")).unwrap_or_default(),
        attributes: serde_json::from_value(json_from(row, "attributes")).unwrap_or_default(),
        dependencies: serde_json::from_value(json_from(row, "dependencies")).unwrap_or_default(),
        risk_score: row.try_get::<Option<i16>, _>("risk_score").ok().flatten().and_then(|v| u8::try_from(v).ok()),
        last_seen_at: ts_opt(row, "last_seen_at"),
        created_at: ts_col(row, "created_at"),
        updated_at: ts_col(row, "updated_at"),
        deleted_at: ts_opt(row, "deleted_at"),
    })
}

pub(crate) fn parse_protocol(raw: &str) -> Option<agf_core::enums::Protocol> {
    use agf_core::enums::Protocol as P;
    [
        P::McpStdio,
        P::McpSse,
        P::McpHttp,
        P::OpenAiCompat,
        P::Anthropic,
        P::Gemini,
        P::A2a,
        P::Http,
        P::Grpc,
        P::WebSocket,
        P::Syslog,
        P::Kafka,
        P::Nats,
        P::Mqtt,
        P::Other,
    ]
    .into_iter()
    .find(|p| p.as_str() == raw)
}

pub(crate) fn parse_data_class(raw: &str) -> Result<DataClass, String> {
    match raw {
        "public" => Ok(DataClass::Public),
        "internal" => Ok(DataClass::Internal),
        "confidential" => Ok(DataClass::Confidential),
        "restricted" => Ok(DataClass::Restricted),
        other => Err(format!("未知数据分级 {other}")),
    }
}

pub(crate) fn parse_lifecycle(raw: &str) -> Result<LifecycleState, String> {
    match raw.replace('_', "-").as_str() {
        "requested" => Ok(LifecycleState::Requested),
        "under-review" => Ok(LifecycleState::UnderReview),
        "trial" => Ok(LifecycleState::Trial),
        "production" => Ok(LifecycleState::Production),
        "changing" => Ok(LifecycleState::Changing),
        "archived" => Ok(LifecycleState::Archived),
        "rejected" => Ok(LifecycleState::Rejected),
        other => Err(format!("未知生命周期 {other}")),
    }
}

pub(crate) fn parse_discovery(raw: &str) -> Result<DiscoverySource, String> {
    match raw.replace('_', "-").as_str() {
        "agent-report" => Ok(DiscoverySource::AgentReport),
        "network-scan" => Ok(DiscoverySource::NetworkScan),
        "cloud-api" => Ok(DiscoverySource::CloudApi),
        "passive-traffic" => Ok(DiscoverySource::PassiveTraffic),
        "manual" => Ok(DiscoverySource::Manual),
        "git-scan" => Ok(DiscoverySource::GitScan),
        "collector" => Ok(DiscoverySource::Collector),
        "sidecar" => Ok(DiscoverySource::Sidecar),
        "import" => Ok(DiscoverySource::Import),
        other => Err(format!("未知发现来源 {other}")),
    }
}

impl FindingRepo {
    /// 插入发现（含证据明细）。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn insert(tx: &mut TenantTransaction<'_>, f: &Finding) -> DomainResult<Id> {
        sqlx::query(
            r"INSERT INTO findings (
                id, tenant_id, title, severity, domain, category, cwe, cvss, target, asset_id,
                summary, description, poc, fix, patch, state, evidence_level, evidence_refs,
                rule_ids, rule_keys, llm_verdict, confidence, source_origin, audit_mode,
                chain, chain_tracer, chain_verdict, baseline, diff_evidence, marker_echo,
                request_pkt, response_pkt, impact, verify_note, retest_note,
                first_seen_at, last_seen_at, created_at, updated_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,
                       $25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,$39)",
        )
        .bind(f.id.as_uuid())
        .bind(f.tenant_id.as_uuid())
        .bind(&f.title)
        .bind(f.severity.as_str())
        .bind(f.domain.as_str())
        .bind(&f.category)
        .bind(&f.cwe)
        .bind(&f.cvss)
        .bind(&f.target)
        .bind(f.asset_id.map(|v| v.as_uuid()))
        .bind(&f.summary)
        .bind(&f.description)
        .bind(&f.poc)
        .bind(&f.fix)
        .bind(&f.patch)
        .bind(f.state.as_str())
        .bind(f.evidence_level.as_str())
        .bind(serde_json::to_value(&f.evidence_refs).unwrap_or(serde_json::Value::Null))
        .bind(serde_json::to_value(&f.rule_ids).unwrap_or(serde_json::Value::Null))
        .bind(serde_json::to_value(&f.rule_keys).unwrap_or(serde_json::Value::Null))
        .bind(serde_json::to_value(&f.llm_verdict).unwrap_or(serde_json::Value::Null))
        .bind(f.confidence)
        .bind(&f.source_origin)
        .bind(f.audit_mode.map(|m| m.as_str().to_string()))
        .bind(&f.chain)
        .bind(&f.chain_tracer)
        .bind(&f.chain_verdict)
        .bind(&f.baseline)
        .bind(&f.diff_evidence)
        .bind(&f.marker_echo)
        .bind(&f.request_pkt)
        .bind(&f.response_pkt)
        .bind(&f.impact)
        .bind(&f.verify_note)
        .bind(&f.retest_note)
        .bind(f.first_seen_at.as_datetime())
        .bind(f.last_seen_at.as_datetime())
        .bind(f.created_at.as_datetime())
        .bind(f.updated_at.as_datetime())
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("insert_finding", &e))?;

        for ev in &f.evidence {
            let exists = sqlx::query("SELECT id FROM finding_evidence WHERE finding_id = $1 AND code = $2")
                .bind(f.id.as_uuid())
                .bind(&ev.code)
                .fetch_optional(&mut **tx)
                .await
                .map_err(|e| map_sqlx_err("find_finding_evidence", &e))?;
            if exists.is_some() {
                continue;
            }
            sqlx::query(
                "INSERT INTO finding_evidence (id, tenant_id, finding_id, code, kind, summary, content_hash, artifact_ref, collected_at)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            )
            .bind(Id::new().as_uuid())
            .bind(f.tenant_id.as_uuid())
            .bind(f.id.as_uuid())
            .bind(&ev.code)
            .bind(&ev.kind)
            .bind(&ev.summary)
            .bind(&ev.content_hash)
            .bind(&ev.artifact_ref)
            .bind(ev.collected_at.as_datetime())
            .execute(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("insert_finding_evidence", &e))?;
        }
        Ok(f.id)
    }

    /// 按 id 读取（含证据）。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn get(tx: &mut TenantTransaction<'_>, id: Id) -> DomainResult<Option<Finding>> {
        let row = sqlx::query("SELECT * FROM findings WHERE id = $1 AND deleted_at IS NULL")
            .bind(id.as_uuid())
            .fetch_optional(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("get_finding", &e))?;
        let Some(r) = row else { return Ok(None) };
        let mut finding = row_to_finding(&r)?;
        finding.evidence = Self::load_evidence(tx, id).await?;
        Ok(Some(finding))
    }

    /// 读取证据明细。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn load_evidence(
        tx: &mut TenantTransaction<'_>,
        finding_id: Id,
    ) -> DomainResult<Vec<agf_core::risk::Evidence>> {
        let rows = sqlx::query("SELECT * FROM finding_evidence WHERE finding_id = $1 ORDER BY code")
            .bind(finding_id.as_uuid())
            .fetch_all(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("load_evidence", &e))?;
        Ok(rows
            .iter()
            .map(|r| agf_core::risk::Evidence {
                code: r.try_get("code").unwrap_or_default(),
                kind: r.try_get("kind").unwrap_or_default(),
                summary: r.try_get("summary").unwrap_or_default(),
                content_hash: r.try_get("content_hash").unwrap_or_default(),
                artifact_ref: r.try_get("artifact_ref").unwrap_or(None),
                collected_at: ts_col(r, "collected_at"),
            })
            .collect())
    }

    /// 分页查询。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn list(
        tx: &mut TenantTransaction<'_>,
        req: &PageRequest,
        domain: Option<RiskDomain>,
        min_severity: Option<Severity>,
    ) -> DomainResult<Page<Finding>> {
        let n = req.normalized();
        let d = domain.map(|x| x.as_str().to_string());
        let s = min_severity.map(|x| x.as_str().to_string());
        let total: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM findings WHERE deleted_at IS NULL \
             AND ($1::text IS NULL OR domain = $1) AND ($2::text IS NULL OR severity = $2)",
        )
        .bind(d.clone())
        .bind(s.clone())
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("count_findings", &e))?;
        let rows = sqlx::query(
            "SELECT * FROM findings WHERE deleted_at IS NULL \
             AND ($1::text IS NULL OR domain = $1) AND ($2::text IS NULL OR severity = $2) \
             ORDER BY last_seen_at DESC LIMIT $3 OFFSET $4",
        )
        .bind(d)
        .bind(s)
        .bind(n.limit())
        .bind(n.offset())
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("list_findings", &e))?;
        let items = rows.iter().map(row_to_finding).collect::<DomainResult<Vec<_>>>()?;
        Ok(Page::new(items, total, req))
    }

    /// 更新状态与注记。
    ///
    /// # Errors
    /// 记录不存在或 SQL 失败。
    pub async fn set_state(
        tx: &mut TenantTransaction<'_>,
        id: Id,
        state: &str,
        verify_note: Option<&str>,
        evidence_level: Option<&str>,
    ) -> DomainResult<()> {
        let affected = sqlx::query(
            "UPDATE findings SET state = $1, verify_note = COALESCE($2, verify_note), \
             evidence_level = COALESCE($3, evidence_level), updated_at = now() WHERE id = $4 AND deleted_at IS NULL",
        )
        .bind(state)
        .bind(verify_note)
        .bind(evidence_level)
        .bind(id.as_uuid())
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_err("set_finding_state", &e))?
        .rows_affected();
        if affected == 0 {
            return Err(DomainError::NotFound { entity: "finding", id: id.to_string() });
        }
        Ok(())
    }

    /// 按域统计。
    ///
    /// # Errors
    /// SQL 执行失败。
    pub async fn count_by_domain(tx: &mut TenantTransaction<'_>) -> DomainResult<BTreeMap<String, i64>> {
        let rows = sqlx::query("SELECT domain, count(*) AS n FROM findings WHERE deleted_at IS NULL GROUP BY domain")
            .fetch_all(&mut **tx)
            .await
            .map_err(|e| map_sqlx_err("count_findings_by_domain", &e))?;
        Ok(rows
            .iter()
            .map(|r| (r.try_get::<String, _>("domain").unwrap_or_default(), r.try_get::<i64, _>("n").unwrap_or(0)))
            .collect())
    }
}
