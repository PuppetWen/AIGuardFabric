//! Paginate summaries without reading historical transcripts on every poll.
use super::*;
use crate::query::ListQuery;

impl ApiStore {
    pub(crate) async fn campaign_live_success_rate(&self, tenant: TenantId) -> DomainResult<Option<f64>> {
        let (executed, succeeded): (i64, i64) = if let Some(db) = &self.database {
            let mut tx = db.db().begin_tenant(tenant).await?;
            let totals=sqlx::query_as("SELECT COALESCE(sum(executed_cases),0)::bigint,COALESCE(sum(succeeded_cases),0)::bigint FROM redteam_campaigns WHERE deleted_at IS NULL AND state='completed' AND record->>'execution_mode'='live'")
                .fetch_one(&mut *tx).await.map_err(|e|agf_storage::map_sqlx_err("campaign_metric",&e))?;
            tx.commit().await?;
            totals
        } else {
            self.lock()?
                .campaign_records
                .iter()
                .filter(|((t, _), r)| {
                    *t == tenant
                        && r.execution_mode.as_deref() == Some("live")
                        && r.campaign.state == agf_core::redteam::CampaignState::Completed
                })
                .fold((0, 0), |(e, s), (_, r)| {
                    (e + i64::from(r.campaign.executed_cases), s + i64::from(r.campaign.succeeded_cases))
                })
        };
        Ok((executed > 0).then(|| succeeded as f64 / executed as f64))
    }

    pub(crate) async fn campaign_page_durable(
        &self,
        tenant: TenantId,
        query: &ListQuery,
    ) -> DomainResult<Page<serde_json::Value>> {
        let state = query.filter("state");
        if state.is_some_and(|s| !["queued", "running", "completed", "failed", "cancelled"].contains(&s)) {
            return Err(DomainError::Validation("Unknown campaign state".into()));
        }
        let column = match query.sort_by.as_deref() {
            None | Some("created_at") => "created_at",
            Some("name") => "name",
            _ => return Err(DomainError::Validation("Campaign sorting supports created_at or name".into())),
        };
        if query.q.as_ref().is_some_and(|q| q.len() > 512) {
            return Err(DomainError::Validation("Campaign search exceeds 512 bytes".into()));
        }
        let Some(db) = &self.database else {
            let mut mem = self.lock()?;
            let mut records: Vec<_> = mem
                .campaigns
                .iter()
                .filter(|((t, id), _)| *t == tenant && !mem.campaign_records.contains_key(&(*t, *id)))
                .map(|((t, id), c)| {
                    CampaignRecord::legacy(
                        c.clone(),
                        mem.campaign_results.get(&(*t, *id)).cloned().unwrap_or_default(),
                        mem.campaign_reports.get(&(*t, *id)).cloned(),
                    )
                })
                .collect();
            for ((t, _), r) in &mut mem.campaign_records {
                if *t == tenant {
                    r.expire();
                    records.push(r.clone());
                }
            }
            let views = records
                .iter()
                .filter(|r| state.is_none_or(|s| s == r.campaign.state.as_str()))
                .map(CampaignRecord::view)
                .collect::<DomainResult<Vec<_>>>()?;
            return Ok(query.paginate_vec(
                &views,
                |v| format!("{} {}", v["id"].as_str().unwrap_or_default(), v["name"].as_str().unwrap_or_default()),
                |v| v[column].as_str().unwrap_or_default().to_string(),
            ));
        };
        let mut tx = db.db().begin_tenant(tenant).await?;
        let now = Timestamp::now();
        sqlx::query("UPDATE redteam_campaigns SET state='failed',finished_at=$1,updated_at=$1,
            record=jsonb_set(record,'{campaign}',record->'campaign'||jsonb_build_object('state','failed','finished_at',$1::timestamptz))||jsonb_build_object('error',$2::text)
            WHERE state IN ('queued','running') AND created_at <= $3 AND deleted_at IS NULL")
            .bind(now.as_datetime()).bind(super::campaign_record::CAMPAIGN_INTERRUPTED)
            .bind(now.offset_secs(-super::campaign_record::CAMPAIGN_TIMEOUT).as_datetime()).execute(&mut *tx).await
            .map_err(|e|agf_storage::map_sqlx_err("campaign_expire",&e))?;
        let filter = "deleted_at IS NULL AND ($1::text IS NULL OR state=$1) AND ($2::text IS NULL OR strpos(lower(id::text||' '||name),lower($2))>0)";
        let count: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM redteam_campaigns WHERE {filter}"))
            .bind(state)
            .bind(&query.q)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| agf_storage::map_sqlx_err("campaign_count", &e))?;
        let request = query.to_page_request();
        let raws: Vec<(serde_json::Value,Option<bool>)>=sqlx::query_as(&format!("SELECT record-'cases'-'results'-'report',(record->'report'->>'ci_passed')::boolean FROM redteam_campaigns WHERE {filter} ORDER BY {column} {},id LIMIT $3 OFFSET $4",query.sort_dir.as_sql()))
            .bind(state).bind(&query.q).bind(request.limit()).bind(request.offset()).fetch_all(&mut *tx).await
            .map_err(|e|agf_storage::map_sqlx_err("campaign_page",&e))?;
        let mut views = Vec::with_capacity(raws.len());
        for (raw, ci_passed) in raws {
            let record = serde_json::from_value::<CampaignRecord>(raw)?;
            let mut view = record.view()?;
            if record.campaign.state == agf_core::redteam::CampaignState::Completed && record.campaign.ci_gate {
                view["ci_passed"] = serde_json::to_value(ci_passed)?;
            }
            views.push(view);
        }
        tx.commit().await?;
        Ok(Page::new(views, count, &request))
    }

    /// For exports only; bounded history, not the polling path.
    pub async fn campaign_list_durable(&self, tenant: TenantId) -> DomainResult<Vec<RedteamCampaign>> {
        let mut out = Vec::new();
        for page in 1..=500 {
            let query = ListQuery { page, page_size: 200, ..ListQuery::default() };
            let rows = self.campaign_page_durable(tenant, &query).await?;
            let more = rows.has_more();
            for row in rows.items {
                out.push(serde_json::from_value(row)?);
            }
            if !more {
                return Ok(out);
            }
        }
        Err(DomainError::PreconditionFailed("Campaign history exceeds 100000 records".into()))
    }
}
