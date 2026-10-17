//! 仅同步官方支持的 Worker Token 周期限额，写后重新读取确认。
use super::*;
use serde_json::{Value, json};

impl AgentTeamsAdapter {
    async fn worker_limit(&self) -> DomainResult<Value> {
        if self.worker_name.trim().is_empty() || !matches!(self.quota_period.as_str(), "day" | "week" | "month") {
            return Err(DomainError::Config(
                "配额同步需要 settings.worker_name 和 quota_period(day/week/month)".into(),
            ));
        }
        let body = self.call("GetWorker", json!({"Name":self.worker_name})).await?;
        Ok(super::live::checked_data(&body, &self.worker_name, &self.instance_id)?["LimitConfig"].clone())
    }

    pub(super) async fn apply_live_quota(
        &self,
        integration: Id,
        values: &[(QuotaDimension, i64)],
    ) -> DomainResult<Vec<(QuotaDimension, i64)>> {
        if values.len() != 1 || values[0].0 != QuotaDimension::Tokens || values[0].1 <= 0 {
            return Err(DomainError::Validation(
                "云侧仅支持单个 Worker 的正整数 Token 限额；次数/并发/金额仍由平台网关执行".into(),
            ));
        }
        let previous = self.worker_limit().await?;
        if previous["LimitType"] != "token" || previous["PeriodType"] != self.quota_period {
            return Err(DomainError::PreconditionFailed("云配额类型或周期不一致，请先核对 Worker 配额周期".into()));
        }
        let old = previous["UsageLimit"]
            .as_i64()
            .filter(|n| *n > 0)
            .ok_or_else(|| DomainError::Parse("云 Worker 未返回有效 Token 限额".into()))?;
        let requested = values[0].1;
        if old != requested {
            let token = deterministic_id(
                "agf.cloud.worker-quota",
                &format!(
                    "{integration}:{}:{}:{}:{old}:{requested}",
                    self.instance_id, self.worker_name, self.quota_period
                ),
            );
            self.call(
                "UpdateWorker",
                json!({"Name":self.worker_name,"ClientToken":token.to_string(),
                "LimitConfig":{"LimitType":"token","UsageLimit":requested,"PeriodType":self.quota_period}}),
            )
            .await?;
            let after = self.worker_limit().await?;
            if after["LimitType"] != "token"
                || after["PeriodType"] != self.quota_period
                || after["UsageLimit"].as_i64() != Some(requested)
            {
                return Err(DomainError::PreconditionFailed("配额写入已提交，但云端回读尚未一致；请核对后重试".into()));
            }
        }
        Ok(vec![(QuotaDimension::Tokens, old)])
    }
}
