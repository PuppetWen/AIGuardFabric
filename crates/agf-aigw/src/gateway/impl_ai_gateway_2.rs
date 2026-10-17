//! 由 `gateway.rs` 拆分：`impl_AiGateway`/`impl_Prepared` 等 7 项（纯搬移，逻辑不变）。
use super::*;

impl AiGateway {
    /// 已注册的 Prompt 模板名。
    #[must_use]
    pub fn prompt_names(&self) -> Vec<&str> {
        self.prompts.keys().map(String::as_str).collect()
    }
    /// 会话粘性端点（多轮会话尽量落同一端点）。
    #[must_use]
    pub fn affinity_endpoint(&self, session_id: &str) -> Option<Id> {
        self.session_affinity.lock().get(session_id).copied()
    }
    /// 最近用量记录（控制台"成本计量"页）。
    #[must_use]
    pub fn recent_usage(&self, limit: usize) -> Vec<UsageRecord> {
        self.meter.recent(limit)
    }
    /// 网关自检摘要（供"系统自检"页）。
    #[must_use]
    pub fn self_check(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        out.insert("endpoints_total".to_string(), self.router.len().to_string());
        out.insert("endpoints_enabled".to_string(), self.router.enabled_count().to_string());
        out.insert("mock_mode".to_string(), self.mock_mode().to_string());
        out.insert("screen".to_string(), self.screen.name().to_string());
        out.insert(
            "cache_backend".to_string(),
            if self.cache.has_redis() { "redis+memory" } else { "memory" }.to_string(),
        );
        out.insert("prompts".to_string(), self.prompts.len().to_string());
        out.insert("usage_records".to_string(), self.meter.snapshot().total.calls.to_string());
        out.insert("generated_at".to_string(), Timestamp::now().to_rfc3339());
        out
    }
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prepared")
            .field("mutated", &self.screening.mutated)
            .field("request_redactions", &self.screening.request_redactions)
            .finish_non_exhaustive()
    }
}

/// 渲染 `{{var}}` 模板（变量名两侧空白会被忽略）。
///
/// # Errors
/// 缺少必需变量时返回 `DomainError::Validation`。
pub fn render_template(template: &str, vars: &BTreeMap<String, String>) -> DomainResult<String> {
    let required = agf_core::skill::PromptTemplate::extract_variables(template);
    let missing: Vec<String> = required.iter().filter(|name| !vars.contains_key(name.as_str())).cloned().collect();
    if !missing.is_empty() {
        return Err(DomainError::Validation(format!("Prompt 模板缺少变量: {}", missing.join(", "))));
    }
    let mut out = template.to_string();
    for name in &required {
        if let Some(value) = vars.get(name) {
            out = out.replace(&format!("{{{{{name}}}}}"), value);
            // 容忍 `{{ name }}` 形式的空格写法
            out = out.replace(&format!("{{{{ {name} }}}}"), value);
        }
    }
    Ok(out)
}

/// 判断消息内容是否为空（网关写缓存前的快速检查）。
#[must_use]
pub fn response_is_empty(response: &ChatResponse) -> bool {
    response.message.content.is_empty()
}

/// 系统消息个数（审计统计）。
#[must_use]
pub fn system_message_count(req: &ChatRequest) -> usize {
    req.messages.iter().filter(|m| m.role == Role::System).count()
}

/// 合并 usage（流式累积的便捷入口）。
#[must_use]
pub fn merge_usage(left: Usage, right: Usage) -> Usage {
    left.saturating_add(right)
}

/// 拼接两次路由结果（`Either` 用于在不引入额外分配语义的前提下表达"二选一"分支）。
#[must_use]
pub fn concat_chains<'a>(first: Vec<&'a ModelEndpoint>, second: Vec<&'a ModelEndpoint>) -> Vec<&'a ModelEndpoint> {
    match Either::<Vec<&'a ModelEndpoint>, ()>::Left(first) {
        Either::Left(mut a) => {
            a.extend(second);
            a
        }
        Either::Right(()) => second,
    }
}
