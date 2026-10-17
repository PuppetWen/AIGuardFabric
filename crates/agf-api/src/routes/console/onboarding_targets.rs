//! Read-only target selection and links to existing administration.
use super::onboarding_types::{OnboardingLink, OnboardingTarget};
use agf_core::error::{DomainError, DomainResult};

impl OnboardingTarget {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Collector => "collector",
            Self::McpStdio => "mcp-stdio",
            Self::PythonStartup => "python-startup",
            Self::NodeCjsStartup => "node-cjs-startup",
            Self::ModelOpenai => "model-openai",
            Self::ModelAnthropic => "model-anthropic",
            Self::McpHttp => "mcp-http",
        }
    }
}

pub(super) fn select(mode: &str, requested: Option<OnboardingTarget>) -> DomainResult<OnboardingTarget> {
    let default = match mode {
        "sidecar" => OnboardingTarget::Collector,
        "sdk-inject" => OnboardingTarget::PythonStartup,
        "gateway-register" => OnboardingTarget::ModelOpenai,
        _ => return Err(DomainError::Validation("Unsupported onboarding mode".into())),
    };
    let target = requested.unwrap_or(default);
    let valid = match mode {
        "sidecar" => matches!(target, OnboardingTarget::Collector | OnboardingTarget::McpStdio),
        "sdk-inject" => matches!(target, OnboardingTarget::PythonStartup | OnboardingTarget::NodeCjsStartup),
        "gateway-register" => matches!(
            target,
            OnboardingTarget::ModelOpenai | OnboardingTarget::ModelAnthropic | OnboardingTarget::McpHttp
        ),
        _ => false,
    };
    if !valid {
        return Err(DomainError::Validation("Target does not belong to the selected onboarding mode".into()));
    }
    Ok(target)
}

pub(super) fn available(mode: &str) -> Vec<String> {
    let values = match mode {
        "sidecar" => vec![OnboardingTarget::Collector, OnboardingTarget::McpStdio],
        "sdk-inject" => vec![OnboardingTarget::PythonStartup, OnboardingTarget::NodeCjsStartup],
        _ => vec![OnboardingTarget::ModelOpenai, OnboardingTarget::ModelAnthropic, OnboardingTarget::McpHttp],
    };
    values.into_iter().map(|value| value.as_str().into()).collect()
}

pub(super) fn links(target: OnboardingTarget, zh: bool) -> Vec<OnboardingLink> {
    let text = |cn: &str, en: &str| if zh { cn.to_owned() } else { en.to_owned() };
    let scopes = match target {
        OnboardingTarget::Collector | OnboardingTarget::PythonStartup | OnboardingTarget::NodeCjsStartup => {
            "sources:write"
        }
        OnboardingTarget::McpStdio => "policies:read",
        OnboardingTarget::McpHttp => "mcps:execute,policies:read",
        _ => "models:read,models:write",
    };
    let mut links = vec![
        OnboardingLink {
            label: text("登记或查看真实应用资产", "Register or inspect the actual application"),
            href: "/assets".into(),
        },
        OnboardingLink {
            label: text(
                "创建独立 Key；手工选择真实 Agent 绑定",
                "Create a separate key; explicitly bind the actual Agent",
            ),
            href: format!("/settings?tab=apiKeys&createKey=1&scopes={scopes}"),
        },
    ];
    let (cn, en, href) = match target {
        OnboardingTarget::McpHttp => {
            ("登记、探测并复制 MCP 模板", "Register, probe and copy the MCP template", "/mcps")
        }
        OnboardingTarget::PythonStartup | OnboardingTarget::NodeCjsStartup => (
            "盘点 Worker 并建立当前审计绑定",
            "Inventory Workers and bind a current audit source",
            "/alicloud?tab=audit",
        ),
        OnboardingTarget::Collector | OnboardingTarget::McpStdio => {
            ("检查台账及运行时防护", "Inspect inventory and runtime protection", "/runtime")
        }
        _ => ("登记并检查精确模型 ID", "Register and inspect the exact model ID", "/models"),
    };
    links.push(OnboardingLink { label: text(cn, en), href: href.into() });
    if matches!(target, OnboardingTarget::PythonStartup | OnboardingTarget::NodeCjsStartup) {
        links.push(OnboardingLink {
            label: text("盘点真实 Worker 及关系", "Inventory actual Workers and relationships"),
            href: "/alicloud?tab=inventory".into(),
        });
    }
    links
}

/// One quoted shell argument. Data is never interpolated as executable shell syntax.
pub(super) fn quote(value: &str, windows: bool) -> String {
    if windows { format!("'{}'", value.replace('\'', "''")) } else { format!("'{}'", value.replace('\'', "'\"'\"'")) }
}

pub(super) fn plain(value: &str, max: usize) -> DomainResult<()> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(DomainError::Validation("Invalid noncredential onboarding value".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn target_matrix_is_explicit_and_defaults_cannot_switch_to_a_gateway() {
        let cases = [
            ("sidecar", vec![OnboardingTarget::Collector, OnboardingTarget::McpStdio]),
            ("sdk-inject", vec![OnboardingTarget::PythonStartup, OnboardingTarget::NodeCjsStartup]),
            (
                "gateway-register",
                vec![OnboardingTarget::ModelOpenai, OnboardingTarget::ModelAnthropic, OnboardingTarget::McpHttp],
            ),
        ];
        let all = [
            OnboardingTarget::Collector,
            OnboardingTarget::McpStdio,
            OnboardingTarget::PythonStartup,
            OnboardingTarget::NodeCjsStartup,
            OnboardingTarget::ModelOpenai,
            OnboardingTarget::ModelAnthropic,
            OnboardingTarget::McpHttp,
        ];
        for (mode, allowed) in cases {
            assert!(select(mode, None).is_ok_and(|value| value == allowed[0]));
            for target in all {
                assert_eq!(select(mode, Some(target)).is_ok(), allowed.contains(&target), "{mode}/{}", target.as_str());
            }
        }
        assert!(select("future", None).is_err());
    }
    #[test]
    fn shell_arguments_remain_data_even_with_quotes_and_substitutions() {
        assert_eq!(quote("a'b$(not-code)", true), "'a''b$(not-code)'");
        assert_eq!(quote("a'b$(not-code)", false), "'a'\"'\"'b$(not-code)'");
        assert!(plain("line\ncommand", 256).is_err());
    }
}
