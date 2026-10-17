//! Operator-reviewed launch templates. No process, credential, asset or cloud mutation occurs here.
use super::onboarding_targets::quote;
use super::onboarding_types::{OnboardingSource, OnboardingStartup, OnboardingStepView, OnboardingTarget};
use agf_core::error::{DomainError, DomainResult};
use serde_json::json;

pub(super) struct Template {
    pub endpoint: String,
    pub ready: bool,
    pub env: String,
    pub steps: Vec<OnboardingStepView>,
    pub configuration: Option<String>,
    pub key_env: Option<String>,
}
pub(super) fn step(title: &str, command: String) -> OnboardingStepView {
    OnboardingStepView {
        order: 1,
        title: title.into(),
        command,
        rollback: "# Restore the original launch/configuration; revoke only this separately issued platform key".into(),
    }
}
fn environment(values: &[(&str, String)], key: &str, windows: bool) -> String {
    let mut lines = values
        .iter()
        .map(|(name, value)| {
            let value = quote(value, windows);
            if windows { format!("$env:{name}={value}") } else { format!("export {name}={value}") }
        })
        .collect::<Vec<_>>();
    lines.push(if windows { format!("$env:{key}=[System.Net.NetworkCredential]::new('',(Read-Host 'Separate platform key' -AsSecureString)).Password") }
        else { format!("printf 'Separate platform key: '; read -r -s {key}; export {key}; printf '\\n'") });
    lines.join("\n")
}
pub(super) fn incomplete(target: OnboardingTarget, base: &str, zh: bool) -> Template {
    let title = if zh {
        "填写精确来源和业务入口后生成；不会自动登记或派发"
    } else {
        "Select the exact source and application entry; no automatic registration or dispatch"
    };
    Template {
        endpoint: if target == OnboardingTarget::ModelOpenai { format!("{base}/v1") } else { base.into() },
        ready: false,
        env: String::new(),
        steps: vec![step(
            title,
            "# Complete the fields and generate again; retain original application arguments locally".into(),
        )],
        configuration: None,
        key_env: None,
    }
}
pub(super) fn startup(
    target: OnboardingTarget,
    input: &OnboardingStartup,
    selected: &OnboardingSource,
    base: &str,
    configuration: String,
    windows: bool,
    zh: bool,
) -> Template {
    let python = target == OnboardingTarget::PythonStartup;
    let key = if python { "AGF_COLLECTOR_KEY" } else { "AGF_STARTUP_KEY" };
    let values = if !python {
        vec![
            ("AGF_PLATFORM_URL", base.into()),
            ("AGF_SOURCE_ID", selected.source_id.to_string()),
            ("AGF_BINDING_ID", selected.binding_id.to_string()),
            ("AGF_SCOPE_ID", selected.scope_id.to_string()),
            ("AGF_EXPECTED_MOCKED", selected.mocked.to_string()),
            ("AGF_SPOOL_DIR", input.spool_directory.clone()),
            ("AGF_NODE_STARTUP_CONFIG", input.configuration_file.clone()),
        ]
    } else {
        vec![]
    };
    let mut env = environment(&values, key, windows);
    if python {
        let directory = quote(&input.sdk_directory, windows);
        env.push_str(&if windows {
            format!("\n$env:PYTHONPATH={directory} + ';' + $env:PYTHONPATH")
        } else {
            format!("\nexport PYTHONPATH={directory}\"${{PYTHONPATH:+:$PYTHONPATH}}\"")
        });
    }
    let prefix = if windows { "& " } else { "" };
    let config = quote(&input.configuration_file, windows);
    let entry = quote(&input.entry, windows);
    let (launch, drain) = if python {
        (
            format!("python -m agf_agentteams.bootstrap --config {config} --module {entry} --"),
            format!("python -m agf_agentteams.bootstrap --config {config} --drain-only"),
        )
    } else {
        let preload = quote(&format!("{}/startup.cjs", input.sdk_directory.trim_end_matches(['/', '\\'])), windows);
        let drain = quote(&format!("{}/startup-drain.mjs", input.sdk_directory.trim_end_matches(['/', '\\'])), windows);
        (format!("{prefix}node --require {preload} {entry}"), format!("{prefix}node {drain} --drain-only 5"))
    };
    let title = if zh {
        "保存不含密钥的 JSON；保留原命令参数再启动"
    } else {
        "Save the noncredential JSON; preserve original arguments when launching"
    };
    let mut steps = vec![
        step(
            title,
            format!(
                "# Save the displayed JSON as {config}\n{launch}\n# Append your original application arguments to the launch line"
            ),
        ),
        step(
            if zh {
                "仅投递原 UUID 队列，不执行业务"
            } else {
                "Drain original UUIDs only; execute no business"
            },
            drain,
        ),
    ];
    steps[1].order = 2;
    Template {
        endpoint: format!("{base}/api/v1/alicloud/agentteams/audit-sources/{}/events", selected.source_id),
        ready: true,
        env,
        steps,
        configuration: Some(configuration),
        key_env: Some(key.into()),
    }
}
pub(super) fn stdio(base: &str, windows: bool, zh: bool) -> DomainResult<Template> {
    let agent = if windows { "./agf-agent.exe" } else { "./agf-agent" };
    let config = json!({"mcpServers":{"guarded":{"command":agent,
        "args":["mcp-proxy","--server",base,"--","<ORIGINAL_COMMAND>","<ORIGINAL_ARGS>"]}}});
    let configuration = serde_json::to_string_pretty(&config)
        .map_err(|_| DomainError::Config("MCP template encoding failed".into()))?;
    Ok(Template { endpoint: base.into(), ready: false, env: environment(&[], "AGF_AGENT_TOKEN", windows),
        steps: vec![step(if zh { "构建并合并原 stdio command/args；保留原环境" } else { "Build and merge the original stdio command/args; preserve its environment" },
            "cargo build --release -p agf-agent --bin agf-agent\n# Copy the binary to the reviewed command path. Merge the displayed template into the project configuration.\n# Replace placeholders with the original command and each original argument; do not store a plaintext key.".into())],
        configuration: Some(configuration), key_env: Some("AGF_AGENT_TOKEN".into()) })
}
pub(super) fn model(target: OnboardingTarget, model: &str, base: &str, windows: bool, zh: bool) -> Template {
    let openai = target == OnboardingTarget::ModelOpenai;
    let endpoint = if openai { format!("{base}/v1") } else { base.into() };
    let (url, key) =
        if openai { ("OPENAI_BASE_URL", "OPENAI_API_KEY") } else { ("ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY") };
    Template {
        endpoint: endpoint.clone(),
        ready: true,
        env: environment(&[(url, endpoint), ("AGF_SELECTED_MODEL", model.into())], key, windows),
        steps: vec![step(
            if zh {
                "在原应用中明确选择模型；此计划不请求生成"
            } else {
                "Explicitly select the model in the original application; this plan sends no generation request"
            },
            format!(
                "# Set the application's model to {}. Keep the original entry and arguments.\n# {}",
                quote(model, windows),
                if openai {
                    "OpenAI calls use /v1/chat/completions"
                } else {
                    "Anthropic calls use /v1/messages beneath the origin; do not append /v1 to ANTHROPIC_BASE_URL"
                }
            ),
        )],
        configuration: None,
        key_env: Some(key.into()),
    }
}
pub(super) fn mcp_http(base: &str, zh: bool) -> Template {
    Template { endpoint: base.into(), ready: false, env: String::new(),
        steps: vec![step(if zh { "打开 MCP 页面，登记后显式探测并复制该端点模板" } else { "Open MCPs, register the endpoint, explicitly probe and copy its template" },
            "# /mcps → HTTP endpoints → register → explicit probe → template\n# Do not replace the original stdio command with an HTTP template.".into())],
        configuration: None, key_env: None }
}
