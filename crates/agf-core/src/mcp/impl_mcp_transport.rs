//! 由 `mcp.rs` 拆分：`McpCapabilities`/`McpServer`/`McpTool`/`McpTransport`/`ToolTraits` 的实现（纯搬移，逻辑不变）。
use super::*;

use crate::enums::Protocol;
use crate::ids::{TenantId, TenantScoped};

impl McpTransport {
    /// 文本形式。
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Stdio => "stdio",
            Self::Sse => "sse",
            Self::Http => "http",
            Self::WebSocket => "websocket",
        }
    }

    /// 转为通用协议枚举。
    #[must_use]
    pub const fn as_protocol(&self) -> Protocol {
        match self {
            Self::Stdio => Protocol::McpStdio,
            Self::Sse => Protocol::McpSse,
            Self::Http => Protocol::McpHttp,
            Self::WebSocket => Protocol::WebSocket,
        }
    }

    /// 是否为远程传输（决定是否需要出网管控）。
    #[must_use]
    pub const fn is_remote(&self) -> bool {
        !matches!(self, Self::Stdio)
    }

    /// 解析文本。
    ///
    /// # Errors
    /// 未知传输方式返回错误。
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "stdio" => Ok(Self::Stdio),
            "sse" => Ok(Self::Sse),
            "http" | "streamable-http" | "streamable_http" => Ok(Self::Http),
            "websocket" | "ws" => Ok(Self::WebSocket),
            other => Err(format!("未知 MCP 传输方式: {other}")),
        }
    }
}

impl TenantScoped for McpServer {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl McpServer {
    /// 是否为"影子 MCP"（发现但未登记）。
    #[must_use]
    pub fn is_shadow(&self) -> bool {
        !self.registered
    }

    /// 高风险工具数量（具备写/执行/网络能力的工具）。
    #[must_use]
    pub fn high_risk_tool_count(&self) -> usize {
        self.tools.iter().filter(|t| t.risk_level().weight() >= crate::enums::Severity::High.weight()).count()
    }
}

impl McpCapabilities {
    /// 具备的能力名列表。
    #[must_use]
    pub fn enabled_names(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.tools {
            v.push("tools");
        }
        if self.resources {
            v.push("resources");
        }
        if self.prompts {
            v.push("prompts");
        }
        if self.logging {
            v.push("logging");
        }
        if self.sampling {
            v.push("sampling");
        }
        if self.roots {
            v.push("roots");
        }
        if self.completions {
            v.push("completions");
        }
        v
    }

    /// 是否存在高风险能力组合（可读取资源 + 可反向调用模型 = 数据外传通道）。
    #[must_use]
    pub const fn has_exfil_channel(&self) -> bool {
        (self.resources || self.roots) && self.sampling
    }
}

impl McpTool {
    /// 工具风险等级（依据能力画像推断）。
    #[must_use]
    pub fn risk_level(&self) -> crate::enums::Severity {
        use crate::enums::Severity;
        let t = &self.traits;
        if t.shell_exec || t.filesystem_write || t.network_egress {
            Severity::High
        } else if t.filesystem_read || t.database || t.credential_access {
            Severity::Medium
        } else if t.network_ingress {
            Severity::Low
        } else {
            Severity::Info
        }
    }
}

impl ToolTraits {
    /// 危险能力组合是否成立（可读文件 + 可出网 = 数据外传）。
    #[must_use]
    pub const fn is_exfil_capable(&self) -> bool {
        self.filesystem_read && self.network_egress
    }

    /// 危险能力组合是否成立（可写文件 + 可执行 = 持久化/命令注入）。
    #[must_use]
    pub const fn is_rce_capable(&self) -> bool {
        self.shell_exec || (self.filesystem_write && self.network_egress)
    }

    /// 从工具名与描述推断能力画像（关键词规则，可解释；LLM 研判可覆盖）。
    #[must_use]
    pub fn infer(name: &str, description: &str) -> Self {
        let hay = format!("{name} {description}").to_lowercase();
        let has = |keys: &[&str]| keys.iter().any(|k| hay.contains(k));
        Self {
            shell_exec: has(&["shell", "exec", "command", "run_", "terminal", "bash", "powershell", "spawn"]),
            filesystem_read: has(&["read_file", "readfile", "cat", "open_file", "list_dir", "ls", "glob", "grep"]),
            filesystem_write: has(&["write_file", "writefile", "save", "create_file", "edit_file", "append", "mkdir"]),
            network_egress: has(&["http", "fetch", "curl", "request", "download", "upload", "webhook", "url"]),
            network_ingress: has(&["listen", "server", "serve", "bind"]),
            database: has(&["sql", "query", "database", "postgres", "mysql", "mongo", "redis"]),
            credential_access: has(&["secret", "vault", "credential", "key", "token", "password", "kms"]),
            messaging: has(&["send_email", "sendmail", "slack", "dingtalk", "feishu", "wecom", "sms", "notify"]),
            cloud_mutation: has(&["create_instance", "delete_", "terminate", "scale", "deploy", "iam", "policy"]),
        }
    }
}
