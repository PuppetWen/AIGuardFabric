//! MCP management, OAuth, proxy and legacy SSE OpenAPI operations.
use super::EndpointSpec;
use utoipa::openapi::path::HttpMethod::{Delete, Get, Post, Put};

pub(super) fn endpoint_specs() -> Vec<EndpointSpec> {
    let mut specs = Vec::new();
    let mut push = |path, method, id, summary, tag, implemented| {
        specs.push(EndpointSpec { path, method, id, summary, tag, implemented });
    };
    push("/api/v1/mcps", Get, "listMcps", "MCP Server 列表", "mcps", true);
    push("/api/v1/mcp/endpoints", Get, "listMcpHttpEndpoints", "MCP HTTP 代理配置（隐藏凭据）", "mcps", true);
    push("/api/v1/mcp/endpoints", Post, "saveMcpHttpEndpoint", "按版本保存 MCP HTTP 代理", "mcps", true);
    push(
        "/api/v1/mcp/oauth/client-metadata/{tenant}/{id}/{revision}",
        Get,
        "getMcpOAuthClientMetadata",
        "供授权服务公开读取的版本绑定 Client ID 元数据文档",
        "mcps",
        true,
    );
    push("/api/v1/mcp/endpoints/{id}/usage", Get, "getMcpToolUsage", "按端点和工具查询已结算调用用量", "mcps", true);
    push(
        "/api/v1/mcp/endpoints/{id}/oauth",
        Get,
        "getMcpOAuth",
        "读取端点 OAuth 配置与连接状态；隐藏密钥和令牌",
        "mcps",
        true,
    );
    push(
        "/api/v1/mcp/endpoints/{id}/oauth",
        Put,
        "saveMcpOAuth",
        "发现资源与授权服务并按版本保存 OAuth 客户端",
        "mcps",
        true,
    );
    push("/api/v1/mcp/endpoints/{id}/oauth/start", Post, "startMcpOAuth", "发起浏览器绑定的 PKCE 授权", "mcps", true);
    push(
        "/api/v1/mcp/endpoints/{id}/oauth/complete",
        Post,
        "completeMcpOAuth",
        "一次性交换授权码并加密保存令牌",
        "mcps",
        true,
    );
    push(
        "/api/v1/mcp/endpoints/{id}/oauth/disconnect",
        Post,
        "disconnectMcpOAuth",
        "移除端点保存的 OAuth 令牌",
        "mcps",
        true,
    );
    push(
        "/api/v1/runtime/mcp/usage",
        Get,
        "getRuntimeMcpToolUsage",
        "按工具查询 Agent / stdio MCP 检查入口累计调用用量",
        "runtime",
        true,
    );
    push("/api/v1/mcp/endpoints/{id}/probe", Post, "probeMcpHttpEndpoint", "只读握手及工具列表检查", "mcps", true);
    push("/api/v1/mcp/proxy/{id}", Post, "proxyMcpMessage", "MCP JSON-RPC / SSE，执行策略与配额", "mcps", true);
    push("/api/v1/mcp/proxy/{id}", Get, "listenLegacyMcp", "传统 Streamable HTTP 会话 SSE", "mcps", true);
    push("/api/v1/mcp/proxy/{id}", Delete, "closeLegacyMcp", "关闭传统 MCP 会话", "mcps", true);
    push("/api/v1/mcp/legacy/{id}/sse", Get, "listenMcpSse2024", "2024 HTTP+SSE 接收流及 POST 地址公告", "mcps", true);
    push(
        "/api/v1/mcp/legacy/{id}/messages/{session}",
        Post,
        "postMcpSse2024",
        "2024 HTTP+SSE 客户端 JSON-RPC 消息",
        "mcps",
        true,
    );
    push("/api/v1/mcps/{id}", Get, "getMcp", "MCP Server 详情", "mcps", true);
    specs
}
