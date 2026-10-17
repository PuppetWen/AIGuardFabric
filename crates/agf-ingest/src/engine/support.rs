//! 能力矩阵与降级：引擎/协议支持表、未实现引擎的显式错误。

use super::*;

/// 厂商动作字符串归一化。
#[must_use]
pub fn normalize_action(raw: &str) -> String {
    let v = raw.trim().to_ascii_lowercase();
    let mapped = match v.as_str() {
        "allow" | "allowed" | "accept" | "accepted" | "pass" | "permit" | "放行" | "允许" => "allowed",
        "deny" | "denied" | "block" | "blocked" | "drop" | "dropped" | "reject" | "rejected" | "quarantine"
        | "isolate" | "contain" | "阻断" | "拒绝" | "隔离" => "denied",
        "create" | "created" | "新建" | "创建" => "created",
        "update" | "updated" | "modify" | "modified" | "修改" => "updated",
        "delete" | "deleted" | "remove" | "removed" | "删除" => "deleted",
        "write" | "put" | "upload" | "写入" => "write",
        "read" | "get" | "query" | "access" | "open" | "读取" => "read",
        "execute" | "exec" | "spawn" | "run" | "执行" => "execute",
        "connect" | "connection" | "established" | "连接" => "connect",
        "disconnect" | "closed" | "断开" => "disconnect",
        "alert" | "alarm" | "告警" => "alert",
        "detect" | "detection" | "检测" => "detect",
        "logon" | "login" | "signin" | "sign-in" | "登录" => "login",
        "logout" | "logoff" | "signout" | "sign-out" | "登出" => "logout",
        "exfiltrate" | "exfil" | "外传" => "exfiltrate",
        other => other,
    };
    mapped.to_string()
}

/// 引擎能力矩阵（接入能力页可直接渲染）。
///
/// `Plugin` 一行的状态由**进程级插件运行时**（见 [`crate::engine::plugin`]）如实折算：
/// 已装载/失败清单与超时策略都在 [`crate::engine::plugin::plugin_runtime_status`] 里，
/// 本函数只给出"代码层面已实现"这一格。
#[must_use]
pub fn engine_support_matrix() -> Vec<(ParserEngine, bool, &'static str)> {
    vec![
        (ParserEngine::Grok, true, "已实现（内置 pattern 表）"),
        (ParserEngine::Regex, true, "已实现（命名捕获组，无命名组退化为 g1..gn）"),
        (ParserEngine::JsonPath, true, "已实现（jsonpath-rust + `字段=$.路径` 规格表）"),
        (ParserEngine::Jq, true, "已实现（jaq-core，纯 Rust，无需外部 jq）"),
        (ParserEngine::Syslog, true, "已实现（RFC3164/5424）"),
        (ParserEngine::Cef, true, "已实现（含 \\| 逃逸与标准键改写）"),
        (ParserEngine::Leef, true, "已实现（LEEF 1.0/2.0）"),
        (ParserEngine::Gelf, true, "已实现（NUL 分隔 JSON）"),
        (ParserEngine::Csv, true, "已实现（表头映射 + 分隔符自动识别）"),
        (ParserEngine::Kv, true, "已实现"),
        (ParserEngine::AiInferred, true, "部分实现（离线启发式，见 ai_parser）"),
        (ParserEngine::Cel, true, "已实现（派生字段：cel-interpreter，见 cel 模块；非独立抽取引擎）"),
        (
            ParserEngine::Plugin,
            true,
            "已实现（Rust 动态库插件：版本化 C ABI + ABI 门禁 + 可配超时；\
             未配置插件目录即无插件可用 ⇒ 该模板如实报错/未命中；不参与样本打分；\
             超时只放弃结果、插件线程仍在跑（同进程调用无法中断））",
        ),
    ]
}

/// 本模块声明的协议支持情况（供 [`crate::receiver::receiver_capability_matrix`] 复用）。
#[must_use]
pub fn protocol_supported(protocol: IngestProtocol) -> bool {
    !matches!(
        protocol,
        IngestProtocol::Kafka | IngestProtocol::Pulsar | IngestProtocol::Mqtt | IngestProtocol::SnmpTrap
    )
}

/// "引擎不可用"的统一错误（供上层转成 501/降级提示）。
///
/// **当前 13 个引擎全部已实现**（`Plugin` 于本轮接线，`Cel` 是派生字段求值），
/// 因此本函数现在只用于"引擎级能力被上层判定为不可用"的兜底路径——不再有任何引擎
/// 因为"没写代码"走到这里。`Plugin` 的运行时缺失走的是 [`crate::engine::plugin`] 的
/// **五类明确失败**（unavailable / unknown_plugin / call_error / bad_output / timeout），
/// 不再是这个笼统的错误。
#[must_use]
pub fn unimplemented_engine_error(engine: ParserEngine) -> DomainError {
    DomainError::NotImplemented(format!(
        "解析引擎 {} 在当前装配下不可用（降级：改用 Regex/Grok 模板或 AI 推断）",
        engine.as_str()
    ))
}
