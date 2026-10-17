//! `ParserEngine::Plugin`：把 Rust 动态库插件接进解析管线（宿主侧接线层）。
//!
//! ## 它解决什么
//!
//! `engine::run_engine` 的 `Plugin` 分支不再返回"未实现"：模板声明
//! `engine: plugin` 时，宿主**真的去调插件**，并把插件返回的 AGF-ECS JSON 交给
//! **既有的** `apply_mapping` / `normalize` 路径（不另写一套 Event 构造）。
//!
//! 插件装载、ABI 门禁、错误分类在 [`agf_plugin`] crate 里（版本化稳定 C ABI：
//! 唯一符号 `agf_plugin_descriptor_v1`）。本模块只负责"接线 + 超时 + 诊断"。
//!
//! ## 模板怎么写
//!
//! `pattern`（`engine: plugin` 时的**唯一**声明处）写成一行规格：
//!
//! ```yaml
//! engine: plugin
//! pattern: "plugin=agf-plugin-example"          # 最小形态
//! # pattern: "plugin=demo entry=normalize ctx=envelope"   # 全量形态
//! ```
//!
//! | 规格项 | 取值 | 默认 | 说明 |
//! |---|---|---|---|
//! | `plugin=<name>`（或裸 `<name>`） | 插件描述符里的 `name`（`[A-Za-z0-9._-]`） | 必填 | 按名字在插件运行时里查找 |
//! | `entry=<fn>` | **只接受 `normalize`** | `normalize` | ABI v1 只导出 `normalize` 一个入口；写别的值**明确报错**（不静默忽略） |
//! | `ctx=raw` | 把原始日志行原样传给 `normalize` | `raw` | 与已交付的示例插件兼容 |
//! | `ctx=envelope` | 传 `{"input": "<原始行>", "context": {protocol, source, received_at}}` | | 需要上下文的插件声明它；原始行仍在 `input` 里 |
//!
//! 未知规格项一律**加载期报错**（[`validate_pattern`](super::validate_pattern)），
//! 坏模板不进入匹配集。
//!
//! ## 插件返回什么
//!
//! 插件必须返回**顶层为对象**的 AGF-ECS JSON（示例插件产出的形态）。宿主把嵌套对象
//! **扁平化**成点号键（`source.ip` / `event.action` / `labels.tenant`），再走既有映射：
//!
//! * 已是 ECS 路径的键（`source.ip`、`event.action`、`message` …）原样进 `fields`；
//! * 模板 `mapping.map` 里声明的**源字段名**照常改写；
//! * 其余进 `extra`（由 `normalize` 决定是否落到 `Event::extra`，**绝不丢弃**）；
//! * 插件的时间戳用模板 `mapping.time_field: "@timestamp"` 声明即可落到 `event.time`
//!   （复用 `map_time`，不为插件另开一条时间路径）。
//!
//! ## 失败与超时（全部如实计数，绝不 panic、绝不静默丢弃）
//!
//! | 情况 | 分类 | 行为 |
//! |---|---|---|
//! | 未配置插件目录 / 未装载运行时 | `unavailable` | 返回明确错误 ⇒ 该模板不命中（原始日志照常落库） |
//! | 插件名不在已装载集合里 | `unknown_plugin` | 同上（错误文本列出已装载插件名） |
//! | 插件返回业务错误（`normalize` 空指针 / 非 0） | `call_errors` | 同上（原因含插件自己的 `last_error`） |
//! | 插件返回非法 JSON / 顶层非对象 / 空对象 | `bad_output` | 同上 |
//! | 调用超过 `AGF_INGEST_PLUGIN_TIMEOUT_MS` | `timeouts` | 放弃本次结果并计失败 |
//!
//! 失败还会进**最近 32 条诊断环形缓冲**（[`PluginRuntimeStatus::recent_diagnostics`]，
//! 与模板 `derived_errors` 同一"如实记账"风格），并由 `/readyz` 的能力矩阵行 +
//! 启动日志暴露。
//!
//! ### 超时的真实局限（必须如实说明）
//!
//! 插件是**同进程代码**，`normalize` 是同步 C ABI 调用，**无法被真正中断**。
//! 因此超时的语义是"**宿主放弃这次结果**"，而**被放弃的插件调用线程仍在继续跑**
//! （它会跑完、然后被丢弃）。要真正可中断，必须换进程边界（子进程 + IPC/沙箱），
//! 那不是本 crate 的形态。`AGF_INGEST_PLUGIN_TIMEOUT_MS=0` 表示**不启用超时**
//! （同线程直调，插件卡死会拖住解析线程）——默认 500ms，不建议改成 0。
//!
//! ## 上下文从哪来
//!
//! `protocol` / `source` 由注册表匹配路径（[`crate::registry::ParserRegistry::match_raw_with_mode`]）
//! 写入 thread-local（`source` 取调用方给的厂商标识提示，流水线传的是 `LogSource.vendor`），
//! `received_at` 取解析时刻。**直接调用 `engine::parse_with` 时上下文为空串**——
//! 这是如实状态，不是"假装有上下文"。

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use agf_core::time::Timestamp;
use serde_json::Value;

mod invoker;
mod runtime;
mod status;

// 三个子模块按"职责"切分（本文件负责纯逻辑：规格 / 上下文 / 扁平化）：
//   * `invoker`：调用接口（trait）与真实插件调用器、失败分类；
//   * `status`：运行态快照与 `/readyz` notes 文案；
//   * `runtime`：计数、诊断、超时包装、进程级装载点与环境变量。
pub use invoker::*;
pub use runtime::*;
pub use status::*;

/// 插件目录环境变量（缺省 `<项目根>/plugins`）。
pub const PLUGIN_DIR_ENV: &str = "AGF_INGEST_PLUGIN_DIR";
/// 单次插件调用超时（毫秒）环境变量。
pub const PLUGIN_TIMEOUT_ENV: &str = "AGF_INGEST_PLUGIN_TIMEOUT_MS";
/// 默认超时（毫秒）。**刻意不设 0**：同进程调用无法中断，卡死的插件会拖住解析线程。
pub const DEFAULT_PLUGIN_TIMEOUT_MS: u64 = 500;
/// 插件运行时默认目录名（`<项目根>/plugins`）。
pub const DEFAULT_PLUGIN_DIR_NAME: &str = "plugins";

/// 插件规格里 `entry=` 的**唯一**合法取值（ABI v1 只导出这一个入口）。
pub const PLUGIN_ENTRY_NORMALIZE: &str = "normalize";

/// 传给插件 `normalize` 的输入形态（规格项 `ctx=`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginInput {
    /// 原始日志行原样传（默认；与已交付的示例插件兼容）。
    Raw,
    /// 传 `{"input": …, "context": {…}}` JSON 信封。
    Envelope,
}

impl PluginInput {
    /// 文本形式（规格与展示共用）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Envelope => "envelope",
        }
    }
}

/// 模板 `pattern` 解析出的插件规格。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginSpec {
    /// 插件名（描述符里的 `name`；字符集与 `agf_plugin` 的描述符校验一致）。
    pub name: String,
    /// 入口函数名（ABI v1 恒为 `normalize`）。
    pub entry: String,
    /// 传给插件的输入形态。
    pub input: PluginInput,
}

impl PluginSpec {
    /// 规格的规范化文本（错误信息与诊断用）。
    #[must_use]
    pub fn describe(&self) -> String {
        format!("plugin={} entry={} ctx={}", self.name, self.entry, self.input.as_str())
    }
}

/// 解析插件规格（`plugin=<name> [entry=normalize] [ctx=raw|envelope]`）。
///
/// `#` 起为**行内注释**（到行尾）；片段间用空白/逗号分隔（与 YAML 里写多行等价）。
/// 裸片段（不含 `=`）等价于 `plugin=<片段>`。
///
/// # Errors
/// 规格为空、插件名非法/重复、入口不是 `normalize`、`ctx` 取值不认识、出现未知规格项。
pub fn parse_plugin_spec(pattern: &str) -> Result<PluginSpec, String> {
    let mut name: Option<String> = None;
    let mut entry = PLUGIN_ENTRY_NORMALIZE.to_string();
    let mut input = PluginInput::Raw;
    let mut seen_entry = false;
    let mut seen_ctx = false;

    // 逐行剥注释后再切片段：`pattern` 常写成多行 YAML 字符串，行内 `#` 之后是注释而不是名字
    // （旧写法只跳过"以 `#` 开头的片段"，`# 注释文字` 的后半段会被误当成插件名）。
    for token in pattern
        .lines()
        .flat_map(|line| line.split('#').next().unwrap_or_default().split([' ', '\t', '\r', ',']))
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        let Some((key, value)) = token.split_once('=') else {
            if name.is_some() {
                return Err(format!("插件规格里出现了第二个插件名 `{token}`（只允许一个）"));
            }
            name = Some(validate_plugin_name(token)?);
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        match key {
            "plugin" | "name" => {
                if name.is_some() {
                    return Err(format!("插件规格里重复声明了插件名 `{value}`"));
                }
                name = Some(validate_plugin_name(value)?);
            }
            "entry" => {
                if seen_entry {
                    return Err("插件规格里重复声明了 entry".to_string());
                }
                if value != PLUGIN_ENTRY_NORMALIZE {
                    return Err(format!(
                        "entry={value} 不支持：ABI v1 只导出 `{PLUGIN_ENTRY_NORMALIZE}` 一个入口（不静默改用别的入口）"
                    ));
                }
                entry = value.to_string();
                seen_entry = true;
            }
            "ctx" => {
                if seen_ctx {
                    return Err("插件规格里重复声明了 ctx".to_string());
                }
                input = match value {
                    "raw" => PluginInput::Raw,
                    "envelope" => PluginInput::Envelope,
                    other => return Err(format!("ctx={other} 不认识（可用 raw / envelope）")),
                };
                seen_ctx = true;
            }
            other => return Err(format!("插件规格里出现未知项 `{other}`（可用 plugin / entry / ctx）")),
        }
    }

    let Some(name) = name else {
        return Err(format!("Plugin 引擎需要插件名（如 `plugin=agf-plugin-example`，当前 pattern=`{pattern}`）"));
    };
    Ok(PluginSpec { name, entry, input })
}

/// 插件名字符集校验（与 `agf_plugin` 描述符校验规则一致）。
fn validate_plugin_name(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("插件名不得为空".to_string());
    }
    if raw.len() > 64 {
        return Err(format!("插件名长度必须在 1..=64 字节，实际 {}", raw.len()));
    }
    if !raw.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')) {
        return Err(format!("插件名 `{raw}` 含非法字符（只允许 [A-Za-z0-9._-]）"));
    }
    Ok(raw.to_string())
}

/// 传给插件的调用上下文（协议 / 源 / 时间）。
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PluginContext {
    /// 接入协议（注册表匹配路径写入；直接调 `parse_with` 时为空串）。
    pub protocol: String,
    /// 源标识（流水线传的是 `LogSource.vendor` 提示；拿不到时为空串）。
    pub source: String,
    /// 解析时刻（RFC3339）。
    pub received_at: String,
}

thread_local! {
    /// 当前线程的插件上下文（由注册表匹配路径设置，`Drop` 时还原）。
    static PLUGIN_CONTEXT: RefCell<Option<PluginContext>> = const { RefCell::new(None) };
}

/// 设置当前线程的插件上下文，返回**还原守卫**（`Drop` 时恢复原值）。
///
/// 之所以用守卫而不是 `set`/`clear` 配对：匹配路径里有多个提前 `return`，
/// 手写清理必然漏掉某条分支（漏掉就会把上下文泄漏给后续无关的解析）。
#[must_use]
pub fn set_plugin_context(context: PluginContext) -> PluginContextGuard {
    let previous = PLUGIN_CONTEXT.with(|slot| slot.borrow_mut().replace(context));
    PluginContextGuard { previous }
}

/// [`set_plugin_context`] 的还原守卫。
#[derive(Debug)]
pub struct PluginContextGuard {
    previous: Option<PluginContext>,
}

impl Drop for PluginContextGuard {
    fn drop(&mut self) {
        let previous = self.previous.take();
        PLUGIN_CONTEXT.with(|slot| {
            *slot.borrow_mut() = previous;
        });
    }
}

/// 当前线程的插件上下文（未设置时返回空上下文 + 当前时间）。
#[must_use]
pub fn current_plugin_context() -> PluginContext {
    PLUGIN_CONTEXT.with(|slot| slot.borrow().clone()).unwrap_or_else(|| PluginContext {
        protocol: String::new(),
        source: String::new(),
        received_at: Timestamp::now().to_rfc3339(),
    })
}

/// 插件输出 JSON → **映射前**的扁平字段表（嵌套对象展开为点号键）。
///
/// 与其它引擎**同一口径**：返回的表就是 `required_fields` 判定、
/// `sample_match_score` 与 `apply_mapping` 的输入（插件因此不需要另写映射路径）。
///
/// # Errors
/// 非法 JSON、顶层不是对象、或对象为空（空对象等于"什么都没抽到"，按不匹配处理）。
pub fn plugin_json_to_fields(text: &str) -> Result<BTreeMap<String, Value>, String> {
    let value: Value = serde_json::from_str(text).map_err(|e| format!("插件返回的不是合法 JSON: {e}"))?;
    let Value::Object(object) = value else {
        return Err(format!("插件返回的 JSON 顶层必须是对象（AGF-ECS 字段表），实际是 {}", json_kind(&value)));
    };
    let mut out = BTreeMap::new();
    flatten_object("", &object, &mut out);
    if out.is_empty() {
        return Err("插件返回了空对象（未产出任何字段）".to_string());
    }
    Ok(out)
}

/// JSON 值的形态名（错误信息用）。
fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "布尔值",
        Value::Number(_) => "数字",
        Value::String(_) => "字符串",
        Value::Array(_) => "数组",
        Value::Object(_) => "对象",
    }
}

/// 递归扁平化：`{source:{ip:x}}` → `source.ip=x`；数组按原值落到该键（不展开）。
fn flatten_object(prefix: &str, object: &serde_json::Map<String, Value>, out: &mut BTreeMap<String, Value>) {
    for (key, value) in object {
        let path = if prefix.is_empty() { key.clone() } else { format!("{prefix}.{key}") };
        match value {
            Value::Object(inner) => flatten_object(&path, inner, out),
            other => {
                out.insert(path, other.clone());
            }
        }
    }
}

/// 默认插件目录（`<项目根>/plugins`）。
#[must_use]
pub fn default_plugin_dir(root: &Path) -> PathBuf {
    root.join(DEFAULT_PLUGIN_DIR_NAME)
}

#[cfg(test)]
mod tests;
