//! CEL 派生字段（模板 `derived` 段）求值。
//!
//! 解析模板可在 `derived` 段声明「目标 ECS 路径 → 表达式」，在引擎抽取并完成
//! [`crate::engine`] 的字段映射之后，对映射结果做**派生计算**，产出新的 ECS 字段。
//!
//! ## 支持的三种形式（按优先级匹配）
//!
//! | 形式 | 语义 | 示例 |
//! |---|---|---|
//! | `copy:<源字段>` | 直接复制字段值（保留原短路行为） | `copy:source.ip` |
//! | `const:<字面量>` | 常量（整型/浮点/布尔，其余按字符串） | `const:critical` |
//! | 其它任意字符串 | **CEL 表达式**，用 `cel-interpreter` 求值 | `severity >= 7 ? 'high' : 'low'` |
//!
//! ## 表达式可用变量
//!
//! 求值上下文注入两个变量：`fields`（映射后扁平字段表）与 `extra`（未映射到 ECS
//! 路径的剩余字段）。键含点号（`source.ip`），需用**索引**访问：
//! `fields['event.severity'] == 'high' ? fields['user.name'] : 'unknown'`。
//!
//! ## 降级行为
//!
//! 单条表达式编译/求值失败**不中断解析**，只把原因记入 `ParseOutcome::derived_errors`
//! （与既有 `copy:`/`const:` 同一口径），对应目标字段不写值；无法转 JSON 的返回值
//! 同样按失败处理。

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use cel_interpreter::objects::{Key, Map};
use cel_interpreter::{Context, Program, Value as CelValue};
use serde_json::Value;

type CacheEntry = Result<Arc<Program>, String>;

/// 编译缓存：表达式文本 → 编译结果。同一表达式在批量日志上反复求值，只编译一次。
fn program_cache() -> &'static Mutex<std::collections::HashMap<String, CacheEntry>> {
    static CACHE: OnceLock<Mutex<std::collections::HashMap<String, CacheEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// 每个表达式**真正调用 `Program::compile` 的次数**（命中缓存不增加）。
///
/// 为什么可观测：编译缓存是本模块唯一的有状态优化，"缓存生效"必须能被断言，
/// 否则"每次求值都重新编译"（批量日志上的主要开销）在测试里完全看不出来。
fn compile_attempts_table() -> &'static Mutex<std::collections::HashMap<String, u64>> {
    static ATTEMPTS: OnceLock<Mutex<std::collections::HashMap<String, u64>>> = OnceLock::new();
    ATTEMPTS.get_or_init(|| Mutex::new(std::collections::HashMap::new()))
}

/// 某表达式真正经历过几次编译（`0` = 还没编译过；反复求值应恒为 `1`）。
#[must_use]
pub fn compile_attempts(expr: &str) -> u64 {
    compile_attempts_table().lock().ok().and_then(|table| table.get(expr).copied()).unwrap_or(0)
}

/// 某表达式当前是否已在缓存里（**含编译失败的条目**：非法表达式同样只编译一次）。
#[must_use]
pub fn is_cached(expr: &str) -> bool {
    program_cache().lock().map(|cache| cache.contains_key(expr)).unwrap_or(false)
}

/// 记录一次编译尝试。
fn note_compile_attempt(expr: &str) {
    if let Ok(mut table) = compile_attempts_table().lock() {
        *table.entry(expr.to_string()).or_insert(0) += 1;
    }
}

/// 编译（带缓存）一条 CEL 表达式。
///
/// `cel-parser`（antlr4rust）在部分**语法错误**输入上会在错误恢复路径触发
/// `unreachable!` panic 而非返回 `Err`，因此这里用 `catch_unwind` 兜住，
/// 保证"模板写错表达式"永远降级为 `derived_errors`，绝不让接入进程 panic。
fn compile(expr: &str) -> Result<Arc<Program>, String> {
    if let Some(entry) = program_cache().lock().ok().and_then(|g| g.get(expr).cloned()) {
        return entry;
    }
    note_compile_attempt(expr);
    let source = expr.to_string();
    let entry: CacheEntry = std::panic::catch_unwind(move || Program::compile(&source))
        .map_err(|_| "CEL 语法非法（解析器内部错误恢复）".to_string())
        .and_then(|r| r.map(Arc::new).map_err(|e| e.to_string()));
    if let Ok(mut guard) = program_cache().lock() {
        guard.insert(expr.to_string(), entry.clone());
    }
    entry
}

/// 求值单条派生表达式，返回应写入目标路径的 JSON 值。
///
/// # Errors
/// `copy:` 源缺失、或 CEL 表达式编译/求值/JSON 转换失败时返回原因。
pub fn evaluate(
    target: &str,
    expr: &str,
    fields: &BTreeMap<String, Value>,
    extra: &BTreeMap<String, Value>,
) -> Result<Value, String> {
    if let Some(src) = expr.strip_prefix("copy:") {
        let src = src.trim();
        return fields
            .get(src)
            .or_else(|| extra.get(src))
            .cloned()
            .ok_or_else(|| format!("派生字段 {target} 的源 {src} 不存在"));
    }
    if let Some(lit) = expr.strip_prefix("const:") {
        return Ok(const_literal(lit.trim()));
    }
    evaluate_cel(target, expr, fields, extra)
}

/// `const:` 字面量 → JSON 值（尽量识别数值/布尔，否则按字符串）。
fn const_literal(lit: &str) -> Value {
    if let Ok(i) = lit.parse::<i64>() {
        return Value::from(i);
    }
    if let Ok(f) = lit.parse::<f64>() {
        if let Some(n) = serde_json::Number::from_f64(f) {
            return Value::Number(n);
        }
    }
    match lit {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        "null" => Value::Null,
        _ => Value::from(lit),
    }
}

/// 用 CEL 求值一条表达式。
fn evaluate_cel(
    target: &str,
    expr: &str,
    fields: &BTreeMap<String, Value>,
    extra: &BTreeMap<String, Value>,
) -> Result<Value, String> {
    let program = compile(expr).map_err(|e| format!("派生字段 {target} 的表达式编译失败: {e}"))?;
    let mut ctx = Context::default();
    ctx.add_variable_from_value("fields", json_map_to_cel(fields));
    ctx.add_variable_from_value("extra", json_map_to_cel(extra));
    let value = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| program.execute(&ctx)))
        .map_err(|_| format!("派生字段 {target} 求值触发内部 panic"))?
        .map_err(|e| format!("派生字段 {target} 求值失败: {e}"))?;
    value.json().map_err(|e| format!("派生字段 {target} 的结果无法转 JSON: {e}"))
}

/// `BTreeMap<String, serde_json::Value>` → CEL `Map`。
fn json_map_to_cel(map: &BTreeMap<String, Value>) -> CelValue {
    let mut inner: std::collections::HashMap<Key, CelValue> = std::collections::HashMap::with_capacity(map.len());
    for (k, v) in map {
        inner.insert(Key::from(k.clone()), json_to_cel(v));
    }
    CelValue::Map(Map { map: Arc::new(inner) })
}

/// `serde_json::Value` → CEL `Value`（递归）。
fn json_to_cel(v: &Value) -> CelValue {
    match v {
        Value::Null => CelValue::Null,
        Value::Bool(b) => CelValue::Bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                CelValue::Int(i)
            } else if let Some(u) = n.as_u64() {
                CelValue::UInt(u)
            } else if let Some(f) = n.as_f64() {
                CelValue::Float(f)
            } else {
                CelValue::Null
            }
        }
        Value::String(s) => CelValue::String(Arc::new(s.clone())),
        Value::Array(arr) => CelValue::List(Arc::new(arr.iter().map(json_to_cel).collect::<Vec<_>>())),
        Value::Object(obj) => {
            let mut inner: std::collections::HashMap<Key, CelValue> =
                std::collections::HashMap::with_capacity(obj.len());
            for (k, val) in obj {
                inner.insert(Key::from(k.clone()), json_to_cel(val));
            }
            CelValue::Map(Map { map: Arc::new(inner) })
        }
    }
}

/// 求值模板的全部 `derived` 条目，把成功结果写入 `fields`，失败原因收集返回。
///
/// 这是 [`crate::engine`] 的接入口：在字段映射完成后调用，按目标 ECS 路径写值。
/// 单条失败不影响其余派生字段，也不让整条事件解析失败（"派生失败不丢数据"）。
pub fn apply_derived(
    def: &agf_core::parser::ParserDefinition,
    fields: &mut BTreeMap<String, Value>,
    extra: &BTreeMap<String, Value>,
) -> Vec<String> {
    let mut errors = Vec::new();
    for (target, expr) in &def.derived {
        match evaluate(target, expr, fields, extra) {
            Ok(value) => {
                fields.insert(target.clone(), value);
            }
            Err(reason) => errors.push(reason),
        }
    }
    errors
}
