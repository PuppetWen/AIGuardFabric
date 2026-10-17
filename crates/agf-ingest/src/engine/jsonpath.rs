//! JSONPath 与 JQ（jaq）引擎：路径规格解析、扁平化、求值与语句编译。

use super::*;

/// JSONPath 模式的一行规格。
#[derive(Debug, Clone, PartialEq, Eq)]
enum JsonSpec {
    /// `字段名=$.路径`：命中值存到 `字段名`。
    Named(String, String),
    /// 裸路径：对象命中则扁平化展开，标量命中则按路径末段命名。
    Auto(String),
}

/// 解析 `字段名=$.路径` 规格表（`#` 开头为注释）。
fn jsonpath_specs(pattern: &str) -> Vec<JsonSpec> {
    let mut out = Vec::new();
    for raw_line in pattern.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((name, path)) = line.split_once('=') {
            let (name, path) = (name.trim(), path.trim());
            if is_identifier(name) && !path.is_empty() {
                out.push(JsonSpec::Named(name.to_string(), path.to_string()));
                continue;
            }
        }
        out.push(JsonSpec::Auto(line.to_string()));
    }
    out
}

/// 是否为可用于字段名的标识符（`rule.level` 这类带点路径也允许）。
fn is_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// 裸路径 → 字段名（取路径末段，全通配时给 `value`）。
fn auto_path_name(path: &str) -> String {
    let trimmed = path.trim_end_matches([']', ')', '*']);
    let last = trimmed
        .rsplit(['.', '[', ']'])
        .find(|s| !s.is_empty() && *s != "$" && !s.starts_with('?') && !s.starts_with('('));
    last.map_or_else(|| "value".to_string(), ToString::to_string)
}

pub(super) fn parse_jsonpath(pattern: &str, raw: &str) -> Result<BTreeMap<String, Value>, String> {
    use jsonpath_rust::JsonPath as _;

    let value: Value = serde_json::from_str(raw).map_err(|e| format!("不是合法 JSON: {e}"))?;
    let specs = jsonpath_specs(pattern);
    if specs.is_empty() {
        return Err("JsonPath 模式为空（应为逐行 `字段=$.路径`）".to_string());
    }
    let mut out = BTreeMap::new();
    for spec in specs {
        match spec {
            JsonSpec::Named(name, path) => {
                let hits = value.query(&path).map_err(|e| format!("JSONPath 非法: {e:?}"))?;
                match hits.len() {
                    0 => {}
                    1 => {
                        out.insert(name, hits[0].clone());
                    }
                    _ => {
                        out.insert(name, Value::Array(hits.iter().map(|v| (*v).clone()).collect()));
                    }
                }
            }
            JsonSpec::Auto(path) => {
                let hits = value.query(&path).map_err(|e| format!("JSONPath 非法: {e:?}"))?;
                for hit in hits {
                    match hit {
                        Value::Object(obj) => flatten_into("", obj, &mut out),
                        other => {
                            out.insert(auto_path_name(&path), other.clone());
                        }
                    }
                }
            }
        }
    }
    if out.is_empty() {
        return Err("JSONPath 未提取到任何字段".to_string());
    }
    Ok(out)
}

/// 把嵌套 JSON 对象扁平化为 `a.b.c` 键。
fn flatten_into(prefix: &str, obj: &serde_json::Map<String, Value>, out: &mut BTreeMap<String, Value>) {
    for (k, v) in obj {
        let key = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
        match v {
            Value::Object(inner) => flatten_into(&key, inner, out),
            other => {
                out.insert(key, other.clone());
            }
        }
    }
}

/// 只校验 JSONPath 语法（用一个空对象试跑，语法错误会立刻返回）。
pub(super) fn validate_jsonpath(pattern: &str) -> Result<(), String> {
    use jsonpath_rust::JsonPath as _;

    let specs = jsonpath_specs(pattern);
    if specs.is_empty() {
        return Err("JsonPath 引擎需要逐行 `字段=$.路径`（或单行裸路径）".to_string());
    }
    let probe = serde_json::json!({});
    for spec in specs {
        let path = match spec {
            JsonSpec::Named(_, p) | JsonSpec::Auto(p) => p,
        };
        probe.query(&path).map_err(|e| format!("JSONPath 非法（{path}）: {e:?}"))?;
    }
    Ok(())
}

pub(super) fn parse_jq(program: &str, raw: &str) -> Result<BTreeMap<String, Value>, String> {
    use jaq_core::Ctx;
    use jaq_core::RcIter;
    use jaq_json::Val;

    let input: Value = serde_json::from_str(raw).map_err(|e| format!("不是合法 JSON: {e}"))?;
    let filter = compile_jq(program)?;
    let inputs = RcIter::new(core::iter::empty());
    let mut out = BTreeMap::new();
    for item in filter.run((Ctx::new([], &inputs), Val::from(input))) {
        match item {
            Ok(v) => {
                let json: Value = v.into();
                match json {
                    Value::Object(obj) => flatten_into("", &obj, &mut out),
                    other => {
                        out.insert("value".to_string(), other);
                    }
                }
            }
            Err(e) => return Err(format!("JQ 运行错误: {e:?}")),
        }
    }
    if out.is_empty() {
        return Err("JQ 未产出任何字段".to_string());
    }
    Ok(out)
}

/// 编译 JQ 程序（纯语法/编译校验，不执行；`validate_pattern` 与 `parse_jq` 共用）。
pub(super) fn compile_jq(program: &str) -> Result<jaq_core::Filter<jaq_core::Native<jaq_json::Val>>, String> {
    use jaq_core::Compiler;
    use jaq_core::load::{Arena, File, Loader};

    let arena = Arena::default();
    let loader = Loader::new(jaq_std::defs().chain(jaq_json::defs()));
    let modules =
        loader.load(&arena, File { code: program, path: () }).map_err(|errs| format!("JQ 语法错误: {errs:?}"))?;
    Compiler::default()
        .with_funs(jaq_std::funs().chain(jaq_json::funs()))
        .compile(modules)
        .map_err(|errs| format!("JQ 编译错误: {errs:?}"))
}

// ---------------------------------------------------------------------------
// Syslog / CEF / LEEF / GELF
// ---------------------------------------------------------------------------
