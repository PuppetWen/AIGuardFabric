//! 模板文件装载与一致性辅助：YAML 目录遍历、单文件解析、协议/格式合理性与引擎能力矩阵。

use super::*;

/// 模板是否声明支持该协议（`protocols` 为空 = 不限协议，与旧行为一致）。
pub(super) fn protocol_allowed(def: &ParserDefinition, protocol: IngestProtocol) -> bool {
    def.protocols.is_empty() || def.protocols.contains(&protocol)
}

/// 载荷是否为 JSON 文档（对象/数组）。
fn is_json_document(raw: &str) -> bool {
    let trimmed = raw.trim_start();
    (trimmed.starts_with('{') || trimmed.starts_with('[')) && serde_json::from_str::<serde_json::Value>(trimmed).is_ok()
}

/// **格式自证**闸门（放宽趟与样本打分趟共用）。
///
/// 严格趟不需要它：协议声明本身就是模板作者对"这条通道会送来什么形态"的承诺。
/// 另外两趟放宽的分别是**协议**（放宽趟）与**协议+厂商**（样本打分），不能连"引擎要求的
/// 输入形态"一起放宽——`Csv` 引擎会把一条 JSON 日志按逗号切开，再按 pattern 里的列名凑出
/// `required_fields`，产生**假命中**（实测：`paloalto-panos-csv` 吃掉一条 JSON 载荷，
/// 把 AI 推断兜底都顶掉了；样本打分趟没有这道闸门时会从另一个门复现同一个坑）。
/// 反方向不需要闸门：`JsonPath`/`Jq` 引擎自己就要求载荷是合法 JSON。
pub(super) fn format_plausible(def: &ParserDefinition, raw: &str) -> bool {
    match def.engine {
        ParserEngine::Csv => !is_json_document(raw),
        _ => true,
    }
}

/// 厂商提示是否接受该模板（`None` = 不过滤；与修复前的判定逐字一致）。
pub(super) fn vendor_accepts(def: &ParserDefinition, hint: Option<&str>) -> bool {
    let Some(hint) = hint else { return true };
    let v = def.vendor.to_lowercase();
    let p = def.product.to_lowercase();
    v.is_empty() || v.contains(hint) || hint.contains(&v) || p.contains(hint)
}

/// 递归收集 YAML 文件（不使用 walkdir，避免额外依赖面）。
///
/// 顺序**确定性**很重要：同名/同优先级模板的匹配顺序会随目录遍历顺序变化，
/// 因此先按文件名排序处理当前目录的文件，再按名字排序递归子目录
/// （保证 `单文件模板` 先于 `子目录模板` 注册，测试与线上行为一致）。
pub(super) fn collect_yaml_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> DomainResult<()> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| DomainError::Internal(format!("读取目录 {} 失败: {e}", dir.display())))?;
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    let mut subdirs: Vec<std::path::PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| DomainError::Internal(format!("遍历目录失败: {e}")))?;
        let path = entry.path();
        if path.is_dir() {
            subdirs.push(path);
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml") {
                files.push(path);
            }
        }
    }
    files.sort();
    subdirs.sort();
    out.extend(files);
    for sub in subdirs {
        collect_yaml_files(&sub, out)?;
    }
    Ok(())
}

/// 解析模板文件（单模板或 `{parsers: [...]}` 包装）。
///
/// # Errors
/// YAML 非法。
pub fn parse_template_file(text: &str) -> Result<Vec<ParserDefinition>, String> {
    #[derive(serde::Deserialize)]
    struct Wrapper {
        parsers: Vec<ParserDefinition>,
    }
    if let Ok(wrapper) = serde_yaml::from_str::<Wrapper>(text) {
        return Ok(wrapper.parsers);
    }
    serde_yaml::from_str::<ParserDefinition>(text).map(|d| vec![d]).map_err(|e| format!("YAML 解析失败: {e}"))
}

/// 引擎实现状态清单（UI"接入能力"页展示；文档与代码同源）。
///
/// 这里的 `plugin` 一行是"**代码层面已实现**"；本进程**实际装载了哪些插件**由
/// [`crate::engine::plugin::plugin_runtime_status`] 给出（两张表口径不同，都要看）。
#[must_use]
pub fn engine_support_matrix() -> BTreeMap<&'static str, &'static str> {
    ParserEngine::all()
        .into_iter()
        .map(|e| {
            let status = match e {
                ParserEngine::Cel => "已实现（派生字段；非独立抽取引擎，主引擎请用 Grok/Regex/…）",
                ParserEngine::Plugin => {
                    "已实现（Rust 动态库插件：版本化 C ABI + 超时；未装载插件时该模板如实报错/未命中）"
                }
                ParserEngine::AiInferred => "部分实现（离线启发式，见 ai_parser）",
                _ => "已实现",
            };
            (e.as_str(), status)
        })
        .collect()
}
