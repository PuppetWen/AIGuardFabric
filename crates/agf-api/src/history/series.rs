//! 序列归并与小时归并等纯函数（自 `history.rs` 拆出，逻辑未变）。

use super::*;

/// 把"某租户的时间序列点"转成落盘采样点（装配侧一行转换）。
///
/// 典型调用（`state.rs` 侧）：`history::from_points(tenant, points.into_iter().map(|p| (p.at, p.value)))`，
/// 其中 `points` 是 [`crate::state::RiskHistory::points`] 的返回值
/// （[`crate::state::RiskSample`] 的字段 `at` / `value` 都是 `pub`）。
#[must_use]
pub fn from_points(tenant: TenantId, points: impl IntoIterator<Item = (Timestamp, f64)>) -> Vec<Sample> {
    points.into_iter().map(|(ts, value)| Sample::new(tenant, ts, value)).collect()
}

/// 按租户分组（**升序时间**），供调用方回填 `state::RiskHistory`。
#[must_use]
pub fn group_by_tenant(samples: &[Sample]) -> BTreeMap<TenantId, Vec<Sample>> {
    let mut grouped: BTreeMap<TenantId, Vec<Sample>> = BTreeMap::new();
    for sample in samples {
        grouped.entry(sample.tenant_id).or_default().push(*sample);
    }
    for series in grouped.values_mut() {
        series.sort_by_key(|sample| sample.ts);
    }
    grouped
}

/// 合并两批采样点（`existing` 在前、`incoming` 在后）后按 [`normalize`] 归并。
///
/// 语义：**并集 + 小时桶去重 + 裁剪**。不修改任何实际观测值。
#[must_use]
pub fn merge_sets(existing: &[Sample], incoming: &[Sample]) -> Vec<Sample> {
    let mut merged = Vec::with_capacity(existing.len() + incoming.len());
    merged.extend_from_slice(existing);
    merged.extend_from_slice(incoming);
    normalize(merged)
}

/// 按租户归并：每小时保留最后一次实际观测，最多保留 168 个点。
#[must_use]
pub fn normalize(samples: Vec<Sample>) -> Vec<Sample> {
    let mut out = Vec::with_capacity(samples.len());
    for (_, series) in group_by_tenant(&samples) {
        out.extend(roll_up_hourly(&series));
    }
    out
}

/// 单个租户序列的小时桶滚动（输入需已按时间升序）。
fn roll_up_hourly(series: &[Sample]) -> Vec<Sample> {
    let mut out: Vec<Sample> = Vec::with_capacity(series.len());
    for sample in series {
        match out.last() {
            Some(last) if sample.hour_bucket() == last.hour_bucket() => {
                if let Some(slot) = out.last_mut() {
                    *slot = *sample;
                }
            }
            _ => out.push(*sample),
        }
    }
    if out.len() > MAX_SAMPLES_PER_TENANT {
        let drop_count = out.len() - MAX_SAMPLES_PER_TENANT;
        out.drain(0..drop_count);
    }
    out
}

/// 解析文件内容：先试带版本封套的对象，再试裸数组。
pub(super) fn parse_samples(raw: &str) -> Result<Vec<Sample>, String> {
    if let Ok(file) = serde_json::from_str::<HistoryFile>(raw) {
        if file.version > FORMAT_VERSION {
            return Err(format!("风险历史格式版本 {} 高于本进程支持的 {FORMAT_VERSION}", file.version));
        }
        return Ok(file.samples);
    }
    if let Ok(samples) = serde_json::from_str::<Vec<Sample>>(raw) {
        return Ok(samples);
    }
    Err("既不是带版本封套的对象（{version, samples}），也不是采样点数组".to_string())
}

/// 临时文件路径（同目录 + 唯一后缀：`rename` 必须同盘才能原子替换）。
pub(super) fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().map_or_else(|| FILE_NAME.into(), std::ffi::OsString::from);
    name.push(format!(".tmp-{}-{}", std::process::id(), Timestamp::now().unix_millis()));
    path.with_file_name(name)
}
