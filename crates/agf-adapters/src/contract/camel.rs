//! 由 `contract.rs` 拆分：`camel` 函数（纯搬移，逻辑不变）。

/// 把 kebab-case 名称转为 UpperCamel（用于 Mock 位置文案）。
#[must_use]
pub fn camel(name: &str) -> String {
    name.split(['-', '_'])
        .filter(|s| !s.is_empty())
        .map(|s| {
            let mut chars = s.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().chain(chars).collect::<String>(),
                None => String::new(),
            }
        })
        .collect()
}
