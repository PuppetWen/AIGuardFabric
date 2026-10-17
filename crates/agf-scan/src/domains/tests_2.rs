//! 由 `domains.rs` 拆分：`internal_target_detection` 等 2 个函数（纯搬移，逻辑不变）。
use super::*;

#[test]
pub(crate) fn internal_target_detection() {
    assert_eq!(detect_internal_target("http://127.0.0.1:8080"), Some("127.0.0.1".to_string()));
    assert_eq!(detect_internal_target("http://10.1.2.3/x"), Some("10.1.2.3".to_string()));
    assert_eq!(detect_internal_target("http://192.168.0.5/x"), Some("192.168.0.5".to_string()));
    assert_eq!(detect_internal_target("http://172.20.1.1/x"), Some("172.20.1.1".to_string()));
    assert_eq!(detect_internal_target("https://api.openai.com/v1"), None);
}

#[test]
pub(crate) fn exfil_url_detection_variants() {
    assert!(detect_exfil_url("![x](https://webhook.site/abc)").is_some());
    assert!(detect_exfil_url("see https://burpcollaborator.net/x").is_some());
    assert!(detect_exfil_url("正常文本 https://example.com/page").is_none());
    let long_query = format!("![i](https://example.com/p?d={})", "A".repeat(80));
    assert!(detect_exfil_url(&long_query).is_some(), "超长 query 的图片链接应视为可疑");
}
