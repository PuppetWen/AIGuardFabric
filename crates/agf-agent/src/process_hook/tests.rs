//! 纯契约与本地准入边界；不附着内核、不启动 WMI、不操作宿主进程。
use super::*;
use crate::client::TlsConfig;
use agf_core::{enums::PolicyAction, process_hook::launch_action_supported};
#[test]
fn observed_non_utf8_filename_is_preserved_without_inventing_arguments_or_enforcement() {
    let body =
        event(Id::new(), ProcessSource::LinuxSchedExec, b"/owned/\xff\nfile", Some(7), Some(10), Some(123), true, 0);
    assert_eq!(body.validate().unwrap(), b"/owned/\xff\nfile");
    assert!(body.arguments.is_empty());
    assert_eq!(body.mode, ProcessMode::Observe);
    let text = format!("{body:?}");
    assert!(!text.contains("file"));
    let mut spoofed = serde_json::to_value(body).unwrap();
    spoofed["tenant_id"] = serde_json::json!(Id::new());
    assert!(serde_json::from_value::<ProcessRequest>(spoofed).is_err());
}
#[test]
fn loss_frame_and_supported_actions_do_not_advertise_capabilities_the_launcher_does_not_have() {
    let mut loss = event(Id::new(), ProcessSource::LinuxSchedExec, &[], None, None, None, false, 12);
    assert!(loss.validate().is_ok());
    loss.pid = Some(42);
    assert!(loss.validate().is_err());
    for action in [
        PolicyAction::Deny,
        PolicyAction::Quota,
        PolicyAction::Redact,
        PolicyAction::Throttle,
        PolicyAction::Degrade,
        PolicyAction::CircuitBreak,
        PolicyAction::Isolate,
        PolicyAction::Approval,
    ] {
        assert!(!launch_action_supported(action, false, false));
        assert!(launch_action_supported(action, true, false));
    }
    assert!(launch_action_supported(PolicyAction::Allow, false, false));
    assert!(launch_action_supported(PolicyAction::Audit, false, false));
    assert!(!launch_action_supported(PolicyAction::Allow, false, true));
}
#[test]
fn transport_rejects_plaintext_credentialed_urls_redirect_authority_and_insecure_tls_before_network() {
    for base in
        ["http://localhost", "https://user:password@localhost", "https://localhost/prefix", "https://localhost?query=1"]
    {
        assert!(ProcessClient::new(base, "agf_owned_fixture".to_string().into(), &TlsConfig::default()).is_err());
    }
    let insecure = TlsConfig { insecure_skip_verify: true, ..TlsConfig::default() };
    assert!(ProcessClient::new("https://localhost", "agf_owned_fixture".to_string().into(), &insecure).is_err());
}
// 该受控测试程序只由下面 TLS 副作用门禁通过已拥有的 Child 启动。
#[test]
#[ignore = "由受管启动回归调用的受控子进程入口"]
fn managed_child_side_effect() {
    let root = std::env::current_exe().unwrap().parent().unwrap().to_owned();
    assert!(std::env::vars_os().all(|(name, _)| !name.to_str().is_some_and(|n| n.starts_with("AGF_"))));
    std::fs::write(root.join("side-effect.marker"), b"owned-approved-execution").unwrap();
}
