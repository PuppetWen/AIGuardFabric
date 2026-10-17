//! Compare compatible complete observations, including recovery after an unreadable scan.
use agf_core::{
    asset::Asset,
    skill_package::{PackageObservation, PackageStatus},
};
use serde_json::Value;

fn verified(value: Option<&Value>) -> Option<PackageObservation> {
    let row: PackageObservation = serde_json::from_value(value?.clone()).ok()?;
    (row.validate().is_ok() && row.status == PackageStatus::Verified).then_some(row)
}

pub(crate) fn remember_verified(asset: &mut Asset) {
    if verified(asset.attributes.get("skill_package")).is_some() {
        if let Some(value) = asset.attributes.get("skill_package").cloned() {
            asset.attributes.insert("skill_package_last_verified".into(), value);
        }
        if let Some(value) = asset.attributes.get("skill_package_received_at").cloned() {
            asset.attributes.insert("skill_package_last_verified_at".into(), value);
        }
    }
}

pub(super) fn differences(before: &Asset, after: &Asset, push: &mut impl FnMut(&'static str, Value, Value)) {
    let old = before.attributes.get("skill_package");
    let new = after.attributes.get("skill_package");
    if old == new {
        return;
    }
    let baseline = verified(old).or_else(|| verified(before.attributes.get("skill_package_last_verified")));
    let current = verified(new);
    if let (Some(baseline), Some(current)) = (baseline, current) {
        if baseline.algorithm == current.algorithm && baseline.sha256 != current.sha256 {
            push("skill_package_sha256", Value::from(baseline.sha256), Value::from(current.sha256));
        }
    }
    // Initial baselining and unavailable/recovered observations are facts, not tampering verdicts.
    if old.and_then(|v| v.get("status")) != new.and_then(|v| v.get("status"))
        || old.and_then(|v| v.get("sha256")) == new.and_then(|v| v.get("sha256"))
    {
        push("skill_package_observation", old.cloned().unwrap_or_default(), new.cloned().unwrap_or_default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drift::{DriftScanner, tests::asset};
    use agf_core::{enums::AssetKind, time::Timestamp};
    use serde_json::json;

    #[test]
    fn first_baseline_is_informational_and_recovery_compares_last_complete_hash() {
        let before = asset(AssetKind::Skill, "package");
        let mut after = before.clone();
        let observed =
            json!({"algorithm":"sha256-tree-v1","status":"verified","sha256":"a".repeat(64),"files":2,"bytes":46});
        after.attributes.insert("skill_package".into(), observed.clone());
        let scanner = DriftScanner::new();
        let changes = scanner.diff_one(&before, &after, Timestamp::now());
        assert_eq!(changes.len(), 1);
        assert!(!changes[0].risky);
        remember_verified(&mut after);
        let before = after.clone();
        after.attributes.insert("skill_package".into(), json!({"algorithm":"sha256-tree-v1","status":"unreadable"}));
        remember_verified(&mut after);
        assert_eq!(after.attributes.get("skill_package_last_verified"), Some(&observed));
        assert!(scanner.diff_one(&before, &after, Timestamp::now()).iter().all(|row| !row.risky));
        let unavailable = after.clone();
        let mut updated = observed;
        updated["sha256"] = json!("b".repeat(64));
        after.attributes.insert("skill_package".into(), updated);
        remember_verified(&mut after);
        let changes = scanner.diff_one(&unavailable, &after, Timestamp::now());
        assert!(changes.iter().any(|row| row.field.as_deref() == Some("skill_package_sha256") && row.risky));
        let before = after.clone();
        after.attributes.insert("skill_package_received_at".into(), json!(Timestamp::now()));
        remember_verified(&mut after);
        assert!(scanner.diff_one(&before, &after, Timestamp::now()).is_empty());
    }
}
