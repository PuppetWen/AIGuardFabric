//! Automatic configured injection into byte-identical ordinary business files, not explicit SDK decorators.
use super::{
    fail,
    owned::{Owned, write_new},
    platform::{Key, Platform},
    queue, subprocess,
};
use agf_api::agentteams_audit::binding::Binding;
use agf_core::{error::DomainResult, ids::Id};
use futures::FutureExt;
use serde_json::{Value, json};
use std::{panic::AssertUnwindSafe, path::PathBuf, sync::atomic::Ordering};

#[derive(Clone, Copy)]
pub(crate) enum Language {
    Python,
    Node,
}
impl Language {
    fn name(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::Node => "node",
        }
    }
}
struct Business {
    dir: PathBuf,
    entry: PathBuf,
    descriptor: PathBuf,
    language: Language,
    source_bytes: Vec<u8>,
}
impl Business {
    fn create(owned: &Owned, platform: &Platform, binding: &Binding, language: Language) -> DomainResult<Self> {
        let dir = owned.root.join(format!("{}-{}", language.name(), Id::new().as_uuid().simple()));
        std::fs::create_dir(&dir).map_err(|_| fail("business case directory"))?;
        write_new(
            &dir.join(".owner"),
            format!("{}:{}", platform.tenant, dir.file_name().unwrap().to_string_lossy()).as_bytes(),
        )?;
        let (entry, source) = match language {
            Language::Python => (include_str!("fixtures/entry.py"), include_str!("fixtures/business.py")),
            Language::Node => (include_str!("fixtures/entry.cjs"), include_str!("fixtures/business.cjs")),
        };
        let extension = if matches!(language, Language::Python) { "py" } else { "cjs" };
        let entry_path = dir.join(format!("entry.{extension}"));
        write_new(&entry_path, entry.as_bytes())?;
        write_new(&dir.join(format!("business.{extension}")), source.as_bytes())?;
        write_new(&dir.join("launch.py"), include_bytes!("fixtures/launch.py"))?;
        write_new(&dir.join("inspect_queue.py"), include_bytes!("fixtures/queue_inspect.py"))?;
        let worker = json!({"name":"worker-demo","team":"my-team"});
        let targets:Vec<Value>=[("root","task","promise"),("sync","call","sync"),("asynchronous","call","promise"),("fail","task","sync")].into_iter().map(|(name,kind,mode)|{
            if matches!(language,Language::Python) {
                let mut target=json!({"module":"business","attribute":name,"kind":kind,"worker":worker,"operation":format!("zero-code-{name}")});
                if kind=="call"{target["callee"]=worker.clone();} target
            } else {
                let mut target=json!({"file":"./business.cjs","export":[name],"kind":kind,"worker":worker,"operation":format!("zero-code-{name}"),"mode":mode,"capture":"omit"});
                if kind=="call"{target["to"]=worker.clone();}target
            }
        }).collect();
        let descriptor = if matches!(language, Language::Python) {
            json!({"version":1,"targets":targets,"shutdown_timeout":2.0,
            "collector":{"platform_url":platform.server.origin,"source_id":binding.source_id,"binding_id":binding.binding_id,"expected_scope":binding.scope_id,"expected_mocked":true,"spool_dir":dir.join("spool"),"request_timeout":0.5}})
        } else {
            json!({"version":1,"keyEnv":"AGF_COLLECTOR_KEY","targets":targets})
        };
        let descriptor_path = dir.join("startup.json");
        write_new(&descriptor_path, &serde_json::to_vec(&descriptor)?)?;
        Ok(Self {
            dir,
            entry: entry_path,
            descriptor: descriptor_path,
            language,
            source_bytes: source.as_bytes().to_vec(),
        })
    }
    async fn run(
        &self,
        owned: &Owned,
        platform: &Platform,
        binding: &Binding,
        key: &str,
        injected: bool,
    ) -> DomainResult<Value> {
        let binary = match self.language {
            Language::Python => "AGF_ZERO_CODE_PYTHON",
            Language::Node => "AGF_ZERO_CODE_NODE",
        };
        let mut command = subprocess::command(subprocess::executable(binary)?, owned, &self.dir)?;
        match self.language {
            Language::Python => {
                command.arg("-B");
                if injected {
                    command
                        .arg("-I")
                        .arg(self.dir.join("launch.py"))
                        .arg("--config")
                        .arg(&self.descriptor)
                        .arg("--script");
                }
                command.arg(&self.entry);
            }
            Language::Node => {
                if injected {
                    command.arg("--require").arg(owned.sdk.join("node/startup.cjs"));
                }
                command.arg(&self.entry);
            }
        }
        let counter = self.dir.join(if injected { "observed.count" } else { "baseline.count" });
        command.env("AGF_BUSINESS_COUNTER", &counter);
        if injected {
            collector_env(&mut command, self, platform, binding, key);
        }
        let value = subprocess::run(command, Some(key), true).await?;
        assert_eq!(value, json!({"ok":true,"syncIdentity":true,"asyncIdentity":true,"errorIdentity":true}));
        self.verify_source()?;
        assert_counter(&counter)?;
        Ok(value)
    }
    async fn drain(&self, owned: &Owned, platform: &Platform, binding: &Binding, key: &str) -> DomainResult<Value> {
        let mut command = match self.language {
            Language::Python => {
                let mut c = subprocess::command(subprocess::executable("AGF_ZERO_CODE_PYTHON")?, owned, &self.dir)?;
                c.args(["-I", "-B"]).arg(self.dir.join("launch.py")).arg("--config").arg(&self.descriptor).args([
                    "--drain-only",
                    "--drain-timeout",
                    "30",
                ]);
                c
            }
            Language::Node => {
                let mut c = subprocess::command(subprocess::executable("AGF_ZERO_CODE_NODE")?, owned, &self.dir)?;
                c.arg(owned.sdk.join("node/startup-drain.mjs")).args(["--drain-only", "20"]);
                c
            }
        };
        collector_env(&mut command, self, platform, binding, key);
        let value = subprocess::run(command, Some(key), false).await?;
        assert_eq!(value["pending"], 0);
        assert_eq!(value["quarantined"], 0);
        if matches!(self.language, Language::Node) {
            assert_eq!(value["businessCalls"], 0);
            assert_eq!(value["businessModulesLoaded"], false);
        }
        self.verify_source()?;
        assert_counter(&self.dir.join("observed.count"))?;
        Ok(value)
    }
    fn verify_source(&self) -> DomainResult<()> {
        let extension = if matches!(self.language, Language::Python) { "py" } else { "cjs" };
        assert_eq!(
            std::fs::read(self.dir.join(format!("business.{extension}"))).map_err(|_| fail("business source read"))?,
            self.source_bytes
        );
        let entry = if matches!(self.language, Language::Python) {
            include_bytes!("fixtures/entry.py").as_slice()
        } else {
            include_bytes!("fixtures/entry.cjs").as_slice()
        };
        assert_eq!(std::fs::read(&self.entry).map_err(|_| fail("business entry read"))?, entry);
        Ok(())
    }
}
fn collector_env(
    command: &mut tokio::process::Command,
    business: &Business,
    p: &Platform,
    binding: &Binding,
    key: &str,
) {
    command
        .env("AGF_COLLECTOR_KEY", key)
        .env("AGF_NODE_STARTUP_CONFIG", &business.descriptor)
        .env("AGF_PLATFORM_URL", &p.server.origin)
        .env("AGF_SOURCE_ID", binding.source_id.to_string())
        .env("AGF_BINDING_ID", binding.binding_id.to_string())
        .env("AGF_SCOPE_ID", binding.scope_id.to_string())
        .env("AGF_EXPECTED_MOCKED", "true")
        .env("AGF_SPOOL_DIR", business.dir.join("spool"));
}
fn assert_counter(path: &std::path::Path) -> DomainResult<()> {
    let text = std::fs::read_to_string(path).map_err(|_| fail("business counter"))?;
    let mut lines: Vec<_> = text.lines().collect();
    lines.sort_unstable();
    assert_eq!(lines, ["async", "fail", "root", "sync"], "each actual business function must run exactly once");
    Ok(())
}
async fn setup(p: &Platform) -> DomainResult<(Binding, Key)> {
    p.admin("PUT","/api/v1/alicloud/connections/alicloud-agentteams",Some(json!({"expected_version":0,"enabled":true,"mock":true,"settings":{"instance_id":format!("zero-code-{}",p.tenant),"account_id":"owned-zero-code-mock"}})),200).await?;
    p.admin(
        "POST",
        "/api/v1/alicloud/agentteams/sync",
        Some(json!({"request_id":Id::new(),"configuration_version":1,"confirm_live":false})),
        200,
    )
    .await?;
    let source = p
        .admin(
            "POST",
            "/api/v1/ingest/sources",
            Some(json!({"name":"startup owned webhook","protocol":"http-webhook"})),
            201,
        )
        .await?;
    let source: Id = serde_json::from_value(source["id"].clone())?;
    p.admin(
        "PUT",
        &format!("/api/v1/alicloud/agentteams/audit-sources/{source}"),
        Some(json!({"expected_version":0,"enabled":true})),
        200,
    )
    .await?;
    let binding = agf_api::agentteams_audit::binding::load(&p.state, p.tenant, source)
        .await?
        .ok_or_else(|| fail("binding absent"))?;
    assert!(binding.mocked && binding.members.contains_key("worker-demo"));
    Ok((binding, p.key(&["sources:write"]).await?))
}
pub(crate) async fn roundtrip(language: Language) -> DomainResult<()> {
    let owned = Owned::open().await?;
    let mut platform = Platform::open(&owned).await?;
    let result = AssertUnwindSafe(async {
        let (binding, key) = setup(&platform).await?;
        let business = Business::create(&owned, &platform, &binding, language)?;
        business.run(&owned, &platform, &binding, &key.token, false).await?;
        assert!(queue::snapshot(&platform, binding.source_id).await?["ledger"].as_array().unwrap().is_empty());
        platform.tap.discard_ack.store(true, Ordering::SeqCst);
        business.run(&owned, &platform, &binding, &key.token, true).await?;
        let queued = queue::inspect(&owned, &business.dir, language.name(), &key.token).await?;
        let committed = queue::snapshot(&platform, binding.source_id).await?;
        queue::verify(&committed, &binding, platform.tenant, &key.token, &queued);
        queue::isolated(&platform).await?;
        assert!(platform.tap.committed_responses.load(Ordering::SeqCst) > 0);
        platform.tap.discard_ack.store(false, Ordering::SeqCst);
        business.drain(&owned, &platform, &binding, &key.token).await?;
        assert!(
            queue::inspect(&owned, &business.dir, language.name(), &key.token).await?["rows"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            queue::snapshot(&platform, binding.source_id).await? == committed,
            "ACK loss and drain must never duplicate ledger/raw/Event/outbox"
        );
        let mut fresh = platform.restart(&owned).await?;
        let observed = fresh.admin("GET", "/api/v1/alicloud/agentteams/audit-events", None, 200).await?;
        assert_eq!(observed["items"].as_array().unwrap().len(), 4);
        assert!(
            queue::snapshot(&fresh, binding.source_id).await? == committed,
            "restart must retain exact ledger/raw/Event/outbox"
        );
        for row in observed["items"].as_array().unwrap() {
            assert_eq!(row["authorizationStatus"], "unknown");
            assert!(row["authorized"].is_null());
            assert_eq!(row["mocked"], true);
        }
        fresh.chain().await?;
        fresh.server.stop().await;
        platform.chain().await?;
        Ok(())
    })
    .catch_unwind()
    .await;
    platform.server.stop().await;
    let cleaned = owned.finish().await;
    match result {
        Ok(result) => {
            cleaned?;
            result
        }
        Err(panic) => {
            cleaned?;
            std::panic::resume_unwind(panic)
        }
    }
}
pub(crate) async fn revocation() -> DomainResult<()> {
    let owned = Owned::open().await?;
    let mut platform = Platform::open(&owned).await?;
    let result = AssertUnwindSafe(async {
        let (binding, key) = setup(&platform).await?;
        platform.revoke(&key).await?;
        for language in [Language::Python, Language::Node] {
            let business = Business::create(&owned, &platform, &binding, language)?;
            business.run(&owned, &platform, &binding, &key.token, true).await?;
            let queued = queue::inspect(&owned, &business.dir, language.name(), &key.token).await?;
            assert_eq!(queued["rows"].as_array().unwrap().len(), 4);
            assert!(queued["rows"].as_array().unwrap().iter().all(|row| row["state"] == "pending"));
        }
        let next = platform.key(&["sources:write"]).await?;
        platform
            .admin(
                "PUT",
                &format!("/api/v1/alicloud/agentteams/audit-sources/{}", binding.source_id),
                Some(json!({"expected_version":binding.version,"enabled":false})),
                200,
            )
            .await?;
        for language in [Language::Python, Language::Node] {
            let business = Business::create(&owned, &platform, &binding, language)?;
            business.run(&owned, &platform, &binding, &next.token, true).await?;
            let queued = queue::inspect(&owned, &business.dir, language.name(), &next.token).await?;
            assert_eq!(queued["rows"].as_array().unwrap().len(), 4);
            assert!(queued["rows"].as_array().unwrap().iter().any(|row| row["state"] == "quarantined"));
        }
        let snapshot = queue::snapshot(&platform, binding.source_id).await?;
        for name in ["ledger", "raw", "events"] {
            assert!(snapshot[name].as_array().unwrap().is_empty());
        }
        assert_eq!(snapshot["delivery"], 0);
        platform.chain().await?;
        Ok(())
    })
    .catch_unwind()
    .await;
    platform.server.stop().await;
    let cleaned = owned.finish().await;
    match result {
        Ok(result) => {
            cleaned?;
            result
        }
        Err(panic) => {
            cleaned?;
            std::panic::resume_unwind(panic)
        }
    }
}
