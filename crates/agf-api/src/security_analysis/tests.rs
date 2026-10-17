use super::*;
use serde_json::json;

fn snapshot() -> Snapshot {
    let mut snapshot = snapshot::fixture(TenantId::default_tenant());
    snapshot.facts.push(EvidenceFact {
        reference: "event:known".into(),
        kind: "event".into(),
        observed_at: Some(Timestamp::now()),
        content_hash: Some("actual-hash".into()),
        metadata: json!({}),
    });
    snapshot
}

fn assessment() -> Assessment {
    Assessment {
        verdict: Verdict::Suspicious,
        confidence: 0.7,
        summary: "Review known evidence".into(),
        evidence_refs: vec!["event:known".into()],
        observations: vec![Observation {
            explanation: "This is an observation".into(),
            evidence_refs: vec!["event:known".into()],
        }],
        timeline: vec![TimelineExplanation {
            evidence_ref: "event:known".into(),
            explanation: "Observed event".into(),
        }],
        hypotheses: Vec::new(),
    }
}

#[test]
fn prompt_example_is_valid_json_grounded_in_the_current_snapshot() {
    for snapshot in [snapshot(), snapshot::fixture(TenantId::default_tenant())] {
        let prompt = system_prompt(&snapshot);
        let raw = prompt.strip_prefix(SYSTEM_PROMPT).unwrap();
        let (example, used) = parse_assessment(&snapshot, raw, false, FinishReason::Stop).unwrap();
        assert!(used);
        let expected: Vec<_> = snapshot.facts.first().map(|fact| fact.reference.clone()).into_iter().collect();
        assert_eq!(example.evidence_refs, expected);
    }
}

#[test]
fn unknown_references_times_and_causal_claim_fields_are_rejected() {
    let snapshot = snapshot();
    assert!(validate(&snapshot, &assessment()).is_ok());
    let mut wrong = assessment();
    wrong.evidence_refs = vec!["other-tenant:event".into()];
    assert!(validate(&snapshot, &wrong).is_err());
    let mut wrong = assessment();
    wrong.timeline[0].evidence_ref = "event:invented".into();
    assert!(validate(&snapshot, &wrong).is_err());
    let mut wrong = assessment();
    wrong.confidence = f32::NAN;
    assert!(validate(&snapshot, &wrong).is_err());
    let mut payload = serde_json::to_value(assessment()).unwrap();
    payload["timeline"][0]["at"] = json!("invented timestamp");
    assert!(serde_json::from_value::<Assessment>(payload).is_err());
    let mut payload = serde_json::to_value(assessment()).unwrap();
    payload["causal_relationships"] = json!([{"proven":true}]);
    assert!(serde_json::from_value::<Assessment>(payload).is_err());
    let mut payload = serde_json::to_value(assessment()).unwrap();
    payload["verdict"] = json!("confirmed-causal");
    assert!(serde_json::from_value::<Assessment>(payload).is_err());
    let mut payload = serde_json::to_value(assessment()).unwrap();
    payload["observations"][0]["commands"] = json!(["not-an-analysis-field"]);
    assert!(serde_json::from_value::<Assessment>(payload).is_err());
    let mut wrong = assessment();
    wrong.confidence = 1.1;
    assert!(validate(&snapshot, &wrong).is_err());
    let mut untimed = snapshot.clone();
    untimed.facts[0].observed_at = None;
    assert!(validate(&untimed, &assessment()).is_err());
}

#[test]
fn mock_assessment_is_explicit_unknown_and_does_not_invent_evidence() {
    let snapshot = snapshot();
    let demo = demonstration(&snapshot);
    assert_eq!(demo.verdict, Verdict::Unknown);
    assert_eq!(demo.confidence, 0.0);
    assert!(demo.summary.contains("Mock demonstration"));
    assert!(validate(&snapshot, &demo).is_ok());
    let empty = snapshot::fixture(TenantId::default_tenant());
    assert!(validate(&empty, &demonstration(&empty)).is_ok());
}

#[test]
fn mock_fallback_is_honest_and_live_invalid_output_fails() {
    let snapshot = snapshot();
    let (fixture, used) = parse_assessment(&snapshot, "arbitrary mock DSL", true, FinishReason::Stop).unwrap();
    assert!(!used);
    assert_eq!(fixture.verdict, Verdict::Unknown);
    assert!(parse_assessment(&snapshot, "arbitrary mock DSL", false, FinishReason::Stop).is_err());
    let (parsed, used) =
        parse_assessment(&snapshot, &serde_json::to_string(&assessment()).unwrap(), true, FinishReason::Stop).unwrap();
    assert!(used);
    assert_eq!(parsed.verdict, Verdict::Suspicious);
    let mut invalid = assessment();
    invalid.evidence_refs = vec!["invented".into()];
    let raw = serde_json::to_string(&invalid).unwrap();
    assert!(!parse_assessment(&snapshot, &raw, true, FinishReason::Stop).unwrap().1);
    assert!(parse_assessment(&snapshot, &raw, false, FinishReason::Stop).is_err());
}

#[test]
fn context_bounds_keep_the_actual_object_class_and_count_omitted_facts() {
    let mut snapshot = snapshot::fixture(TenantId::default_tenant());
    snapshot.data_class = DataClass::Confidential;
    snapshot.facts.push(EvidenceFact {
        reference: format!("alert:{}", snapshot.object_id),
        kind: "alert".into(),
        observed_at: None,
        content_hash: None,
        metadata: json!({"id":snapshot.object_id}),
    });
    for n in 0..16 {
        snapshot.facts.push(EvidenceFact {
            reference: format!("event:{n}"),
            kind: "event".into(),
            observed_at: None,
            content_hash: None,
            metadata: json!({"metadata":"x".repeat(200)}),
        });
    }
    let input = bound_snapshot(&mut snapshot, 2048).unwrap();
    assert!(input.len() + system_prompt(&snapshot).len() + 128 + OUTPUT_TOKENS as usize <= 2048);
    assert!(snapshot.truncated);
    assert!(snapshot.omitted_facts > 0);
    assert_eq!(snapshot.facts.len() + snapshot.omitted_facts, 17);
    assert_eq!(snapshot.facts[0].reference, format!("alert:{}", snapshot.object_id));
    assert_eq!(snapshot.data_class, DataClass::Confidential);
    assert!(bound_snapshot(&mut snapshot, 256).is_err());
}

#[test]
fn context_bound_counts_the_actual_reference_in_the_prompt_example() {
    let mut snapshot = snapshot();
    let root = format!("alert:{}", snapshot.object_id);
    snapshot.facts[0].reference = root.clone();
    let original_class = snapshot.data_class;
    let input = bound_snapshot(&mut snapshot, 2048).unwrap();
    let exact_budget = input.len() + system_prompt(&snapshot).len() + 128 + OUTPUT_TOKENS as usize;
    assert!(bound_snapshot(&mut snapshot, exact_budget as u32).is_ok());
    assert!(bound_snapshot(&mut snapshot, exact_budget as u32 - 1).is_err());
    assert_eq!(snapshot.facts[0].reference, root);
    assert_eq!(snapshot.data_class, original_class);
}

#[test]
fn incomplete_outputs_are_rejected_even_when_the_json_is_valid() {
    let snapshot = snapshot();
    let raw = serde_json::to_string(&assessment()).unwrap();
    for reason in [FinishReason::Length, FinishReason::ContentFilter, FinishReason::ToolCalls, FinishReason::Other] {
        assert!(parse_assessment(&snapshot, &raw, false, reason).is_err());
        let (demo, used) = parse_assessment(&snapshot, &raw, true, reason).unwrap();
        assert!(!used);
        assert_eq!(demo.verdict, Verdict::Unknown);
    }
}

#[test]
fn model_markdown_is_rendered_as_literal_text() {
    let snapshot = snapshot();
    let mut assessment = assessment();
    let injected = "[Click](https://untrusted.invalid) ![pixel](https://untrusted.invalid/p) <script>bad()</script> `code` **claim**";
    assessment.summary = injected.into();
    assessment.observations[0].explanation = injected.into();
    let analysis = Analysis {
        id: Id::new(),
        tenant_id: snapshot.tenant_id,
        purpose: snapshot.purpose,
        object_id: snapshot.object_id,
        snapshot_sha256: "proof".into(),
        snapshot,
        assessment,
        model: injected.into(),
        endpoint_id: Id::new(),
        mocked: false,
        cached: false,
        model_response_used: true,
        context_budget_tokens: 2048,
        usage_record_id: Id::new(),
        prompt_tokens: 24,
        completion_tokens: 12,
        cost_micro_cny: 48,
        created_at: Timestamp::now(),
    };
    let rendered = markdown(&analysis);
    assert!(!rendered.contains("[Click]("));
    assert!(!rendered.contains("![pixel]("));
    assert!(!rendered.contains("<script>"));
    assert!(!rendered.contains("`code`"));
    assert!(rendered.contains("&#91;Click&#93;"));
    assert!(rendered.contains("cannot independently validate attacks"));
    assert!(rendered.contains("48 micro CNY"));
}

fn assessment_schema(snapshot: &Snapshot) -> serde_json::Value {
    let ResponseFormat::JsonSchema { schema, strict, .. } = assessment_response_format(snapshot) else {
        panic!("Expected a strict JSON Schema response format");
    };
    assert!(strict);
    schema
}

#[test]
fn assessment_schema_closes_nested_shapes_and_uses_actual_timed_references() {
    let mut snapshot = snapshot();
    snapshot.facts.push(EvidenceFact {
        reference: "asset:untimed".into(),
        kind: "asset".into(),
        observed_at: None,
        content_hash: None,
        metadata: json!({}),
    });
    let schema = assessment_schema(&snapshot);
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["properties"].as_object().unwrap().len(), 7);
    assert_eq!(schema["required"].as_array().unwrap().len(), 7);
    let properties = &schema["properties"];
    assert_eq!(properties["evidence_refs"]["items"]["enum"], json!(["event:known", "asset:untimed"]));
    assert_eq!(properties["evidence_refs"]["minItems"], 1);
    assert_eq!(properties["evidence_refs"]["maxItems"], 8);
    for (key, fields, limit) in [
        ("observations", json!(["explanation", "evidence_refs"]), 4),
        ("timeline", json!(["evidence_ref", "explanation"]), 4),
        ("hypotheses", json!(["from_ref", "to_ref", "explanation"]), 2),
    ] {
        let item = &properties[key]["items"];
        assert_eq!(properties[key]["maxItems"], limit);
        assert_eq!(item["type"], "object");
        assert_eq!(item["additionalProperties"], false);
        assert_eq!(item["required"], fields);
        assert_eq!(item["properties"].as_object().unwrap().len(), fields.as_array().unwrap().len());
        assert_eq!(item["properties"]["explanation"]["maxLength"], 1024);
    }
    assert_eq!(properties["timeline"]["items"]["properties"]["evidence_ref"]["enum"], json!(["event:known"]));
    assert_eq!(
        properties["hypotheses"]["items"]["properties"]["from_ref"]["enum"],
        properties["evidence_refs"]["items"]["enum"]
    );
    assert_eq!(properties["summary"]["maxLength"], 4096);
    assert!(SYSTEM_PROMPT.contains("observations{explanation,evidence_refs}"));
    assert!(SYSTEM_PROMPT.contains("timeline{evidence_ref,explanation}"));
    assert!(SYSTEM_PROMPT.contains("hypotheses{from_ref,to_ref,explanation}"));
}

#[test]
fn empty_or_untimed_snapshot_schema_cannot_request_invented_items() {
    let empty = snapshot::fixture(TenantId::default_tenant());
    let schema = assessment_schema(&empty);
    let properties = &schema["properties"];
    assert_eq!(properties["verdict"]["enum"], json!(["unknown"]));
    assert_eq!(properties["confidence"]["enum"], json!([0.0]));
    for key in ["evidence_refs", "observations", "timeline", "hypotheses"] {
        assert_eq!(properties[key]["maxItems"], 0);
    }
    let mut untimed = snapshot();
    untimed.facts[0].observed_at = None;
    let schema = assessment_schema(&untimed);
    assert_eq!(schema["properties"]["timeline"]["maxItems"], 0);
    assert_eq!(schema["properties"]["hypotheses"]["maxItems"], 0);
    let mut invalid = demonstration(&empty);
    invalid.confidence = 0.1;
    assert!(validate(&empty, &invalid).is_err());
    invalid.confidence = 0.0;
    invalid.verdict = Verdict::Suspicious;
    assert!(validate(&empty, &invalid).is_err());
}

#[test]
fn grammar_references_are_derived_only_after_snapshot_context_bounding() {
    let mut snapshot = snapshot();
    snapshot.facts[0].reference = format!("alert:{}", snapshot.object_id);
    let omitted = "event:omitted";
    snapshot.facts.push(EvidenceFact {
        reference: omitted.into(),
        kind: "event".into(),
        observed_at: Some(Timestamp::now()),
        content_hash: None,
        metadata: json!({"metadata":"x".repeat(2000)}),
    });
    let input = bound_snapshot(&mut snapshot, 2048).unwrap();
    assert!(input.len() + system_prompt(&snapshot).len() + 128 + OUTPUT_TOKENS as usize <= 2048);
    assert_eq!(snapshot.omitted_facts, 1);
    let schema = assessment_schema(&snapshot);
    let refs = schema["properties"]["evidence_refs"]["items"]["enum"].as_array().unwrap();
    assert_eq!(refs, &vec![json!(snapshot.facts[0].reference)]);
    assert!(!refs.contains(&json!(omitted)));
    assert_eq!(schema["properties"]["hypotheses"]["maxItems"], 0);
}

#[test]
fn assessment_wire_uses_the_existing_nested_openai_json_schema_protocol() {
    let snapshot = snapshot();
    let mut request = ChatRequest::simple("model", "metadata");
    request.response_format = Some(assessment_response_format(&snapshot));
    let body = agf_aigw::convert::to_openai_body(&request, false);
    assert_eq!(body["response_format"]["type"], "json_schema");
    assert_eq!(body["response_format"]["json_schema"]["name"], "agf_security_assessment");
    assert_eq!(body["response_format"]["json_schema"]["strict"], true);
    assert_eq!(body["response_format"]["json_schema"]["schema"], assessment_schema(&snapshot));
    assert!(body["response_format"].get("schema").is_none());
}

#[test]
fn actual_diagnostic_nested_shape_failures_remain_strictly_rejected() {
    let snapshot = snapshot();
    for (key, value) in [
        ("observations", json!(["untyped explanation"])),
        ("timeline", json!([{"time":"invented","event":"untyped","source":"event:known"}])),
        ("hypotheses", json!([{"claim":"untyped","references":["event:known"]}])),
    ] {
        let mut payload = serde_json::to_value(assessment()).unwrap();
        payload[key] = value;
        assert!(serde_json::from_value::<Assessment>(payload.clone()).is_err());
        assert!(parse_assessment(&snapshot, &payload.to_string(), false, FinishReason::Stop).is_err());
    }
    let mut invalid = assessment();
    invalid.hypotheses.push(Hypothesis {
        from_ref: "event:known".into(),
        to_ref: "event:known".into(),
        explanation: "Unproven relationship".into(),
    });
    assert!(validate(&snapshot, &invalid).is_err());
    let mut invalid = assessment();
    invalid.summary = "é".repeat(2049);
    assert!(validate(&snapshot, &invalid).is_err());
    invalid.summary = "  ".into();
    assert!(validate(&snapshot, &invalid).is_err());
}
