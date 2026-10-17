//! Vendor absence must be proved by the actual HTTP response and exact error code.
use super::{client, contract};
use agf_alicloud::openapi::ResourceObservation;
use agf_core::enums::AliCloudService;
use serde_json::json;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::query_param};

#[tokio::test]
async fn resource_observation_preserves_http_absence_without_weakening_normal_calls() {
    for action in ["GetTeam", "GetUser"] {
        let server = MockServer::start().await;
        Mock::given(query_param("Action", action))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "Code":"Resource.NotFound","Success":false,"RequestId":"provider-not-found",
                "Message":"PRIVATE PROVIDER MESSAGE"
            })))
            .expect(2)
            .mount(&server)
            .await;
        let operation = contract(AliCloudService::AgentTeams, action).unwrap();
        let client = client(AliCloudService::AgentTeams, &server.uri());
        let input = json!({"InstanceId":"instance-local","Name":"missing-resource"});
        match operation.observe_resource(&client, &input).await.unwrap() {
            ResourceObservation::Absent { http_status, provider_code, provider_request_id } => {
                assert_eq!(http_status, 404);
                assert_eq!(provider_code, "Resource.NotFound");
                assert_eq!(provider_request_id, "provider-not-found");
            }
            ResourceObservation::Present(_) => panic!("Exact vendor absence became present"),
        }
        assert!(operation.call(&client, &input).await.is_err());
    }
}

#[tokio::test]
async fn ambiguous_resource_errors_never_confirm_deletion() {
    let scenarios = [
        (403, json!({"Code":"Resource.NotFound","RequestId":"req"})),
        (404, json!({"Code":"Forbidden","RequestId":"req"})),
        (404, json!({"Code":"Resource.NotFound"})),
        (404, json!({"Code":"Resource.NotFound","RequestId":""})),
        (404, json!({"Code":"Resource.NotFound","RequestId":"bad\nrequest"})),
        (200, json!({"Code":"Resource.NotFound","RequestId":"req"})),
        (404, json!({"Message":"Resource.NotFound","RequestId":"req"})),
        (404, json!({"code":"Resource.NotFound","RequestId":"req"})),
        (404, json!({"Code":"Resource.NotFound","RequestId":"req","Success":true})),
        (404, json!({"Code":"Resource.NotFound","RequestId":"req","HttpStatusCode":200})),
    ];
    for (status, body) in scenarios {
        let server = MockServer::start().await;
        Mock::given(query_param("Action", "GetTeam"))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .expect(1)
            .mount(&server)
            .await;
        assert!(
            contract(AliCloudService::AgentTeams, "GetTeam")
                .unwrap()
                .observe_resource(
                    &client(AliCloudService::AgentTeams, &server.uri()),
                    &json!({"InstanceId":"instance-local","Name":"team"}),
                )
                .await
                .is_err()
        );
    }
    let server = MockServer::start().await;
    Mock::given(query_param("Action", "GetTeam"))
        .respond_with(ResponseTemplate::new(404).set_body_string("<html>Resource.NotFound</html>"))
        .expect(1)
        .mount(&server)
        .await;
    assert!(
        contract(AliCloudService::AgentTeams, "GetTeam")
            .unwrap()
            .observe_resource(
                &client(AliCloudService::AgentTeams, &server.uri()),
                &json!({"InstanceId":"instance-local","Name":"team"}),
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn only_exact_resource_reads_can_use_absence_observer_and_present_data_survives() {
    let server = MockServer::start().await;
    Mock::given(query_param("Action", "GetTeam"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "Code":"SUCCESS","Success":true,"Data":{"Name":"team","InstanceId":"instance-local"}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let client = client(AliCloudService::AgentTeams, &server.uri());
    let params = json!({"InstanceId":"instance-local","Name":"team"});
    let observation =
        contract(AliCloudService::AgentTeams, "GetTeam").unwrap().observe_resource(&client, &params).await.unwrap();
    match observation {
        ResourceObservation::Present(response) => assert_eq!(response.body["Data"]["Name"], "team"),
        ResourceObservation::Absent { .. } => panic!("A present resource became absent"),
    }
    for action in ["ListTeams", "CreateTeam", "UpdateTeam", "DeleteTeam"] {
        assert!(
            contract(AliCloudService::AgentTeams, action).unwrap().observe_resource(&client, &params).await.is_err()
        );
    }
}

#[test]
fn team_directory_is_read_only_and_delete_has_no_client_token() {
    for action in ["ListUsers", "GetUser"] {
        assert!(contract(AliCloudService::AgentTeams, action).unwrap().read_only);
    }
    let delete = contract(AliCloudService::AgentTeams, "DeleteTeam").unwrap();
    assert!(!delete.read_only);
    assert!(delete.validate(&json!({"InstanceId":"instance-local","Name":"team"})).is_ok());
    assert!(delete.validate(&json!({"InstanceId":"instance-local","Name":"team","ClientToken":"token"})).is_err());
    assert!(
        contract(AliCloudService::AgentTeams, "UpdateTeam")
            .unwrap()
            .validate(&json!({"InstanceId":"instance-local","Name":"team","AdminName":"user"}))
            .is_err()
    );
}

#[test]
fn structured_authorization_subcodes_remain_explicit_rejections() {
    use agf_alicloud::http::map_error_code;
    use agf_core::error::DomainError;
    for code in ["Forbidden.RAM", "NoPermission.Team", "UnauthorizedOperation.CreateTeam"] {
        assert!(matches!(map_error_code(code, "denied", Some("provider-request")), DomainError::Forbidden(_)));
    }
    for code in ["Unknown", "Forbiddenish", "Forbidden.", "SomeForbidden.RAM"] {
        assert!(matches!(
            map_error_code(code, "Forbidden.RAM is only message text", Some("provider-request")),
            DomainError::DependencyUnavailable { .. }
        ));
    }
}
