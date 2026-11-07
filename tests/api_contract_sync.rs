//! Focused rust-gvm-api contract regressions added by issue #119.

use gvm_mcp::mcp::tools::alerts::{AlertCondition, AlertEvent, AlertMethod};
use gvm_mcp::mcp::tools::credentials::CredentialType;
use gvm_mcp::mcp::tools::identity::{AuthenticationType, CreateUserParams};
use gvm_mcp::mcp::tools::tasks::UpdateTaskParams;
use schemars::schema_for;
use serde_json::{Value, json};

fn enum_values<T: schemars::JsonSchema>() -> Vec<Value> {
    serde_json::to_value(schema_for!(T)).unwrap()["enum"]
        .as_array()
        .expect("contract enum has an enum array")
        .clone()
}

#[test]
fn create_request_enums_match_the_closed_gateway_contract() {
    // These values feed mutating endpoints. Keeping their MCP schemas closed
    // prevents clients from constructing values rejected by the API contract.
    assert_eq!(
        enum_values::<AlertEvent>(),
        vec![
            json!("task_run_status_changed"),
            json!("updated_secinfo"),
            json!("new_secinfo"),
        ]
    );
    assert_eq!(
        enum_values::<AlertCondition>(),
        vec![
            json!("always"),
            json!("filter_count_at_least"),
            json!("filter_count_changed"),
            json!("severity_at_least"),
            json!("severity_changed"),
        ]
    );
    assert_eq!(
        enum_values::<AlertMethod>(),
        vec![
            json!("email"),
            json!("http_get"),
            json!("scp"),
            json!("send_email"),
            json!("smb"),
            json!("snmp"),
            json!("sourcefire_connector"),
            json!("start_task"),
            json!("syslog"),
            json!("tippingpoint"),
            json!("verinice_ce"),
            json!("verinice_net"),
            json!("alemba"),
        ]
    );
    assert_eq!(
        enum_values::<CredentialType>(),
        vec![
            json!("cc"),
            json!("pw"),
            json!("snmp"),
            json!("snmpv3"),
            json!("up"),
            json!("usk"),
            json!("cs_cc"),
            json!("cs_pw"),
            json!("cs_pgp"),
            json!("cs_smime"),
            json!("cs_snmp"),
            json!("cs_up"),
            json!("cs_usk"),
        ]
    );
    assert_eq!(
        enum_values::<AuthenticationType>(),
        vec![
            json!("file"),
            json!("ldap_connect"),
            json!("radius_connect"),
        ]
    );
}

#[test]
fn user_password_and_authentication_type_remain_optional() {
    // rust-gvm-api #640 is a generated-schema bug: omission is valid at
    // runtime, so MCP must not accidentally make these fields required.
    let params: CreateUserParams = serde_json::from_value(json!({"name": "auditor"})).unwrap();
    assert!(params.password.is_none());
    assert!(params.authentication_type.is_none());

    let error = serde_json::from_value::<CreateUserParams>(
        json!({"name": "auditor", "authentication_type": null}),
    )
    .unwrap_err();
    assert!(error.to_string().contains("must not be null"));
}

#[test]
fn observer_updates_distinguish_omission_empty_and_explicit_null() {
    // Omission preserves access, [] clears it, and a non-empty array replaces
    // it. Explicit null must fail instead of silently behaving like omission.
    let omitted: UpdateTaskParams = serde_json::from_value(json!({"id": "task-1"})).unwrap();
    assert!(omitted.observers.is_none());

    let empty: UpdateTaskParams =
        serde_json::from_value(json!({"id": "task-1", "observers": []})).unwrap();
    assert_eq!(empty.observers, Some(vec![]));

    let replacement: UpdateTaskParams =
        serde_json::from_value(json!({"id": "task-1", "observers": ["alice"]})).unwrap();
    assert_eq!(replacement.observers, Some(vec!["alice".to_string()]));

    let error =
        serde_json::from_value::<UpdateTaskParams>(json!({"id": "task-1", "observers": null}))
            .unwrap_err();
    assert!(error.to_string().contains("must not be null"));
}
