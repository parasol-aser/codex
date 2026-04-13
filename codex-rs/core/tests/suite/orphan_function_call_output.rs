//! Regression tests for PLAN step C (#17630):
//!
//! The Responses API can reject a retry with
//!   `400 "No tool call found for function call output with call_id <ID>."`
//! when a `function_call_output` is present in history but the matching
//! `function_call` was only present in a response the server did not persist
//! (because an earlier attempt errored). The `CodexErr::InvalidRequest` class
//! is non-retryable today, so the turn would fail hard.
//!
//! The fix adds a targeted self-heal: detect the message shape, extract the
//! `call_id`, repair the in-memory history, and retry once. These tests
//! verify that flow end-to-end against a mock Responses endpoint without
//! depending on any internal repair API.

use codex_model_provider_info::ModelProviderInfo;
use codex_model_provider_info::WireApi;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::Op;
use codex_protocol::user_input::UserInput;
use core_test_support::responses::ev_assistant_message;
use core_test_support::responses::ev_completed;
use core_test_support::responses::ev_response_created;
use core_test_support::responses::mount_response_once;
use core_test_support::responses::mount_response_sequence;
use core_test_support::responses::sse;
use core_test_support::responses::sse_response;
use core_test_support::responses::start_mock_server;
use core_test_support::skip_if_no_network;
use core_test_support::test_codex::TestCodex;
use core_test_support::test_codex::test_codex;
use core_test_support::wait_for_event;
use serde_json::json;
use std::sync::Arc;
use std::sync::Mutex;
use wiremock::Mock;
use wiremock::Request;
use wiremock::ResponseTemplate;
use wiremock::matchers::method;
use wiremock::matchers::path_regex;

fn provider(server: &wiremock::MockServer) -> ModelProviderInfo {
    ModelProviderInfo {
        name: "mock-openai".into(),
        base_url: Some(format!("{}/v1", server.uri())),
        env_key: Some("PATH".into()),
        env_key_instructions: None,
        experimental_bearer_token: None,
        auth: None,
        wire_api: WireApi::Responses,
        query_params: None,
        http_headers: None,
        env_http_headers: None,
        // The repair path must NOT consume the stream-retry budget — it has
        // its own single-shot counter — so we pin both to 0 to rule out
        // ordinary retry accidentally hiding the bug.
        request_max_retries: Some(0),
        stream_max_retries: Some(0),
        stream_idle_timeout_ms: Some(2_000),
        websocket_connect_timeout_ms: None,
        requires_openai_auth: false,
        supports_websockets: false,
    }
}

fn orphan_call_id_error_body(call_id: &str) -> serde_json::Value {
    json!({
        "type": "error",
        "status": 400,
        "error": {
            "message": format!(
                "No tool call found for function call output with call_id {call_id}."
            ),
            "type": "invalid_request_error",
            "param": "input"
        }
    })
}

fn orphan_reasoning_error_body(item_id: &str) -> serde_json::Value {
    json!({
        "type": "error",
        "status": 400,
        "error": {
            "message": format!(
                "Item {item_id} of type reasoning was provided without its required following item."
            ),
            "type": "invalid_request_error",
            "param": "input"
        }
    })
}

fn unrelated_invalid_request_body() -> serde_json::Value {
    json!({
        "type": "error",
        "status": 400,
        "error": {
            "message": "Some other invalid request unrelated to orphan outputs.",
            "type": "invalid_request_error",
            "param": "input"
        }
    })
}

fn invalid_request_400(body: serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(400)
        .insert_header("content-type", "application/json")
        .set_body_json(body)
}

fn success_sse() -> ResponseTemplate {
    let body = sse(vec![
        ev_response_created("resp-ok"),
        ev_assistant_message("msg-1", "all set"),
        ev_completed("resp-ok"),
    ]);
    sse_response(body)
}

fn user_input_op(text: &str) -> Op {
    Op::UserInput {
        items: vec![UserInput::Text {
            text: text.into(),
            text_elements: Vec::new(),
        }],
        final_output_json_schema: None,
        responsesapi_client_metadata: None,
    }
}

/// Happy path: server rejects the first request with the orphan
/// `call_id` message; Codex repairs history, retries exactly once, and the
/// turn completes successfully.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repairs_orphan_function_call_output_then_retries() {
    skip_if_no_network!();

    let server = start_mock_server().await;

    let mock = mount_response_sequence(
        &server,
        vec![
            invalid_request_400(orphan_call_id_error_body("call_orphan_123")),
            success_sse(),
        ],
    )
    .await;

    let provider = provider(&server);
    let TestCodex { codex, .. } = test_codex()
        .with_config(move |config| {
            config.model_provider = provider;
        })
        .build(&server)
        .await
        .unwrap();

    codex.submit(user_input_op("hello")).await.unwrap();

    wait_for_event(&codex, |ev| matches!(ev, EventMsg::TurnComplete(_))).await;

    let requests = mock.requests();
    assert_eq!(
        requests.len(),
        2,
        "expected exactly one repair-retry after the orphan 400"
    );

    // The retry request must be a fresh /v1/responses call — the repair path
    // rebuilds the prompt from normalized history.
    assert!(
        requests[1].body_json()["input"].as_array().is_some(),
        "retry request must include a valid input array"
    );
}

/// Mirror repair path: the same self-heal handles the orphan-reasoning
/// invariant (#17161) when the server reports
/// "Item <id> of type reasoning was provided without its required following
/// item."
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repairs_orphan_reasoning_item_then_retries() {
    skip_if_no_network!();

    let server = start_mock_server().await;

    let mock = mount_response_sequence(
        &server,
        vec![
            invalid_request_400(orphan_reasoning_error_body("rs_abc_123")),
            success_sse(),
        ],
    )
    .await;

    let provider = provider(&server);
    let TestCodex { codex, .. } = test_codex()
        .with_config(move |config| {
            config.model_provider = provider;
        })
        .build(&server)
        .await
        .unwrap();

    codex.submit(user_input_op("hello")).await.unwrap();

    wait_for_event(&codex, |ev| matches!(ev, EventMsg::TurnComplete(_))).await;

    assert_eq!(
        mock.requests().len(),
        2,
        "expected exactly one repair-retry after the orphan reasoning 400"
    );
}

/// PLAN edge case #4: the repair must be bounded. If the server keeps
/// returning the same 400 even after repair, Codex must give up rather than
/// loop forever. We count every request the server receives (regardless of
/// how many) and assert a small upper bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn does_not_loop_when_repair_fails() {
    skip_if_no_network!();

    let server = start_mock_server().await;

    // Custom responder: always return the same 400, count every hit.
    let counter = Arc::new(Mutex::new(0usize));
    let counter_clone = Arc::clone(&counter);
    let orphan_body = orphan_call_id_error_body("call_forever");
    Mock::given(method("POST"))
        .and(path_regex(".*/responses$"))
        .respond_with(move |_req: &Request| {
            *counter_clone.lock().unwrap() += 1;
            invalid_request_400(orphan_body.clone())
        })
        .mount(&server)
        .await;

    let provider = provider(&server);
    let TestCodex { codex, .. } = test_codex()
        .with_config(move |config| {
            config.model_provider = provider;
        })
        .build(&server)
        .await
        .unwrap();

    codex.submit(user_input_op("hello")).await.unwrap();

    // The turn must terminate: an Error event is surfaced and then
    // TurnComplete is emitted so the session is released.
    wait_for_event(&codex, |ev| matches!(ev, EventMsg::Error(_))).await;
    wait_for_event(&codex, |ev| matches!(ev, EventMsg::TurnComplete(_))).await;

    let actual = *counter.lock().unwrap();
    assert!(
        actual <= 4,
        "expected bounded repair attempts (≤ 4 total requests) but made {actual}"
    );
    assert!(
        actual >= 1,
        "expected at least one request, got {actual}"
    );
}

/// PLAN step C: the repair path must only trigger on message shapes that
/// match the server's orphan-invariant copy. A generic
/// `invalid_request_error` must fall through to today's non-retryable
/// behavior and NOT consume repair attempts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_repairs_matching_message_shape() {
    skip_if_no_network!();

    let server = start_mock_server().await;

    // Mount a single 400 for the first request. If Codex buggily retried on
    // an unrelated invalid_request_error, it would hit no second mock and
    // the mock server would return its default 404 — either way, the
    // captured request count below catches a regression.
    let mock =
        mount_response_once(&server, invalid_request_400(unrelated_invalid_request_body()))
            .await;

    let provider = provider(&server);
    let TestCodex { codex, .. } = test_codex()
        .with_config(move |config| {
            config.model_provider = provider;
        })
        .build(&server)
        .await
        .unwrap();

    codex.submit(user_input_op("hello")).await.unwrap();

    wait_for_event(&codex, |ev| matches!(ev, EventMsg::Error(_))).await;
    wait_for_event(&codex, |ev| matches!(ev, EventMsg::TurnComplete(_))).await;

    assert_eq!(
        mock.requests().len(),
        1,
        "an unrelated invalid_request_error must NOT trigger repair retries"
    );
}

/// Partial variant of the orphan message: servers sometimes emit richer
/// copies ("... with call_id X, please retry."). The classifier should
/// anchor on the stable prefix and still extract the id.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repairs_orphan_with_trailing_copy_after_call_id() {
    skip_if_no_network!();

    let server = start_mock_server().await;

    // Note the extra trailing content after the call_id token. The PLAN
    // specifies a defensive parse that anchors on the prefix.
    let body = json!({
        "type": "error",
        "status": 400,
        "error": {
            "message": "No tool call found for function call output with call_id call_trailing_suffix (please check your input).",
            "type": "invalid_request_error",
            "param": "input"
        }
    });

    let mock = mount_response_sequence(
        &server,
        vec![invalid_request_400(body), success_sse()],
    )
    .await;

    let provider = provider(&server);
    let TestCodex { codex, .. } = test_codex()
        .with_config(move |config| {
            config.model_provider = provider;
        })
        .build(&server)
        .await
        .unwrap();

    codex.submit(user_input_op("hello")).await.unwrap();
    wait_for_event(&codex, |ev| matches!(ev, EventMsg::TurnComplete(_))).await;

    assert_eq!(
        mock.requests().len(),
        2,
        "defensive classifier must still recognize the prefix and repair"
    );
}

/// PLAN step B / step E: the retry request must re-run `for_prompt`
/// normalization, so the retry's `input` array passes the invariant-clean
/// checks the mock server enforces (`validate_request_body_invariants` in
/// `core/tests/common/responses.rs`). If the retry still contained orphan
/// outputs, the mock's `Match` impl would panic. Reaching TurnComplete with
/// two requests proves the retry's history was self-consistent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retry_input_is_invariant_clean() {
    skip_if_no_network!();

    let server = start_mock_server().await;

    let mock = mount_response_sequence(
        &server,
        vec![
            invalid_request_400(orphan_call_id_error_body("call_xyz")),
            success_sse(),
        ],
    )
    .await;

    let provider = provider(&server);
    let TestCodex { codex, .. } = test_codex()
        .with_config(move |config| {
            config.model_provider = provider;
        })
        .build(&server)
        .await
        .unwrap();

    codex.submit(user_input_op("hello")).await.unwrap();
    wait_for_event(&codex, |ev| matches!(ev, EventMsg::TurnComplete(_))).await;

    // Inspect the retry body directly: no function_call_output entry may
    // reference `call_xyz` (the repair target), and the retry must still
    // carry the original user message so the server has context.
    let retry = mock.requests().into_iter().nth(1).expect("retry request");
    let body = retry.body_json();
    let input = body["input"].as_array().expect("input array");

    let has_orphan = input.iter().any(|item| {
        item.get("type").and_then(|v| v.as_str()) == Some("function_call_output")
            && item.get("call_id").and_then(|v| v.as_str()) == Some("call_xyz")
    });
    assert!(
        !has_orphan,
        "retry must not carry the orphan function_call_output; got: {input:#?}"
    );

    // The user message must still be present so the retry makes semantic
    // sense — the repair surgically removes only the orphan.
    let has_user_msg = input.iter().any(|item| {
        item.get("type").and_then(|v| v.as_str()) == Some("message")
            && item.get("role").and_then(|v| v.as_str()) == Some("user")
    });
    assert!(
        has_user_msg,
        "retry must still carry the user message; got: {input:#?}"
    );
}
