//! Verifies that the agent retries when the SSE stream terminates before
//! delivering a `response.completed` event.

use codex_model_provider_info::ModelProviderInfo;
use codex_model_provider_info::WireApi;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::Op;
use codex_protocol::user_input::UserInput;
use codex_utils_cargo_bin::find_resource;
use core_test_support::load_sse_fixture;
use core_test_support::responses;
use core_test_support::responses::ev_assistant_message;
use core_test_support::responses::ev_completed;
use core_test_support::responses::ev_function_call;
use core_test_support::responses::ev_response_created;
use core_test_support::responses::sse;
use core_test_support::skip_if_no_network;
use core_test_support::streaming_sse::StreamingSseChunk;
use core_test_support::streaming_sse::start_streaming_sse_server;
use core_test_support::test_codex::TestCodex;
use core_test_support::test_codex::test_codex;
use core_test_support::wait_for_event;

fn sse_incomplete() -> String {
    let fixture = find_resource!("tests/fixtures/incomplete_sse.json")
        .unwrap_or_else(|err| panic!("failed to resolve incomplete_sse fixture: {err}"));
    load_sse_fixture(fixture)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retries_on_early_close() {
    skip_if_no_network!();

    let incomplete_sse = sse_incomplete();
    let completed_sse = responses::sse_completed("resp_ok");

    let (server, _) = start_streaming_sse_server(vec![
        vec![StreamingSseChunk {
            gate: None,
            body: incomplete_sse,
        }],
        vec![StreamingSseChunk {
            gate: None,
            body: completed_sse,
        }],
    ])
    .await;

    // Configure retry behavior explicitly to avoid mutating process-wide
    // environment variables.

    let model_provider = ModelProviderInfo {
        name: "openai".into(),
        base_url: Some(format!("{}/v1", server.uri())),
        // Environment variable that should exist in the test environment.
        // ModelClient will return an error if the environment variable for the
        // provider is not set.
        env_key: Some("PATH".into()),
        env_key_instructions: None,
        experimental_bearer_token: None,
        auth: None,
        wire_api: WireApi::Responses,
        query_params: None,
        http_headers: None,
        env_http_headers: None,
        // exercise retry path: first attempt yields incomplete stream, so allow 1 retry
        request_max_retries: Some(0),
        stream_max_retries: Some(1),
        stream_idle_timeout_ms: Some(2000),
        websocket_connect_timeout_ms: None,
        requires_openai_auth: false,
        supports_websockets: false,
    };

    let TestCodex { codex, .. } = test_codex()
        .with_config(move |config| {
            config.model_provider = model_provider;
        })
        .build_with_streaming_server(&server)
        .await
        .unwrap();

    codex
        .submit(Op::UserInput {
            items: vec![UserInput::Text {
                text: "hello".into(),
                text_elements: Vec::new(),
            }],
            final_output_json_schema: None,
            responsesapi_client_metadata: None,
        })
        .await
        .unwrap();

    // Wait until TurnComplete (should succeed after retry).
    wait_for_event(&codex, |event| matches!(event, EventMsg::TurnComplete(_))).await;

    let requests = server.requests().await;
    assert_eq!(
        requests.len(),
        2,
        "expected retry after incomplete SSE stream"
    );

    server.shutdown().await;
}

/// Regression test for PLAN step A / step B (#17630):
///
/// If the SSE stream emits a `function_call` item whose tool future resolves,
/// but the stream closes before `response.completed`, the turn-level cleanup
/// trailer in `try_run_sampling_request` must still run (via the `break
/// Err(err)` conversion) so `drain_in_flight` records the
/// `FunctionCallOutput`. The retry request must then rebuild its prompt from
/// *fresh* history (step B) so the output is visible in the next attempt —
/// never dropped on the floor (#16255 mirror).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retries_include_function_call_output_after_early_close() {
    skip_if_no_network!();

    // First SSE: emits a function_call but closes before response.completed.
    let first_response = sse(vec![
        ev_response_created("resp-1"),
        ev_function_call("call-early-close", "shell_command", "{\"command\":\"echo hi\"}"),
        // NOTE: deliberately no ev_completed — the stream is incomplete.
    ]);
    let second_response = sse(vec![
        ev_response_created("resp-2"),
        ev_assistant_message("msg-1", "done"),
        ev_completed("resp-2"),
    ]);

    let (server, _) = start_streaming_sse_server(vec![
        vec![StreamingSseChunk {
            gate: None,
            body: first_response,
        }],
        vec![StreamingSseChunk {
            gate: None,
            body: second_response,
        }],
    ])
    .await;

    let model_provider = ModelProviderInfo {
        name: "openai".into(),
        base_url: Some(format!("{}/v1", server.uri())),
        env_key: Some("PATH".into()),
        env_key_instructions: None,
        experimental_bearer_token: None,
        auth: None,
        wire_api: WireApi::Responses,
        query_params: None,
        http_headers: None,
        env_http_headers: None,
        request_max_retries: Some(0),
        stream_max_retries: Some(1),
        stream_idle_timeout_ms: Some(2000),
        websocket_connect_timeout_ms: None,
        requires_openai_auth: false,
        supports_websockets: false,
    };

    let TestCodex { codex, .. } = test_codex()
        .with_config(move |config| {
            config.model_provider = model_provider;
        })
        .build_with_streaming_server(&server)
        .await
        .unwrap();

    codex
        .submit(Op::UserInput {
            items: vec![UserInput::Text {
                text: "please run a shell command".into(),
                text_elements: Vec::new(),
            }],
            final_output_json_schema: None,
            responsesapi_client_metadata: None,
        })
        .await
        .unwrap();

    wait_for_event(&codex, |event| matches!(event, EventMsg::TurnComplete(_))).await;

    let requests = server.requests().await;
    assert_eq!(
        requests.len(),
        2,
        "expected retry after early-close on function_call"
    );

    // Decode the second request body and verify BOTH the function_call and
    // the function_call_output for `call-early-close` are present in the input
    // array. This is the core invariant the PLAN protects: drain_in_flight
    // must have persisted the output, and the retry must rebuild its prompt
    // from fresh history so the output is visible in the next request.
    let second_body_bytes = &requests[1];
    let body: serde_json::Value =
        serde_json::from_slice(second_body_bytes).expect("second request body JSON");
    let input = body["input"]
        .as_array()
        .expect("second request must have an input array")
        .clone();

    let has_call = input.iter().any(|item| {
        item.get("type").and_then(|v| v.as_str()) == Some("function_call")
            && item.get("call_id").and_then(|v| v.as_str()) == Some("call-early-close")
    });
    let has_output = input.iter().any(|item| {
        item.get("type").and_then(|v| v.as_str()) == Some("function_call_output")
            && item.get("call_id").and_then(|v| v.as_str()) == Some("call-early-close")
    });

    assert!(
        has_call,
        "retry request must include the function_call for call-early-close"
    );
    assert!(
        has_output,
        "retry request must include the function_call_output for call-early-close \
         (drain_in_flight must run even on early stream close)"
    );

    server.shutdown().await;
}
