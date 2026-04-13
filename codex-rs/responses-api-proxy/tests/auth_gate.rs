#![allow(deprecated)] // assert_cmd::Command::cargo_bin still works fine here.

//! End-to-end integration tests for the auth/origin/content-type gate added in
//! response to issue #17648 (CWE-352 / CWE-306). All tests drive the real
//! `codex-responses-api-proxy` binary against an in-process mock upstream so we
//! observe externally-visible behavior only.
//!
//! The proxy contract under test (per PLAN.md):
//!   * Reads operator `OPENAI_API_KEY` from stdin.
//!   * Generates a 256-bit per-launch `auth_token` and exposes it via
//!     `server-info.json` (and on stderr when --server-info is omitted).
//!   * For `POST /v1/responses` and `GET /shutdown` it requires:
//!       - No `Origin` header (else 403).
//!       - `Content-Type` starting with `application/json` for the responses
//!         endpoint (else 415).
//!       - `Authorization: Bearer <auth_token>` OR `X-Proxy-Token: <auth_token>`
//!         (else 401).
//!   * Strips `Authorization`, `Host`, and `X-Proxy-Token` before forwarding
//!     and injects `Authorization: Bearer <OPENAI_API_KEY>`.
//!   * Writes `server-info.json` with mode 0600 on Unix; refuses to follow a
//!     pre-existing symlink at the target path.

use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use assert_cmd::cargo::CommandCargoExt;
use serde_json::Value;
use tempfile::TempDir;
use tiny_http::Response as TinyResponse;
use tiny_http::Server as TinyServer;

const BIN_NAME: &str = "codex-responses-api-proxy";
const OPERATOR_KEY: &str = "sk-operator-dummy-key-XYZ";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(50);

// --- Mock upstream -----------------------------------------------------------

#[derive(Clone, Debug)]
struct RecordedRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl RecordedRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn has_header(&self, name: &str) -> bool {
        self.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
    }
}

struct MockUpstream {
    base_url: String,
    received: Arc<Mutex<Vec<RecordedRequest>>>,
    server: Arc<TinyServer>,
}

impl MockUpstream {
    fn start() -> Self {
        let server =
            Arc::new(TinyServer::http("127.0.0.1:0").expect("bind upstream mock"));
        let port = server
            .server_addr()
            .to_ip()
            .expect("mock addr is ip")
            .port();
        let base_url = format!("http://127.0.0.1:{port}/v1/responses");
        let received: Arc<Mutex<Vec<RecordedRequest>>> = Arc::new(Mutex::new(Vec::new()));

        let server_thread = server.clone();
        let received_thread = received.clone();
        thread::spawn(move || {
            for mut req in server_thread.incoming_requests() {
                let mut body = Vec::new();
                let _ = req.as_reader().read_to_end(&mut body);
                let recorded = RecordedRequest {
                    method: req.method().to_string(),
                    path: req.url().to_string(),
                    headers: req
                        .headers()
                        .iter()
                        .map(|h| {
                            (h.field.as_str().to_string(), h.value.as_str().to_string())
                        })
                        .collect(),
                    body,
                };
                received_thread.lock().expect("upstream lock").push(recorded);
                let resp = TinyResponse::from_string(r#"{"ok":true,"id":"resp_test"}"#)
                    .with_status_code(200)
                    .with_header(
                        tiny_http::Header::from_bytes(
                            &b"Content-Type"[..],
                            &b"application/json"[..],
                        )
                        .expect("header"),
                    );
                let _ = req.respond(resp);
            }
        });

        MockUpstream {
            base_url,
            received,
            server,
        }
    }

    fn requests(&self) -> Vec<RecordedRequest> {
        self.received.lock().expect("upstream lock").clone()
    }

    fn count(&self) -> usize {
        self.received.lock().expect("upstream lock").len()
    }
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        self.server.unblock();
    }
}

// --- Proxy harness -----------------------------------------------------------

#[allow(dead_code)]
struct ProxyProcess {
    child: Option<Child>,
    server_info_path: PathBuf,
    port: u16,
    pid: u32,
    auth_token: String,
    _tempdir: TempDir,
}

impl ProxyProcess {
    fn launch(upstream_url: &str, extra_args: &[&str]) -> Self {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let server_info_path = tempdir.path().join("server-info.json");

        let mut cmd = Command::cargo_bin(BIN_NAME).expect("binary built");
        cmd.arg("--server-info")
            .arg(&server_info_path)
            .arg("--http-shutdown")
            .arg("--upstream-url")
            .arg(upstream_url)
            .args(extra_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().expect("spawn proxy");
        {
            let mut stdin = child.stdin.take().expect("stdin");
            stdin
                .write_all(OPERATOR_KEY.as_bytes())
                .expect("write key");
            // Some implementations require a trailing newline.
            let _ = stdin.write_all(b"\n");
        }

        let info = wait_for_server_info(&server_info_path)
            .unwrap_or_else(|e| panic!("server-info never appeared: {e}"));

        ProxyProcess {
            child: Some(child),
            server_info_path,
            port: info.port,
            pid: info.pid,
            auth_token: info.auth_token,
            _tempdir: tempdir,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.port, path)
    }

    fn wait_for_exit(&mut self, max: Duration) -> Option<i32> {
        let start = Instant::now();
        let child = self.child.as_mut()?;
        loop {
            match child.try_wait().ok()? {
                Some(status) => return Some(status.code().unwrap_or(-1)),
                None => {
                    if start.elapsed() > max {
                        return None;
                    }
                    thread::sleep(POLL_INTERVAL);
                }
            }
        }
    }

}

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[derive(Debug)]
struct ParsedServerInfo {
    port: u16,
    pid: u32,
    auth_token: String,
}

fn wait_for_server_info(path: &Path) -> Result<ParsedServerInfo, String> {
    let start = Instant::now();
    loop {
        if start.elapsed() > STARTUP_TIMEOUT {
            return Err(format!(
                "{} did not appear within {:?}",
                path.display(),
                STARTUP_TIMEOUT
            ));
        }
        if path.exists() {
            // Re-read until JSON parses (might be mid-write).
            let raw = match std::fs::read_to_string(path) {
                Ok(s) => s,
                Err(_) => {
                    thread::sleep(POLL_INTERVAL);
                    continue;
                }
            };
            let v: Value = match serde_json::from_str(&raw) {
                Ok(v) => v,
                Err(_) => {
                    thread::sleep(POLL_INTERVAL);
                    continue;
                }
            };
            let port = v
                .get("port")
                .and_then(Value::as_u64)
                .ok_or("missing port")? as u16;
            let pid = v
                .get("pid")
                .and_then(Value::as_u64)
                .ok_or("missing pid")? as u32;
            let auth_token = v
                .get("auth_token")
                .and_then(Value::as_str)
                .ok_or("missing auth_token")?
                .to_string();
            assert!(
                !auth_token.is_empty(),
                "auth_token in server-info.json must be a non-empty string"
            );
            return Ok(ParsedServerInfo {
                port,
                pid,
                auth_token,
            });
        }
        thread::sleep(POLL_INTERVAL);
    }
}

// --- HTTP helpers ------------------------------------------------------------

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client")
}

fn json_body() -> &'static str {
    r#"{"model":"gpt-test","input":"hello"}"#
}

// =============================================================================
// AUTH FAILURE CASES (no token, wrong token, wrong scheme)
// =============================================================================

#[test]
fn missing_token_returns_401_and_does_not_call_upstream() {
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let resp = client()
        .post(proxy.url("/v1/responses"))
        .header("Content-Type", "application/json")
        .body(json_body())
        .send()
        .expect("send");

    assert_eq!(
        resp.status().as_u16(),
        401,
        "missing token must yield 401 (CWE-306)"
    );
    let body = resp.text().unwrap_or_default();
    assert!(
        !body.contains(&proxy.auth_token),
        "401 body must not echo the expected token (timing/leak): got {body:?}"
    );
    assert_eq!(
        upstream.count(),
        0,
        "upstream must NOT be called when caller is unauthenticated"
    );
}

#[test]
fn wrong_bearer_token_returns_401() {
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let resp = client()
        .post(proxy.url("/v1/responses"))
        .header("Content-Type", "application/json")
        .header("Authorization", "Bearer not-the-right-token")
        .body(json_body())
        .send()
        .expect("send");

    assert_eq!(resp.status().as_u16(), 401);
    assert_eq!(upstream.count(), 0);
}

#[test]
fn wrong_x_proxy_token_returns_401() {
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let resp = client()
        .post(proxy.url("/v1/responses"))
        .header("Content-Type", "application/json")
        .header("X-Proxy-Token", "obviously-wrong")
        .body(json_body())
        .send()
        .expect("send");

    assert_eq!(resp.status().as_u16(), 401);
    assert_eq!(upstream.count(), 0);
}

#[test]
fn non_bearer_authorization_scheme_returns_401() {
    // A Basic/etc Authorization header (with no X-Proxy-Token fallback) must
    // not be silently accepted as proxy auth.
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let resp = client()
        .post(proxy.url("/v1/responses"))
        .header("Content-Type", "application/json")
        .header("Authorization", "Basic dXNlcjpwYXNz")
        .body(json_body())
        .send()
        .expect("send");

    assert_eq!(
        resp.status().as_u16(),
        401,
        "Authorization with non-Bearer scheme must not silently authenticate"
    );
    assert_eq!(upstream.count(), 0);
}

#[test]
fn empty_bearer_token_returns_401() {
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let resp = client()
        .post(proxy.url("/v1/responses"))
        .header("Content-Type", "application/json")
        .header("Authorization", "Bearer ")
        .body(json_body())
        .send()
        .expect("send");

    assert_eq!(resp.status().as_u16(), 401);
    assert_eq!(upstream.count(), 0);
}

// =============================================================================
// ORIGIN GATE (CSRF kill switch — §3.3 step 1, evaluated FIRST)
// =============================================================================

#[test]
fn origin_header_with_valid_token_returns_403() {
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let resp = client()
        .post(proxy.url("/v1/responses"))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", proxy.auth_token))
        .header("Origin", "https://evil.example.com")
        .body(json_body())
        .send()
        .expect("send");

    assert_eq!(
        resp.status().as_u16(),
        403,
        "Origin header must be rejected even with a valid token (CWE-352)"
    );
    assert_eq!(upstream.count(), 0);
}

#[test]
fn origin_header_evaluated_before_auth() {
    // §3.3 ordering: Origin first, then content-type, then auth, then path.
    // An UNAUTHENTICATED browser request with an Origin must still 403 — never
    // 401 — so the proxy never reveals to a CSRF probe whether the URL exists.
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let resp = client()
        .post(proxy.url("/v1/responses"))
        .header("Content-Type", "application/json")
        .header("Origin", "https://attacker.example")
        .body(json_body())
        .send()
        .expect("send");

    assert_eq!(
        resp.status().as_u16(),
        403,
        "Origin must be evaluated before auth (don't reveal endpoint existence)"
    );
    assert_eq!(upstream.count(), 0);
}

#[test]
fn origin_header_case_insensitive() {
    // §4.11: header-name matching must be case-insensitive.
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let resp = client()
        .post(proxy.url("/v1/responses"))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", proxy.auth_token))
        // reqwest normalizes header names lowercase on the wire; the proxy
        // already iterates with eq_ignore_ascii_case so this still hits the
        // origin gate.
        .header("oRiGiN", "https://attacker.example")
        .body(json_body())
        .send()
        .expect("send");

    assert_eq!(resp.status().as_u16(), 403);
    assert_eq!(upstream.count(), 0);
}

// =============================================================================
// CONTENT-TYPE GATE (§3.3 step 2)
// =============================================================================

#[test]
fn non_json_content_type_returns_415() {
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let resp = client()
        .post(proxy.url("/v1/responses"))
        .header("Content-Type", "text/plain")
        .header("Authorization", format!("Bearer {}", proxy.auth_token))
        .body(json_body())
        .send()
        .expect("send");

    assert_eq!(resp.status().as_u16(), 415);
    assert_eq!(upstream.count(), 0);
}

#[test]
fn missing_content_type_returns_415() {
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    // reqwest will not auto-set Content-Type when sending a raw bytes body.
    let resp = client()
        .post(proxy.url("/v1/responses"))
        .header("Authorization", format!("Bearer {}", proxy.auth_token))
        .body(json_body().as_bytes().to_vec())
        .send()
        .expect("send");

    assert_eq!(
        resp.status().as_u16(),
        415,
        "missing Content-Type must yield 415 per §4.5"
    );
    assert_eq!(upstream.count(), 0);
}

#[test]
fn form_urlencoded_content_type_returns_415() {
    // The simple-request CSRF bypass relies on form-encoded POSTs which don't
    // require a CORS preflight. This must be locked out.
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let resp = client()
        .post(proxy.url("/v1/responses"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Authorization", format!("Bearer {}", proxy.auth_token))
        .body("foo=bar")
        .send()
        .expect("send");

    assert_eq!(resp.status().as_u16(), 415);
    assert_eq!(upstream.count(), 0);
}

#[test]
fn application_json_with_charset_is_accepted() {
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let resp = client()
        .post(proxy.url("/v1/responses"))
        .header("Content-Type", "application/json; charset=utf-8")
        .header("Authorization", format!("Bearer {}", proxy.auth_token))
        .body(json_body())
        .send()
        .expect("send");

    assert!(
        resp.status().is_success(),
        "application/json; charset=utf-8 must be accepted, got {}",
        resp.status()
    );
    assert_eq!(upstream.count(), 1);
}

#[test]
fn content_type_case_insensitive() {
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let resp = client()
        .post(proxy.url("/v1/responses"))
        .header("Content-Type", "Application/JSON")
        .header("Authorization", format!("Bearer {}", proxy.auth_token))
        .body(json_body())
        .send()
        .expect("send");

    assert!(resp.status().is_success(), "got {}", resp.status());
    assert_eq!(upstream.count(), 1);
}

// =============================================================================
// HAPPY PATH (valid token, no Origin, JSON body)
// =============================================================================

#[test]
fn valid_bearer_token_forwards_to_upstream() {
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let resp = client()
        .post(proxy.url("/v1/responses"))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", proxy.auth_token))
        .body(json_body())
        .send()
        .expect("send");

    assert!(resp.status().is_success(), "got {}", resp.status());
    let reqs = upstream.requests();
    assert_eq!(reqs.len(), 1, "exactly one upstream call expected");

    let r = &reqs[0];
    assert_eq!(r.method.to_uppercase(), "POST");
    assert!(
        r.path.ends_with("/v1/responses"),
        "upstream path={}",
        r.path
    );

    // §3.4: operator key replaces caller's Authorization.
    assert_eq!(
        r.header("Authorization"),
        Some(format!("Bearer {OPERATOR_KEY}").as_str()),
        "upstream must see operator's bearer, not the proxy auth_token"
    );

    // The proxy's per-launch token must NEVER be exposed upstream — neither
    // verbatim in any header value nor as the X-Proxy-Token header.
    assert!(
        !r.has_header("X-Proxy-Token"),
        "X-Proxy-Token must be stripped before forwarding (§3.4)"
    );
    for (name, value) in &r.headers {
        assert!(
            !value.contains(&proxy.auth_token),
            "proxy auth_token leaked upstream in header {name}: {value}"
        );
    }

    // Body should be passed through verbatim.
    assert_eq!(r.body, json_body().as_bytes());
}

#[test]
fn valid_x_proxy_token_forwards_to_upstream() {
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let resp = client()
        .post(proxy.url("/v1/responses"))
        .header("Content-Type", "application/json")
        .header("X-Proxy-Token", &proxy.auth_token)
        .body(json_body())
        .send()
        .expect("send");

    assert!(resp.status().is_success(), "got {}", resp.status());
    let reqs = upstream.requests();
    assert_eq!(reqs.len(), 1);
    assert!(!reqs[0].has_header("X-Proxy-Token"));
    assert_eq!(
        reqs[0].header("Authorization"),
        Some(format!("Bearer {OPERATOR_KEY}").as_str())
    );
}

#[test]
fn host_header_is_stripped_before_forwarding() {
    // §3.4: Host is stripped (existing behavior, must not regress). reqwest
    // sets Host automatically; the upstream tiny_http will set its own based
    // on the connection it receives, so we just assert the original value
    // (the proxy's loopback host) is not echoed.
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let _ = client()
        .post(proxy.url("/v1/responses"))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", proxy.auth_token))
        .body(json_body())
        .send()
        .expect("send");

    let reqs = upstream.requests();
    assert_eq!(reqs.len(), 1);
    let host = reqs[0].header("Host").unwrap_or("");
    assert!(
        !host.contains(&format!("{}", proxy.port)),
        "proxy's loopback Host must not leak upstream; got Host={host}"
    );
}

#[test]
fn arbitrary_pass_through_headers_preserved() {
    // §3.4: "Keep everything else intact for upstream observability."
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let _ = client()
        .post(proxy.url("/v1/responses"))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", proxy.auth_token))
        .header("X-Codex-Window-Id", "win-1234")
        .body(json_body())
        .send()
        .expect("send");

    let reqs = upstream.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].header("X-Codex-Window-Id"), Some("win-1234"));
}

#[test]
fn x_proxy_token_takes_precedence_over_authorization() {
    // X-Proxy-Token is the dedicated proxy auth header; Authorization is
    // reserved for the upstream credential and is forwarded transparently. So
    // a valid X-Proxy-Token must authenticate even when Authorization carries
    // an unrelated upstream bearer.
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let resp = client()
        .post(proxy.url("/v1/responses"))
        .header("Content-Type", "application/json")
        .header("Authorization", "Bearer some-upstream-key")
        .header("X-Proxy-Token", &proxy.auth_token)
        .body(json_body())
        .send()
        .expect("send");

    assert!(
        resp.status().is_success(),
        "valid X-Proxy-Token must authenticate regardless of Authorization, \
         got {}",
        resp.status()
    );
    assert_eq!(upstream.count(), 1);
}

#[test]
fn authorization_header_case_insensitive() {
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let resp = client()
        .post(proxy.url("/v1/responses"))
        .header("Content-Type", "application/json")
        .header("authorization", format!("Bearer {}", proxy.auth_token))
        .body(json_body())
        .send()
        .expect("send");

    assert!(resp.status().is_success(), "got {}", resp.status());
    assert_eq!(upstream.count(), 1);
}

// =============================================================================
// METHOD / PATH / OPTIONS
// =============================================================================

#[test]
fn wrong_path_with_valid_token_returns_403() {
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let resp = client()
        .post(proxy.url("/v1/wrong/path"))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", proxy.auth_token))
        .body(json_body())
        .send()
        .expect("send");

    // §3.3 step 4: "403 for method/path mismatch (as today)".
    assert_eq!(resp.status().as_u16(), 403);
    assert_eq!(upstream.count(), 0);
}

#[test]
fn get_on_responses_endpoint_with_valid_token_returns_403() {
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let resp = client()
        .get(proxy.url("/v1/responses"))
        .header("Authorization", format!("Bearer {}", proxy.auth_token))
        // GET typically lacks Content-Type; the implementation may or may not
        // gate GET behind Content-Type. Either way, method mismatch is fatal.
        .send()
        .expect("send");

    assert_eq!(resp.status().as_u16(), 403);
    assert_eq!(upstream.count(), 0);
}

#[test]
fn options_preflight_is_rejected() {
    // §4.4: OPTIONS preflights must fail (no CORS allowlist), so browsers
    // can't bypass the JSON content-type requirement.
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let resp = client()
        .request(
            reqwest::Method::OPTIONS,
            proxy.url("/v1/responses"),
        )
        .header("Origin", "https://attacker.example")
        .header("Access-Control-Request-Method", "POST")
        .header("Access-Control-Request-Headers", "content-type")
        .send()
        .expect("send");

    let status = resp.status().as_u16();
    assert!(
        status == 403 || status == 405,
        "OPTIONS preflight should be rejected (403 or 405), got {status}"
    );
    // Critically, no Access-Control-Allow-Origin header (§3.6).
    assert!(
        resp.headers().get("access-control-allow-origin").is_none(),
        "no CORS allowlist headers must be returned"
    );
    assert_eq!(upstream.count(), 0);
}

// =============================================================================
// /shutdown ENDPOINT
// =============================================================================

#[test]
fn shutdown_without_token_returns_401_and_proxy_stays_alive() {
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let resp = client()
        .get(proxy.url("/shutdown"))
        .send()
        .expect("send");

    assert_eq!(
        resp.status().as_u16(),
        401,
        "shutdown without token must NOT terminate the proxy (DoS protection)"
    );

    // Quick liveness check: a follow-up auth-failed POST should still get 401,
    // proving the listener is still serving.
    thread::sleep(Duration::from_millis(100));
    let r = client()
        .post(proxy.url("/v1/responses"))
        .header("Content-Type", "application/json")
        .body(json_body())
        .send()
        .expect("liveness");
    assert_eq!(r.status().as_u16(), 401);
}

#[test]
fn shutdown_with_origin_returns_403() {
    // §3.5: Origin must also be rejected for /shutdown.
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let resp = client()
        .get(proxy.url("/shutdown"))
        .header("Origin", "https://attacker.example")
        .header("Authorization", format!("Bearer {}", proxy.auth_token))
        .send()
        .expect("send");

    assert_eq!(
        resp.status().as_u16(),
        403,
        "Origin on /shutdown must be 403 even with valid token"
    );

    // Proxy should still be alive.
    let r = client()
        .post(proxy.url("/v1/responses"))
        .header("Content-Type", "application/json")
        .body(json_body())
        .send()
        .expect("liveness");
    assert_eq!(r.status().as_u16(), 401);
}

#[test]
fn shutdown_with_token_terminates_proxy() {
    let upstream = MockUpstream::start();
    let mut proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let resp = client()
        .get(proxy.url("/shutdown"))
        .header("Authorization", format!("Bearer {}", proxy.auth_token))
        .send();
    // The connection may be closed mid-response by the shutdown handler;
    // either an OK response or a connection reset is acceptable.
    let _ = resp;

    let exit = proxy.wait_for_exit(Duration::from_secs(10));
    assert_eq!(
        exit,
        Some(0),
        "proxy should exit cleanly when /shutdown is invoked with a valid token"
    );
}

#[test]
fn shutdown_with_x_proxy_token_terminates_proxy() {
    let upstream = MockUpstream::start();
    let mut proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let _ = client()
        .get(proxy.url("/shutdown"))
        .header("X-Proxy-Token", &proxy.auth_token)
        .send();

    let exit = proxy.wait_for_exit(Duration::from_secs(10));
    assert_eq!(exit, Some(0));
}

// =============================================================================
// SERVER-INFO FILE PROPERTIES
// =============================================================================

#[test]
fn server_info_contains_required_fields() {
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let raw = std::fs::read_to_string(&proxy.server_info_path).expect("read");
    let v: Value = serde_json::from_str(&raw).expect("json");

    assert!(v.get("port").and_then(Value::as_u64).is_some());
    assert!(v.get("pid").and_then(Value::as_u64).is_some());
    let token = v
        .get("auth_token")
        .and_then(Value::as_str)
        .expect("auth_token");
    // Plan §3.1: 64 hex chars OR 43 base64url chars.
    assert!(
        token.len() == 64 || token.len() == 43,
        "auth_token length should be 64 (hex) or 43 (base64url), got {} ({:?})",
        token.len(),
        token
    );
    assert!(
        token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "auth_token should be hex or base64url alphabet, got {token:?}"
    );
}

#[cfg(unix)]
#[test]
fn server_info_file_is_mode_0600() {
    use std::os::unix::fs::MetadataExt;

    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let meta = std::fs::metadata(&proxy.server_info_path).expect("stat");
    let mode = meta.mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "server-info.json must be 0600 to prevent local-tenant token theft"
    );
}

#[cfg(unix)]
#[test]
fn server_info_refuses_existing_symlink() {
    use std::os::unix::fs::symlink;

    let upstream = MockUpstream::start();
    let tempdir = tempfile::tempdir().expect("tempdir");
    let real_path = tempdir.path().join("decoy.json");
    std::fs::write(&real_path, "{}").expect("seed decoy");
    let symlink_path = tempdir.path().join("server-info.json");
    symlink(&real_path, &symlink_path).expect("symlink");

    let mut cmd = Command::cargo_bin(BIN_NAME).expect("binary built");
    cmd.arg("--server-info")
        .arg(&symlink_path)
        .arg("--upstream-url")
        .arg(&upstream.base_url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        let _ = stdin.write_all(OPERATOR_KEY.as_bytes());
        let _ = stdin.write_all(b"\n");
    }

    let start = Instant::now();
    let exit = loop {
        if start.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            panic!("proxy did not refuse symlink within 10s");
        }
        match child.try_wait().expect("wait") {
            Some(s) => break s,
            None => thread::sleep(POLL_INTERVAL),
        }
    };

    assert!(
        !exit.success(),
        "proxy must refuse to write server-info to a symlink target (§3.2)"
    );

    // The symlink target must NOT have been overwritten with new contents.
    let after = std::fs::read_to_string(&real_path).expect("decoy still readable");
    assert_eq!(
        after, "{}",
        "decoy file behind symlink must NOT have been clobbered"
    );
}

#[cfg(unix)]
#[test]
fn server_info_overwrites_existing_with_tight_mode() {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;

    let upstream = MockUpstream::start();
    let tempdir = tempfile::tempdir().expect("tempdir");
    let path = tempdir.path().join("server-info.json");

    // Pre-create the file with loose permissions to simulate a leftover from
    // a prior run with a permissive umask.
    std::fs::write(&path, "stale").expect("seed");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .expect("chmod seed");

    // Per §3.2, the proxy should either refuse a world-readable target OR
    // overwrite-and-tighten to 0600. Both are acceptable; both must NOT
    // leave the file at 0644 (which would still leak the new token).
    let mut cmd = Command::cargo_bin(BIN_NAME).expect("binary built");
    cmd.arg("--server-info")
        .arg(&path)
        .arg("--upstream-url")
        .arg(&upstream.base_url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        let _ = stdin.write_all(OPERATOR_KEY.as_bytes());
        let _ = stdin.write_all(b"\n");
    }

    // Wait briefly: either the proxy aborts (file should still be "stale") or
    // it succeeds (file should be 0600).
    thread::sleep(Duration::from_secs(2));
    if let Ok(Some(_status)) = child.try_wait() {
        // Aborted — verify the original file was NOT replaced with token data.
        let raw = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            !raw.contains("auth_token"),
            "if the proxy refuses, it must leave the pre-existing file intact"
        );
        return;
    }

    // Proxy still running — it must have rewritten with mode 0600.
    let _ = child.kill();
    let _ = child.wait();
    let meta = std::fs::metadata(&path).expect("stat");
    let mode = meta.mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "if the proxy overwrites a pre-existing file, it MUST tighten mode to 0600"
    );
}

// =============================================================================
// --server-info OMITTED: token printed to stderr (§4.1)
// =============================================================================

#[test]
fn token_printed_to_stderr_when_server_info_omitted() {
    let upstream = MockUpstream::start();

    let mut cmd = Command::cargo_bin(BIN_NAME).expect("binary built");
    cmd.arg("--upstream-url")
        .arg(&upstream.base_url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        let _ = stdin.write_all(OPERATOR_KEY.as_bytes());
        let _ = stdin.write_all(b"\n");
    }

    // Drain stderr in a thread to look for the auth_token line.
    let stderr = child.stderr.take().expect("stderr");
    let collected: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let collected_thread = collected.clone();
    let drain = thread::spawn(move || {
        let mut buf = [0u8; 1024];
        let mut handle = stderr;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if Instant::now() > deadline {
                break;
            }
            match handle.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let s = String::from_utf8_lossy(&buf[..n]).to_string();
                    let mut g = collected_thread.lock().expect("lock");
                    g.push_str(&s);
                    if g.contains("auth_token=") {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Give it time to start and print.
    let start = Instant::now();
    let mut found = false;
    while start.elapsed() < Duration::from_secs(10) {
        if collected.lock().expect("lock").contains("auth_token=") {
            found = true;
            break;
        }
        thread::sleep(POLL_INTERVAL);
    }
    let _ = drain.join();
    let _ = child.kill();
    let _ = child.wait();

    let captured = collected.lock().expect("lock").clone();
    assert!(
        found,
        "stderr must include `auth_token=...` when --server-info is omitted (§4.1). \
         Captured stderr: {captured:?}"
    );
}

// =============================================================================
// PER-LAUNCH UNIQUENESS
// =============================================================================

#[test]
fn auth_token_is_unique_per_launch() {
    // Two launches in a row must generate different tokens.
    let upstream = MockUpstream::start();
    let proxy_a = ProxyProcess::launch(&upstream.base_url, &[]);
    let token_a = proxy_a.auth_token.clone();
    drop(proxy_a);
    let proxy_b = ProxyProcess::launch(&upstream.base_url, &[]);
    let token_b = proxy_b.auth_token.clone();

    assert_ne!(
        token_a, token_b,
        "auth_token must be freshly generated per launch (256-bit, vanishingly \
         unlikely to collide); equality strongly suggests a hard-coded or \
         static-seeded RNG"
    );
}

// =============================================================================
// CONCURRENCY
// =============================================================================

#[test]
fn many_concurrent_authenticated_requests_all_forwarded() {
    // §4.3: token shared via Arc, constant_time_eq is thread-safe.
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let n = 10;
    let mut handles = Vec::new();
    for i in 0..n {
        let url = proxy.url("/v1/responses");
        let token = proxy.auth_token.clone();
        handles.push(thread::spawn(move || {
            let body = format!(r#"{{"req":{i}}}"#);
            let r = client()
                .post(&url)
                .header("Content-Type", "application/json")
                .header("Authorization", format!("Bearer {token}"))
                .body(body)
                .send()
                .expect("send");
            assert!(r.status().is_success(), "req {i} got {}", r.status());
        }));
    }
    for h in handles {
        h.join().expect("join");
    }
    assert_eq!(upstream.count(), n);
}

#[test]
fn concurrent_unauthenticated_requests_all_rejected() {
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let n = 10;
    let mut handles = Vec::new();
    for _ in 0..n {
        let url = proxy.url("/v1/responses");
        handles.push(thread::spawn(move || {
            let r = client()
                .post(&url)
                .header("Content-Type", "application/json")
                .body(r#"{"x":1}"#)
                .send()
                .expect("send");
            assert_eq!(r.status().as_u16(), 401);
        }));
    }
    for h in handles {
        h.join().expect("join");
    }
    assert_eq!(upstream.count(), 0);
}

// =============================================================================
// NEGATIVE: ensure 401 body has no token leak
// =============================================================================

#[test]
fn unauth_body_never_echoes_received_token() {
    // §4.12: 401 body must not echo received or expected token.
    let upstream = MockUpstream::start();
    let proxy = ProxyProcess::launch(&upstream.base_url, &[]);

    let attacker_guess = "ATTACKER-PROBED-VALUE-DEADBEEF";
    let resp = client()
        .post(proxy.url("/v1/responses"))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {attacker_guess}"))
        .body(json_body())
        .send()
        .expect("send");
    assert_eq!(resp.status().as_u16(), 401);
    let body = resp.text().unwrap_or_default();
    assert!(
        !body.contains(attacker_guess),
        "401 body must not echo the received token: {body:?}"
    );
    assert!(
        !body.contains(&proxy.auth_token),
        "401 body must not echo the expected token: {body:?}"
    );
}

