use std::fs::{self};
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Parser;
use constant_time_eq::constant_time_eq;
use rand::TryRngCore;
use rand::rngs::OsRng;
use reqwest::Url;
use reqwest::blocking::Client;
use reqwest::header::AUTHORIZATION;
use reqwest::header::HOST;
use reqwest::header::HeaderMap;
use reqwest::header::HeaderName;
use reqwest::header::HeaderValue;
use serde::Serialize;
use tiny_http::Header;
use tiny_http::Method;
use tiny_http::Request;
use tiny_http::Response;
use tiny_http::Server;
use tiny_http::StatusCode;

mod dump;
mod read_api_key;
use dump::ExchangeDumper;
use read_api_key::read_auth_header_from_stdin;

/// CLI arguments for the proxy.
#[derive(Debug, Clone, Parser)]
#[command(name = "responses-api-proxy", about = "Minimal OpenAI responses proxy")]
pub struct Args {
    /// Port to listen on. If not set, an ephemeral port is used.
    #[arg(long)]
    pub port: Option<u16>,

    /// Path to a JSON file to write startup info (single line). Includes
    /// `{"port": <u16>, "pid": <u32>, "auth_token": <string>}`.
    #[arg(long, value_name = "FILE")]
    pub server_info: Option<PathBuf>,

    /// Enable HTTP shutdown endpoint at GET /shutdown
    #[arg(long)]
    pub http_shutdown: bool,

    /// Absolute URL the proxy should forward requests to (defaults to OpenAI).
    #[arg(long, default_value = "https://api.openai.com/v1/responses")]
    pub upstream_url: String,

    /// Directory where request/response dumps should be written as JSON.
    #[arg(long, value_name = "DIR")]
    pub dump_dir: Option<PathBuf>,
}

#[derive(Serialize)]
struct ServerInfo {
    port: u16,
    pid: u32,
    auth_token: String,
}

struct ForwardConfig {
    upstream_url: Url,
    host_header: HeaderValue,
    auth_token: String,
}

#[derive(Debug, PartialEq, Eq)]
enum AuthOutcome {
    Ok,
    OriginRejected,
    BadContentType,
    Unauthorized,
}

/// Entry point for the library main, for parity with other crates.
pub fn run_main(args: Args) -> Result<()> {
    let auth_header = read_auth_header_from_stdin()?;

    // Per-launch shared secret used to authenticate local callers talking to
    // this proxy. 256 bits of entropy, base64url-encoded (no padding).
    let auth_token = generate_auth_token()?;

    let upstream_url = Url::parse(&args.upstream_url).context("parsing --upstream-url")?;
    let host = match (upstream_url.host_str(), upstream_url.port()) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host.to_string(),
        _ => return Err(anyhow!("upstream URL must include a host")),
    };
    let host_header =
        HeaderValue::from_str(&host).context("constructing Host header from upstream URL")?;

    let forward_config = Arc::new(ForwardConfig {
        upstream_url,
        host_header,
        auth_token: auth_token.clone(),
    });
    let dump_dir = args
        .dump_dir
        .map(ExchangeDumper::new)
        .transpose()
        .context("creating --dump-dir")?
        .map(Arc::new);

    let (listener, bound_addr) = bind_listener(args.port)?;
    if let Some(path) = args.server_info.as_ref() {
        let info = ServerInfo {
            port: bound_addr.port(),
            pid: std::process::id(),
            auth_token: auth_token.clone(),
        };
        write_server_info(path, &info)?;
    } else {
        // When --server-info is not provided, surface the token on stderr so
        // operators running the proxy interactively can still authenticate.
        eprintln!("responses-api-proxy auth_token={auth_token}");
    }
    let server = Server::from_listener(listener, None)
        .map_err(|err| anyhow!("creating HTTP server: {err}"))?;
    let client = Arc::new(
        Client::builder()
            // Disable reqwest's 30s default so long-lived response streams keep flowing.
            .timeout(None::<Duration>)
            .build()
            .context("building reqwest client")?,
    );

    eprintln!("responses-api-proxy listening on {bound_addr}");

    let http_shutdown = args.http_shutdown;
    for request in server.incoming_requests() {
        let client = client.clone();
        let forward_config = forward_config.clone();
        let dump_dir = dump_dir.clone();
        std::thread::spawn(move || {
            if http_shutdown && request.method() == &Method::Get && request.url() == "/shutdown" {
                handle_shutdown(request, &forward_config.auth_token);
                return;
            }

            if let Err(e) = forward_request(
                &client,
                auth_header,
                &forward_config,
                dump_dir.as_deref(),
                request,
            ) {
                eprintln!("forwarding error: {e}");
            }
        });
    }

    Err(anyhow!("server stopped unexpectedly"))
}

fn generate_auth_token() -> Result<String> {
    let mut secret_bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut secret_bytes)
        .context("generating proxy auth token")?;
    let encoded = URL_SAFE_NO_PAD.encode(secret_bytes);
    // Best-effort wipe of the raw bytes now that the encoded copy exists.
    for byte in &mut secret_bytes {
        *byte = 0;
    }
    Ok(encoded)
}

fn bind_listener(port: Option<u16>) -> Result<(TcpListener, SocketAddr)> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port.unwrap_or(0)));
    let listener = TcpListener::bind(addr).with_context(|| format!("failed to bind {addr}"))?;
    let bound = listener.local_addr().context("failed to read local_addr")?;
    Ok((listener, bound))
}

#[cfg(unix)]
fn write_server_info(path: &Path, info: &ServerInfo) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    // Refuse to follow a symlink or overwrite a file that is readable by
    // anyone other than the owner. This blocks symlink-plant attacks where a
    // local attacker pre-creates the target pointing somewhere readable.
    match fs::symlink_metadata(path) {
        Ok(md) => {
            if md.file_type().is_symlink() {
                return Err(anyhow!(
                    "refusing to write server info: {} is a symlink",
                    path.display()
                ));
            }
            let mode = md.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(anyhow!(
                    "refusing to overwrite {}: insecure permissions {:03o}",
                    path.display(),
                    mode
                ));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }

    let mut data = serde_json::to_string(info)?;
    data.push('\n');
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(data.as_bytes())?;
    // Re-apply mode in case a umask or a pre-existing file left a looser bit set.
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_server_info(path: &Path, info: &ServerInfo) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let mut data = serde_json::to_string(info)?;
    data.push('\n');
    let mut f = fs::File::create(path)?;
    f.write_all(data.as_bytes())?;
    Ok(())
}

fn header_name_eq(h: &Header, name: &str) -> bool {
    h.field.as_str().as_str().eq_ignore_ascii_case(name)
}

fn header_value_as_str(h: &Header) -> &str {
    h.value.as_str()
}

/// Authenticate a caller. `require_json_body` controls whether the caller must
/// also supply `Content-Type: application/json` (true for body-bearing POSTs,
/// false for the bodyless `/shutdown` endpoint).
fn authorize(headers: &[Header], token: &str, require_json_body: bool) -> AuthOutcome {
    // 1. Origin check. CLIs do not send `Origin`; browsers always do. Any
    // presence of this header means the request was issued by a browser
    // context, which we refuse wholesale.
    if headers.iter().any(|h| header_name_eq(h, "origin")) {
        return AuthOutcome::OriginRejected;
    }

    // 2. Content-Type check. Requiring `application/json` forces any browser
    // cross-origin POST into a CORS preflight, which the proxy does not
    // answer — killing the "simple request" bypass.
    if require_json_body {
        let ct = headers.iter().find(|h| header_name_eq(h, "content-type"));
        match ct {
            None => return AuthOutcome::BadContentType,
            Some(h) => {
                let value = header_value_as_str(h);
                let primary = value.split(';').next().unwrap_or("").trim();
                if !primary.eq_ignore_ascii_case("application/json") {
                    return AuthOutcome::BadContentType;
                }
            }
        }
    }

    // 3. Auth check. `X-Proxy-Token` is the dedicated proxy-local auth header
    // and takes precedence: clients targeting upstream APIs (Codex CLI, etc.)
    // already use `Authorization: Bearer <upstream-key>` for the upstream
    // credential, so the proxy must accept its own per-launch token under a
    // distinct header. `Authorization: Bearer <tok>` is supported as a fallback
    // for direct callers that don't carry an upstream credential. A non-Bearer
    // `Authorization` scheme (when used as the sole credential) is a hard
    // reject to avoid ambiguity.
    let auth_hdr = headers.iter().find(|h| header_name_eq(h, "authorization"));
    let x_proxy_hdr = headers.iter().find(|h| header_name_eq(h, "x-proxy-token"));

    let received = if let Some(xt) = x_proxy_hdr {
        header_value_as_str(xt).trim()
    } else if let Some(auth) = auth_hdr {
        let value = header_value_as_str(auth).trim();
        match value.split_once(' ') {
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("Bearer") => rest.trim(),
            _ => return AuthOutcome::Unauthorized,
        }
    } else {
        return AuthOutcome::Unauthorized;
    };

    if constant_time_eq(received.as_bytes(), token.as_bytes()) {
        AuthOutcome::Ok
    } else {
        AuthOutcome::Unauthorized
    }
}

fn respond_status(req: Request, status: u16) {
    let _ = req.respond(Response::new_empty(StatusCode(status)));
}

fn handle_shutdown(req: Request, token: &str) {
    match authorize(req.headers(), token, /* require_json_body */ false) {
        AuthOutcome::Ok => {
            let _ = req.respond(Response::new_empty(StatusCode(200)));
            std::process::exit(0);
        }
        AuthOutcome::OriginRejected => respond_status(req, 403),
        AuthOutcome::BadContentType => respond_status(req, 415),
        AuthOutcome::Unauthorized => respond_status(req, 401),
    }
}

fn forward_request(
    client: &Client,
    auth_header: &'static str,
    config: &ForwardConfig,
    dump_dir: Option<&ExchangeDumper>,
    mut req: Request,
) -> Result<()> {
    // Enforce the auth gate before inspecting method/path so an attacker
    // cannot probe endpoint existence without a valid token. Only require a
    // JSON Content-Type for body-bearing POSTs; non-POST methods will be
    // rejected with 403 by the method/path check below.
    let require_json_body = req.method() == &Method::Post;
    match authorize(req.headers(), &config.auth_token, require_json_body) {
        AuthOutcome::Ok => {}
        AuthOutcome::OriginRejected => {
            respond_status(req, 403);
            return Ok(());
        }
        AuthOutcome::BadContentType => {
            respond_status(req, 415);
            return Ok(());
        }
        AuthOutcome::Unauthorized => {
            respond_status(req, 401);
            return Ok(());
        }
    }

    // Only allow POST /v1/responses exactly, no query string.
    let method = req.method().clone();
    let url_path = req.url().to_string();
    let allow = method == Method::Post && url_path == "/v1/responses";

    if !allow {
        let resp = Response::new_empty(StatusCode(403));
        let _ = req.respond(resp);
        return Ok(());
    }

    // Read request body
    let mut body = Vec::new();
    let reader = req.as_reader();
    reader.read_to_end(&mut body)?;

    let exchange_dump = dump_dir.and_then(|dump_dir| {
        dump_dir
            .dump_request(&method, &url_path, req.headers(), &body)
            .map_err(|err| {
                eprintln!("responses-api-proxy failed to dump request: {err}");
                err
            })
            .ok()
    });

    // Build headers for upstream, forwarding everything from the incoming
    // request except Authorization and X-Proxy-Token (proxy-local auth
    // material that must never leak upstream) and Host (we override it).
    let mut headers = HeaderMap::new();
    for header in req.headers() {
        let name_ascii = header.field.as_str();
        let lower = name_ascii.to_ascii_lowercase();
        let lower_str = lower.as_str();
        if lower_str == "authorization" || lower_str == "host" || lower_str == "x-proxy-token" {
            continue;
        }

        let header_name = match HeaderName::from_bytes(lower.as_bytes()) {
            Ok(name) => name,
            Err(_) => continue,
        };
        if let Ok(value) = HeaderValue::from_bytes(header.value.as_bytes()) {
            headers.append(header_name, value);
        }
    }

    // As part of our effort to to keep `auth_header` secret, we use a
    // combination of `from_static()` and `set_sensitive(true)`.
    let mut auth_header_value = HeaderValue::from_static(auth_header);
    auth_header_value.set_sensitive(true);
    headers.insert(AUTHORIZATION, auth_header_value);

    headers.insert(HOST, config.host_header.clone());

    let upstream_resp = client
        .post(config.upstream_url.clone())
        .headers(headers)
        .body(body)
        .send()
        .context("forwarding request to upstream")?;

    // We have to create an adapter between a `reqwest::blocking::Response`
    // and a `tiny_http::Response`. Fortunately, `reqwest::blocking::Response`
    // implements `Read`, so we can use it directly as the body of the
    // `tiny_http::Response`.
    let status = upstream_resp.status();
    let mut response_headers = Vec::new();
    for (name, value) in upstream_resp.headers().iter() {
        // Skip headers that tiny_http manages itself.
        if matches!(
            name.as_str(),
            "content-length" | "transfer-encoding" | "connection" | "trailer" | "upgrade"
        ) {
            continue;
        }

        if let Ok(header) = Header::from_bytes(name.as_str().as_bytes(), value.as_bytes()) {
            response_headers.push(header);
        }
    }

    let content_length = upstream_resp.content_length().and_then(|len| {
        if len <= usize::MAX as u64 {
            Some(len as usize)
        } else {
            None
        }
    });

    let response_body: Box<dyn Read + Send> = if let Some(exchange_dump) = exchange_dump {
        let headers = upstream_resp.headers().clone();
        Box::new(exchange_dump.tee_response_body(status.as_u16(), &headers, upstream_resp))
    } else {
        Box::new(upstream_resp)
    };

    let response = Response::new(
        StatusCode(status.as_u16()),
        response_headers,
        response_body,
        content_length,
        None,
    );

    let _ = req.respond(response);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header(name: &str, value: &str) -> Header {
        Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("header")
    }

    fn valid_defaults() -> Vec<Header> {
        vec![make_header("Content-Type", "application/json")]
    }

    const TOKEN: &str = "correct-horse-battery-staple";

    #[test]
    fn authorize_accepts_exact_bearer_token() {
        let mut headers = valid_defaults();
        headers.push(make_header("Authorization", &format!("Bearer {TOKEN}")));
        assert_eq!(authorize(&headers, TOKEN, true), AuthOutcome::Ok);
    }

    #[test]
    fn authorize_accepts_x_proxy_token() {
        let mut headers = valid_defaults();
        headers.push(make_header("X-Proxy-Token", TOKEN));
        assert_eq!(authorize(&headers, TOKEN, true), AuthOutcome::Ok);
    }

    #[test]
    fn authorize_rejects_missing_token() {
        let headers = valid_defaults();
        assert_eq!(authorize(&headers, TOKEN, true), AuthOutcome::Unauthorized);
    }

    #[test]
    fn authorize_rejects_wrong_token() {
        let mut headers = valid_defaults();
        headers.push(make_header("Authorization", "Bearer nope"));
        assert_eq!(authorize(&headers, TOKEN, true), AuthOutcome::Unauthorized);
    }

    #[test]
    fn authorize_rejects_origin_header_even_with_valid_token() {
        let mut headers = valid_defaults();
        headers.push(make_header("Authorization", &format!("Bearer {TOKEN}")));
        headers.push(make_header("Origin", "https://evil.example"));
        assert_eq!(
            authorize(&headers, TOKEN, true),
            AuthOutcome::OriginRejected
        );
    }

    #[test]
    fn authorize_rejects_non_json_content_type() {
        let headers = vec![
            make_header("Content-Type", "text/plain"),
            make_header("Authorization", &format!("Bearer {TOKEN}")),
        ];
        assert_eq!(authorize(&headers, TOKEN, true), AuthOutcome::BadContentType);
    }

    #[test]
    fn authorize_accepts_application_json_with_charset() {
        let headers = vec![
            make_header("Content-Type", "application/json; charset=utf-8"),
            make_header("Authorization", &format!("Bearer {TOKEN}")),
        ];
        assert_eq!(authorize(&headers, TOKEN, true), AuthOutcome::Ok);
    }

    #[test]
    fn authorize_rejects_non_bearer_authorization_scheme() {
        let headers = vec![
            make_header("Content-Type", "application/json"),
            make_header("Authorization", &format!("Basic {TOKEN}")),
        ];
        assert_eq!(authorize(&headers, TOKEN, true), AuthOutcome::Unauthorized);
    }

    #[test]
    fn authorize_ignores_header_casing() {
        let headers = vec![
            make_header("content-TYPE", "application/json"),
            make_header("authorization", &format!("bearer {TOKEN}")),
        ];
        assert_eq!(authorize(&headers, TOKEN, true), AuthOutcome::Ok);

        let mut with_origin = headers.clone();
        with_origin.push(make_header("ORIGIN", "https://evil.example"));
        assert_eq!(
            authorize(&with_origin, TOKEN, true),
            AuthOutcome::OriginRejected
        );
    }

    #[test]
    fn authorize_uses_constant_time_eq() {
        // Exercises the `constant_time_eq` path. We cannot assert timing
        // behavior here; we just verify both "equal" and "same-length but
        // different" inputs take the same API path.
        let mut headers = valid_defaults();
        headers.push(make_header("Authorization", &format!("Bearer {TOKEN}")));
        assert_eq!(authorize(&headers, TOKEN, true), AuthOutcome::Ok);

        let wrong_same_len: String = TOKEN.chars().rev().collect();
        let mut headers = valid_defaults();
        headers.push(make_header(
            "Authorization",
            &format!("Bearer {wrong_same_len}"),
        ));
        assert_eq!(authorize(&headers, TOKEN, true), AuthOutcome::Unauthorized);
    }

    #[test]
    fn authorize_shutdown_skips_content_type() {
        let headers = vec![make_header("Authorization", &format!("Bearer {TOKEN}"))];
        assert_eq!(authorize(&headers, TOKEN, false), AuthOutcome::Ok);
    }

    #[test]
    fn generate_auth_token_is_nonempty_and_url_safe() {
        let t = generate_auth_token().expect("generate token");
        assert!(!t.is_empty());
        assert!(
            t.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        );
        // 32 bytes base64url-encoded (no pad) is 43 characters.
        assert_eq!(t.len(), 43);
    }

    #[cfg(unix)]
    #[test]
    fn write_server_info_creates_file_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server-info.json");
        let info = ServerInfo {
            port: 12345,
            pid: 99,
            auth_token: "abc".to_string(),
        };
        write_server_info(&path, &info).expect("write");
        let md = fs::metadata(&path).expect("metadata");
        assert_eq!(md.permissions().mode() & 0o777, 0o600);
        let s = fs::read_to_string(&path).expect("read");
        let v: serde_json::Value = serde_json::from_str(s.trim()).expect("json");
        assert_eq!(v.get("auth_token").and_then(|v| v.as_str()), Some("abc"));
        assert_eq!(v.get("port").and_then(|v| v.as_u64()), Some(12345));
    }

    #[cfg(unix)]
    #[test]
    fn write_server_info_refuses_existing_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target.txt");
        fs::write(&target, b"").expect("write target");
        let link = dir.path().join("server-info.json");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let info = ServerInfo {
            port: 1,
            pid: 1,
            auth_token: "x".to_string(),
        };
        let err = write_server_info(&link, &info).expect_err("should refuse symlink");
        let msg = format!("{err:#}");
        assert!(msg.contains("symlink"), "unexpected error: {msg}");
    }

    #[cfg(unix)]
    #[test]
    fn write_server_info_refuses_world_readable_existing_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server-info.json");
        fs::write(&path, b"old").expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        let info = ServerInfo {
            port: 1,
            pid: 1,
            auth_token: "x".to_string(),
        };
        let err = write_server_info(&path, &info).expect_err("should refuse loose mode");
        let msg = format!("{err:#}");
        assert!(msg.contains("insecure permissions"), "unexpected: {msg}");
    }

    #[cfg(unix)]
    #[test]
    fn write_server_info_overwrites_existing_secure_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("server-info.json");
        fs::write(&path, b"old").expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        let info = ServerInfo {
            port: 42,
            pid: 7,
            auth_token: "new".to_string(),
        };
        write_server_info(&path, &info).expect("overwrite");
        let md = fs::metadata(&path).expect("metadata");
        assert_eq!(md.permissions().mode() & 0o777, 0o600);
        let s = fs::read_to_string(&path).expect("read");
        assert!(s.contains("\"auth_token\":\"new\""), "got: {s}");
    }
}
