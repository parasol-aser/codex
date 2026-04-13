# codex-responses-api-proxy

A strict HTTP proxy that only forwards `POST` requests to `/v1/responses` to the OpenAI API (`https://api.openai.com`), injecting the `Authorization: Bearer $OPENAI_API_KEY` header. Callers must authenticate with the proxy's per-launch `auth_token` (any request without it is rejected with `401`), must not carry an `Origin` header (any such request is rejected with `403` — this kills browser CSRF), and must send `Content-Type: application/json` (non-JSON is rejected with `415`). Everything else is rejected with `403 Forbidden`.

## Expected Usage

**IMPORTANT:** `codex-responses-api-proxy` is designed to be run by a privileged user with access to `OPENAI_API_KEY` so that an unprivileged user cannot inspect or tamper with the process. When `--http-shutdown` is specified, any process that can read `server-info.json` (and therefore the `auth_token`) may call `GET /shutdown` to terminate the server; without the token, shutdown requests are rejected.

A privileged user (i.e., `root` or a user with `sudo`) who has access to `OPENAI_API_KEY` would run the following to start the server, as `codex-responses-api-proxy` reads the auth token from `stdin`:

```shell
printenv OPENAI_API_KEY | env -u OPENAI_API_KEY codex-responses-api-proxy --http-shutdown --server-info /tmp/server-info.json
```

A non-privileged user would then run Codex as follows, specifying the `model_provider` dynamically. The client must forward the proxy's per-launch token (read from `server-info.json`) under either `Authorization: Bearer <auth_token>` or `X-Proxy-Token: <auth_token>`:

```shell
PROXY_PORT=$(jq -r .port /tmp/server-info.json)
PROXY_TOKEN=$(jq -r .auth_token /tmp/server-info.json)
PROXY_BASE_URL="http://127.0.0.1:${PROXY_PORT}"
codex exec \
    -c "model_providers.openai-proxy={ name = 'OpenAI Proxy', base_url = '${PROXY_BASE_URL}/v1', wire_api='responses', http_headers = { \"X-Proxy-Token\" = \"${PROXY_TOKEN}\" } }" \
    -c model_provider="openai-proxy" \
    'Your prompt here'
```

When the unprivileged user was finished, they could shutdown the server using `curl` (since `kill -SIGTERM` is not an option). The shutdown endpoint also requires the per-launch token:

```shell
curl --fail --silent --show-error --header "X-Proxy-Token: ${PROXY_TOKEN}" "${PROXY_BASE_URL}/shutdown"
```

## Behavior

- Reads the API key from `stdin`. All callers should pipe the key in (for example, `printenv OPENAI_API_KEY | codex-responses-api-proxy`).
- Formats the header value as `Bearer <key>` and attempts to `mlock(2)` the memory holding that header so it is not swapped to disk.
- Generates a fresh 256-bit `auth_token` at startup. Every inbound request (both `/v1/responses` and `/shutdown`) must carry this token in `Authorization: Bearer <auth_token>` or `X-Proxy-Token: <auth_token>`. Comparisons are constant-time. Requests missing or carrying a wrong token receive `401`.
- Refuses any request that carries an `Origin` header (browser-sourced), returning `403`.
- Requires `Content-Type: application/json` on body-bearing requests; otherwise returns `415`. This forces cross-origin browser POSTs through a CORS preflight, which the proxy does not satisfy.
- Listens on the provided port or an ephemeral port if `--port` is not specified.
- Accepts exactly `POST /v1/responses` (no query string). The request body is forwarded to `https://api.openai.com/v1/responses` with `Authorization: Bearer <key>` set. All original request headers (except any incoming `Authorization` and `X-Proxy-Token`) are forwarded upstream, with `Host` overridden to `api.openai.com`. For other requests, it responds with `403`.
- Optionally writes a single-line JSON file with server info: `{ "port": <u16>, "pid": <u32>, "auth_token": <string> }`. On Unix the file is created with mode `0600`; the proxy refuses to follow a pre-existing symlink or overwrite a pre-existing file whose permissions are looser than `0600`. On Windows the file is created with default ACLs.
- If `--server-info` is omitted, the proxy prints `responses-api-proxy auth_token=<TOKEN>` to stderr once at startup so an operator running the proxy manually can still authenticate clients.
- Optionally writes request/response JSON dumps to a directory. Each accepted request gets a pair of files that share a sequence/timestamp prefix, for example `000001-1846179912345-request.json` and `000001-1846179912345-response.json`. Header values are dumped in full except `Authorization`, `X-Proxy-Token`, and any header whose name includes `cookie`, which are redacted. Bodies are written as parsed JSON when possible, otherwise as UTF-8 text.
- Optional `--http-shutdown` enables `GET /shutdown` to terminate the process with exit code `0`. The shutdown endpoint requires the same `auth_token` as the forwarding endpoint and also rejects any request carrying an `Origin` header, so a malicious web page cannot DoS the proxy.

## CLI

```
codex-responses-api-proxy [--port <PORT>] [--server-info <FILE>] [--http-shutdown] [--upstream-url <URL>] [--dump-dir <DIR>]
```

- `--port <PORT>`: Port to bind on `127.0.0.1`. If omitted, an ephemeral port is chosen.
- `--server-info <FILE>`: If set, the proxy writes a single line of JSON with `{ "port": <PORT>, "pid": <PID>, "auth_token": <string> }` once listening. On Unix the file is created with mode `0600`.
- `--http-shutdown`: If set, enables `GET /shutdown` to exit the process with code `0`. Requires the per-launch `auth_token`.
- `--upstream-url <URL>`: Absolute URL to forward requests to. Defaults to `https://api.openai.com/v1/responses`.
- `--dump-dir <DIR>`: If set, writes one request JSON file and one response JSON file per accepted proxy call under this directory. Filenames use a shared sequence/timestamp prefix so each pair is easy to correlate.
- Upstream authentication is fixed to `Authorization: Bearer <key>` to match the Codex CLI expectations. Proxy-local authentication uses the per-launch `auth_token` (`X-Proxy-Token` takes precedence over `Authorization: Bearer` when both are present, since `Authorization` is reserved for the upstream credential and is stripped before forwarding).

For Azure, for example (ensure your deployment accepts `Authorization: Bearer <key>`):

```shell
printenv AZURE_OPENAI_API_KEY | env -u AZURE_OPENAI_API_KEY codex-responses-api-proxy \
  --http-shutdown \
  --server-info /tmp/server-info.json \
  --upstream-url "https://YOUR_PROJECT_NAME.openai.azure.com/openai/deployments/YOUR_DEPLOYMENT/responses?api-version=2025-04-01-preview"
```

## Notes

- Only `POST /v1/responses` is permitted. No query strings are allowed.
- All request headers are forwarded to the upstream call (aside from overriding `Authorization`, stripping `X-Proxy-Token`, and overriding `Host`). Response status and content-type are mirrored from upstream.
- No `Access-Control-Allow-Origin` headers are emitted and the proxy returns `403` for `OPTIONS` preflight. This means browsers cannot read proxy responses and any cross-origin POST requiring a preflight will fail before it reaches the auth gate.

## Hardening Details

Care is taken to restrict access/copying to the value of `OPENAI_API_KEY` retained in memory:

- We leverage [`codex_process_hardening`](https://github.com/openai/codex/blob/main/codex-rs/process-hardening/README.md) so `codex-responses-api-proxy` is run with standard process-hardening techniques.
- At startup, we allocate a `1024` byte buffer on the stack and copy `"Bearer "` into the start of the buffer.
- We then read from `stdin`, copying the contents into the buffer after `"Bearer "`.
- After verifying the key matches `/^[a-zA-Z0-9_-]+$/` (and does not exceed the buffer), we create a `String` from that buffer (so the data is now on the heap).
- We zero out the stack-allocated buffer using https://crates.io/crates/zeroize so it is not optimized away by the compiler.
- We invoke `.leak()` on the `String` so we can treat its contents as a `&'static str`, as it will live for the rest of the process.
- On UNIX, we `mlock(2)` the memory backing the `&'static str`.
- When using the `&'static str` when building an HTTP request, we use `HeaderValue::from_static()` to avoid copying the `&str`.
- We also invoke `.set_sensitive(true)` on the `HeaderValue`, which in theory indicates to other parts of the HTTP stack that the header should be treated with "special care" to avoid leakage:

https://github.com/hyperium/http/blob/439d1c50d71e3be3204b6c4a1bf2255ed78e1f93/src/header/value.rs#L346-L376
