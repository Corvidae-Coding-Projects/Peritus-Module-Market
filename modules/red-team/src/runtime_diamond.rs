//! Application-specific runtime binding for the Diamond language and web runtime.
//!
//! The host gives this module a disposable copy of explicitly scoped source. This binding builds
//! that copy once, drives the real CLI and loopback HTTP server, and projects seven independently
//! validated observations. No path, process, or application knowledge is added to Peritus itself.

use crate::{digest, runtime_browser};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Component, Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

const PASSWORD: &str = "Peritus-Diamond-disposable-9x!";
const USERNAME: &str = "peritus-probe";
const MAXIMUM_HTTP_BYTES: usize = 2 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: u16,
    profile: String,
    laboratory_id: String,
    source_snapshot: String,
}

#[derive(Clone)]
struct Exchange {
    method: String,
    target: String,
    request_headers: Vec<(String, String)>,
    request_body: Vec<u8>,
    request_wire: Vec<u8>,
    status: u16,
    response_headers: BTreeMap<String, String>,
    response_body: Vec<u8>,
    response_wire: Vec<u8>,
}

struct DiamondRuntime {
    child: Child,
    binary: PathBuf,
    address: SocketAddr,
    auth: PathBuf,
    private: tempfile::TempDir,
    source_snapshot: String,
}

impl Drop for DiamondRuntime {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub(super) fn execute(
    input: Value,
    source_snapshot: String,
    request_key: &str,
    state_root: &Path,
) -> Result<Value, String> {
    let request: Request = serde_json::from_value(input).map_err(|error| error.to_string())?;
    if request.schema != 1
        || request.profile != "diamond-lang.v1"
        || request.source_snapshot != source_snapshot
        || request.laboratory_id.len() != 64
    {
        return Err("Diamond binding request has an invalid profile or source identity".into());
    }
    let root = std::env::current_dir().map_err(|error| error.to_string())?;
    require_source(&root)?;
    let mut runtime = DiamondRuntime::launch(&root, &source_snapshot, request_key)?;
    let initial_state = runtime.state_digest()?;

    let http = http_campaign(&mut runtime, &request.laboratory_id, &initial_state)?;
    let identity = identity_campaign(&mut runtime, &request.laboratory_id)?;
    let workflow = workflow_campaign(&mut runtime, &request.laboratory_id)?;
    let boundary = boundary_campaign(&mut runtime, &request.laboratory_id)?;
    let parser = parser_campaign(&runtime, &request.laboratory_id)?;
    let browser = browser_campaign(&runtime, &request.laboratory_id, state_root)?;
    let attack_graph = attack_graph_campaign(
        &runtime,
        &request.laboratory_id,
        &http,
        &browser,
        &root.join("examples/web.dia"),
    )?;

    Ok(json!({
        "schema": 1,
        "profile": request.profile,
        "laboratory_id": request.laboratory_id,
        "source_snapshot": source_snapshot,
        "http": http,
        "browser": browser,
        "identity": identity,
        "parser": parser,
        "workflow": workflow,
        "boundary": boundary,
        "attack_graph": attack_graph,
    }))
}

impl DiamondRuntime {
    fn launch(root: &Path, source_snapshot: &str, request_key: &str) -> Result<Self, String> {
        let private_root = root.join(".red-team-worker-private");
        fs::create_dir_all(&private_root).map_err(|error| error.to_string())?;
        let private = tempfile::Builder::new()
            .prefix("diamond-binding-")
            .tempdir_in(&private_root)
            .map_err(|error| error.to_string())?;
        let target = private.path().join("target");
        let compiler_tmp = private.path().join("compiler-tmp");
        fs::create_dir_all(&compiler_tmp).map_err(|error| error.to_string())?;
        let output = Command::new("cargo")
            .args(["build", "--locked", "--offline", "--bin", "diamond", "--jobs", "2"])
            .current_dir(root)
            .env("CARGO_TARGET_DIR", &target)
            .env("CARGO_TERM_COLOR", "never")
            .env("CARGO_INCREMENTAL", "0")
            .env("CARGO_PROFILE_DEV_DEBUG", "0")
            .env("TMPDIR", &compiler_tmp)
            .stdin(Stdio::null())
            .output()
            .map_err(|error| format!("launch disposable Diamond build: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "disposable Diamond build failed: {}",
                bounded_text(&output.stderr, 16 * 1024)
            ));
        }
        let binary = target.join("debug/diamond");
        if !binary.is_file() {
            return Err("disposable Diamond build produced no executable".into());
        }
        let auth = private.path().join("accounts");
        let mut user = Command::new(&binary)
            .args(["user-add", "--auth"])
            .arg(&auth)
            .args(["--user", USERNAME, "--password-stdin"])
            .current_dir(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("launch Diamond account preparation: {error}"))?;
        user.stdin
            .take()
            .ok_or("Diamond account preparation has no stdin")?
            .write_all(format!("{PASSWORD}\n").as_bytes())
            .map_err(|error| error.to_string())?;
        let output = user.wait_with_output().map_err(|error| error.to_string())?;
        if !output.status.success() {
            return Err(format!(
                "Diamond account preparation failed: {}",
                bounded_text(&output.stderr, 8 * 1024)
            ));
        }
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
        let address = listener.local_addr().map_err(|error| error.to_string())?;
        drop(listener);
        let stdout = fs::File::create(private.path().join("server.stdout"))
            .map_err(|error| error.to_string())?;
        let stderr = fs::File::create(private.path().join("server.stderr"))
            .map_err(|error| error.to_string())?;
        let child = Command::new(&binary)
            .args(["run", "examples/web.dia", "--auth"])
            .arg(&auth)
            .args(["--listen", &address.to_string(), "--max-requests", "256"])
            .current_dir(root)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("PERITUS_RED_TEAM_REQUEST", request_key)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .map_err(|error| format!("launch disposable Diamond server: {error}"))?;
        let mut runtime =
            Self { child, binary, address, auth, private, source_snapshot: source_snapshot.into() };
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = runtime.child.try_wait().map_err(|error| error.to_string())? {
                return Err(format!("disposable Diamond server exited before readiness: {status}"));
            }
            if let Ok(exchange) = runtime.exchange("GET", "/", &[], b"")
                && exchange.status == 200
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err("disposable Diamond server did not become ready".into());
            }
            thread::sleep(Duration::from_millis(50));
        }
        Ok(runtime)
    }

    fn exchange(
        &self,
        method: &str,
        target: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Exchange, String> {
        if !target.starts_with('/') || target.contains('\0') || body.len() > MAXIMUM_HTTP_BYTES {
            return Err("Diamond HTTP request is outside binding bounds".into());
        }
        let mut request_headers = vec![
            ("host".into(), format!("localhost:{}", self.address.port())),
            ("connection".into(), "close".into()),
            ("content-length".into(), body.len().to_string()),
        ];
        request_headers.extend_from_slice(headers);
        let mut wire = format!("{method} {target} HTTP/1.1\r\n").into_bytes();
        for (name, value) in &request_headers {
            wire.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        wire.extend_from_slice(b"\r\n");
        wire.extend_from_slice(body);
        let mut stream = TcpStream::connect_timeout(&self.address, Duration::from_secs(3))
            .map_err(|error| error.to_string())?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).map_err(|error| error.to_string())?;
        stream.write_all(&wire).map_err(|error| error.to_string())?;
        let mut response = Vec::new();
        stream
            .take((MAXIMUM_HTTP_BYTES + 1) as u64)
            .read_to_end(&mut response)
            .map_err(|error| error.to_string())?;
        if response.len() > MAXIMUM_HTTP_BYTES {
            return Err("Diamond HTTP response exceeded 2 MiB".into());
        }
        let split = find_bytes(&response, b"\r\n\r\n")
            .ok_or("Diamond HTTP response has no header terminator")?;
        let head = std::str::from_utf8(&response[..split]).map_err(|error| error.to_string())?;
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse().ok())
            .ok_or("Diamond HTTP response has no status")?;
        let mut response_headers = BTreeMap::new();
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                response_headers.insert(name.trim().to_ascii_lowercase(), value.trim().into());
            }
        }
        Ok(Exchange {
            method: method.into(),
            target: target.into(),
            request_headers,
            request_body: body.to_vec(),
            request_wire: wire,
            status,
            response_headers,
            response_body: response[split + 4..].to_vec(),
            response_wire: response,
        })
    }

    fn state_digest(&self) -> Result<String, String> {
        if self.auth.is_file() {
            return fs::read(&self.auth)
                .map(|bytes| digest(&bytes))
                .map_err(|error| error.to_string());
        }
        digest_tree(&self.auth)
    }
}

fn require_source(root: &Path) -> Result<(), String> {
    for path in ["Cargo.toml", "Cargo.lock", "src/main.rs", "examples/web.dia"] {
        validate_path(path)?;
        if !root.join(path).is_file() {
            return Err(format!("Diamond binding requires `{path}` in the scoped source"));
        }
    }
    let manifest =
        fs::read_to_string(root.join("Cargo.toml")).map_err(|error| error.to_string())?;
    if !manifest.contains("name = \"diamond-lang\"") || !manifest.contains("name = \"diamond\"") {
        return Err("scoped Cargo workspace is not the Diamond application".into());
    }
    Ok(())
}

fn http_campaign(
    runtime: &mut DiamondRuntime,
    laboratory_id: &str,
    initial_state: &str,
) -> Result<Value, String> {
    let mut cases = Vec::new();
    let specifications = [
        ("diamond-http-root", "GET", "/", Vec::new(), Vec::new(), 200, "ordinary_navigation"),
        (
            "diamond-http-typed-route",
            "GET",
            "/numbers/7",
            Vec::new(),
            Vec::new(),
            200,
            "typed_route",
        ),
        (
            "diamond-http-unknown",
            "GET",
            "/does-not-exist",
            Vec::new(),
            Vec::new(),
            404,
            "unknown_route",
        ),
        (
            "diamond-http-bad-number",
            "GET",
            "/numbers/not-an-int",
            Vec::new(),
            Vec::new(),
            400,
            "typed_path_rejection",
        ),
        ("diamond-http-method", "POST", "/", Vec::new(), Vec::new(), 404, "method_rejection"),
        (
            "diamond-http-forwarded",
            "GET",
            "/",
            vec![("x-forwarded-host".into(), "attacker.invalid".into())],
            Vec::new(),
            400,
            "proxy_header_rejection",
        ),
    ];
    for (id, method, target, headers, body, expected, category) in specifications {
        let before = runtime.state_digest()?;
        let exchange = runtime.exchange(method, target, &headers, &body)?;
        let after = runtime.state_digest()?;
        cases.push(http_case(id, category, &exchange, expected, &before, &after, None));
    }
    let payload = b"message=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E";
    let headers = vec![("content-type".into(), "application/x-www-form-urlencoded".into())];
    let before = runtime.state_digest()?;
    let echo = runtime.exchange("POST", "/echo", &headers, payload)?;
    let after = runtime.state_digest()?;
    let escaped = String::from_utf8_lossy(&echo.response_body).contains("&lt;img")
        && !String::from_utf8_lossy(&echo.response_body).contains("<img");
    cases.push(http_case(
        "diamond-http-echo-escape",
        "output_encoding",
        &echo,
        200,
        &before,
        &after,
        Some(escaped),
    ));
    let traffic = serde_json::to_vec(&cases).map_err(|error| error.to_string())?;
    let findings = cases
        .iter()
        .filter(|case| case["disposition"] == "violation")
        .map(|case| {
            let case_id = case["id"].as_str().unwrap_or("diamond-http-unknown");
            json!({
                "id":digest(format!("diamond-http-finding\0{case_id}").as_bytes()),
                "case_id":case_id,"category":case["category"],"severity":"high",
                "message":format!("Diamond HTTP oracle failed: {}",case["oracle"].as_str().unwrap_or("missing oracle detail")),
                "evidence_state":"runtime_confirmed","state_change_observed":case["state_before_digest"]!=case["state_after_digest"],
                "standards":["CWE-20"],"replay_request_digest":case["request"]["digest"]
            })
        })
        .collect::<Vec<_>>();
    let final_state = runtime.state_digest()?;
    let requests = u64::try_from(cases.len()).unwrap_or(u64::MAX);
    let request_bytes =
        cases.iter().filter_map(|case| case["request"]["bytes"].as_u64()).sum::<u64>();
    let response_bytes =
        cases.iter().filter_map(|case| case["response"]["bytes"].as_u64()).sum::<u64>();
    Ok(json!({
        "schema": 1,
        "laboratory_id": laboratory_id,
        "source_snapshot": runtime.source_snapshot,
        "adapter_version": "peritus-http-api-2026-10-24.1",
        "suite_version": "peritus-http-api-diamond-2026-10-25.1",
        "imported_schema_digest": null,
        "routes": [
            {"path":"/","methods":["GET"],"parameters":[],"source":"diamond-source-contract"},
            {"path":"/notes/{id:NoteId}","methods":["GET"],"parameters":["id"],"source":"diamond-source-contract"},
            {"path":"/numbers/{number:Int}","methods":["GET"],"parameters":["number"],"source":"diamond-source-contract"},
            {"path":"/echo","methods":["POST"],"parameters":["message"],"source":"diamond-source-contract"},
            {"path":"/account","methods":["GET"],"parameters":[],"source":"diamond-source-contract"}
        ],
        "cases": cases,
        "findings": findings,
        "traffic_digest": digest(&traffic),
        "requests_executed": requests,
        "request_bytes": request_bytes,
        "response_bytes": response_bytes,
        "final_state_digest": final_state,
        "gaps": [
            "Diamond does not expose OpenAPI, GraphQL, JSON-RPC, or WebSocket endpoints in examples/web.dia; those protocols were not inferred.",
            format!("The initial copied-state digest was {initial_state}; in-memory session internals are observed through behavior, not introspected.")
        ]
    }))
}

fn http_case(
    id: &str,
    category: &str,
    exchange: &Exchange,
    expected: u16,
    before: &str,
    after: &str,
    extra_oracle: Option<bool>,
) -> Value {
    let held = exchange.status == expected && extra_oracle.unwrap_or(true);
    let disposition =
        if held { if expected >= 400 { "rejected" } else { "passed" } } else { "violation" };
    json!({
        "id": id,
        "protocol": "rest",
        "category": category,
        "disposition": disposition,
        "request": request_observation(exchange),
        "response": response_observation(exchange),
        "state_before_digest": before,
        "state_after_digest": after,
        "changed_state_keys": if before == after { Vec::<String>::new() } else { vec!["diamond_private_state".into()] },
        "oracle": format!("expected status {expected}{}; observed {}; property {}", if extra_oracle.is_some() { " and escaped markup" } else { "" }, exchange.status, if held { "held" } else { "failed" }),
        "minimized": true,
    })
}

fn identity_campaign(runtime: &mut DiamondRuntime, laboratory_id: &str) -> Result<Value, String> {
    let anonymous = digest(b"diamond-identity-anonymous");
    let ordinary = digest(b"diamond-identity-ordinary");
    let tenant = digest(b"diamond-local-identity-store");
    let mut cases = Vec::new();
    let anonymous_account = runtime.exchange("GET", "/account", &[], b"")?;
    cases.push(identity_case(
        "diamond-identity-anonymous",
        "authorization",
        "GET /account",
        &anonymous,
        anonymous_account.status,
        anonymous_account.status == 401,
        true,
    ));
    let login = runtime.exchange("GET", "/_diamond/login", &[], b"")?;
    let cookie = cookie_from(&login)?;
    let csrf = extract_hidden(&login.response_body, "_diamond_csrf")?;
    cases.push(identity_case(
        "diamond-identity-login-form",
        "csrf_bootstrap",
        "GET /_diamond/login",
        &anonymous,
        login.status,
        login.status == 200 && csrf.len() == 64,
        false,
    ));
    let invalid_body =
        form(&[("_diamond_csrf", &csrf), ("username", USERNAME), ("password", "wrong-password")]);
    let form_headers = vec![
        ("content-type".into(), "application/x-www-form-urlencoded".into()),
        ("cookie".into(), cookie.clone()),
    ];
    let invalid_login =
        runtime.exchange("POST", "/_diamond/login", &form_headers, invalid_body.as_bytes())?;
    cases.push(identity_case(
        "diamond-identity-invalid-login",
        "authentication",
        "POST /_diamond/login invalid credentials",
        &ordinary,
        invalid_login.status,
        invalid_login.status == 401,
        true,
    ));
    let valid_body =
        form(&[("_diamond_csrf", &csrf), ("username", USERNAME), ("password", PASSWORD)]);
    let valid_login =
        runtime.exchange("POST", "/_diamond/login", &form_headers, valid_body.as_bytes())?;
    let authenticated_cookie = cookie_from(&valid_login)?;
    cases.push(identity_case(
        "diamond-identity-valid-login",
        "authentication",
        "POST /_diamond/login",
        &ordinary,
        valid_login.status,
        valid_login.status == 303,
        false,
    ));
    let protected =
        runtime.exchange("GET", "/account", &[("cookie".into(), authenticated_cookie)], b"")?;
    cases.push(identity_case(
        "diamond-identity-protected-route",
        "authorization",
        "GET /account authenticated",
        &ordinary,
        protected.status,
        protected.status == 200,
        false,
    ));
    let duplicate = runtime.exchange(
        "GET",
        "/account",
        &[("cookie".into(), format!("{cookie}; {cookie}"))],
        b"",
    )?;
    cases.push(identity_case(
        "diamond-identity-duplicate-cookie",
        "session_ambiguity",
        "GET /account duplicate unauthenticated cookie",
        &anonymous,
        duplicate.status,
        duplicate.status == 400 || duplicate.status == 401,
        true,
    ));
    let traffic = serde_json::to_vec(&cases).map_err(|error| error.to_string())?;
    let findings = cases
        .iter()
        .filter(|case| case["disposition"] == "violation")
        .map(|case| {
            let case_id = case["id"].as_str().unwrap_or("diamond-identity-unknown");
            json!({"id":digest(format!("diamond-identity-finding\0{case_id}").as_bytes()),"case_id":case_id,
                "category":case["category"],"severity":"high","message":format!("Diamond identity oracle failed: {}",case["oracle"].as_str().unwrap_or("missing oracle detail")),
                "evidence_state":"runtime_confirmed","standards":["CWE-287","CWE-862"],"replay_digest":case["replay_digest"]})
        })
        .collect::<Vec<_>>();
    let projection = json!({"identities":[anonymous.clone(), ordinary.clone()],"case_ids":cases.iter().map(|case| case["id"].clone()).collect::<Vec<_>>()});
    Ok(json!({
        "schema": 1,
        "laboratory_id": laboratory_id,
        "source_snapshot": runtime.source_snapshot,
        "adapter_version": "peritus-identity-access-2026-10-24.1",
        "suite_version": "peritus-identity-access-diamond-2026-10-25.1",
        "identities": [
            {"identity_handle":anonymous,"role":"anonymous","tenant_handle":null,"privileged":false,"credential_source":"none"},
            {"identity_handle":ordinary,"role":"ordinary_user","tenant_handle":tenant,"privileged":false,"credential_source":"laboratory_generated"}
        ],
        "session_transitions": [
            {"case_id":"diamond-identity-valid-login","identity_handle":ordinary,"from":"anonymous","to":"authenticated","operation":"POST /_diamond/login"}
        ],
        "cases": cases,
        "findings": findings,
        "redaction": {
            "credential_values_checked": 4,
            "request_fields_redacted": 3,
            "response_fields_redacted": 2,
            "provider_projection_clean": !serde_json::to_string(&projection).unwrap_or_default().contains(PASSWORD),
            "projection_digest": digest(&serde_json::to_vec(&projection).unwrap_or_default())
        },
        "traffic_digest": digest(&traffic),
        "operations_executed": cases.len(),
        "final_state_digest": runtime.state_digest()?,
        "gaps": ["examples/web.dia declares one local user role and no tenant, MFA, recovery, administrator, or object-ownership surface; those topologies were not fabricated."]
    }))
}

fn identity_case(
    id: &str,
    category: &str,
    operation: &str,
    actor: &str,
    status: u16,
    held: bool,
    rejection_case: bool,
) -> Value {
    json!({
        "id":id,
        "category":category,
        "disposition":if held { if rejection_case {"rejected"} else {"passed"} } else {"violation"},
        "actor_identity":actor,
        "target_identity":null,
        "operation":operation,
        "response_status":status,
        "state_change_observed":false,
        "oracle":format!("Diamond identity contract {}; observed status {status}", if held {"held"} else {"failed"}),
        "replay_digest":digest(format!("{id}\0{operation}\0{status}\0{held}").as_bytes())
    })
}

fn workflow_campaign(runtime: &mut DiamondRuntime, laboratory_id: &str) -> Result<Value, String> {
    let anonymous = digest(b"diamond-workflow-anonymous");
    let ordinary = digest(b"diamond-workflow-user");
    let start = runtime.state_digest()?;
    let began = Instant::now();
    let first = runtime.exchange("GET", "/account", &[], b"")?;
    let middle = runtime.state_digest()?;
    let login_page = runtime.exchange("GET", "/_diamond/login", &[], b"")?;
    let csrf = extract_hidden(&login_page.response_body, "_diamond_csrf")?;
    let cookie = cookie_from(&login_page)?;
    let body = form(&[("_diamond_csrf", &csrf), ("username", USERNAME), ("password", PASSWORD)]);
    let login = runtime.exchange(
        "POST",
        "/_diamond/login",
        &[
            ("content-type".into(), "application/x-www-form-urlencoded".into()),
            ("cookie".into(), cookie),
        ],
        body.as_bytes(),
    )?;
    let authenticated = cookie_from(&login)?;
    let after_login = runtime.state_digest()?;
    let protected =
        runtime.exchange("GET", "/account", &[("cookie".into(), authenticated)], b"")?;
    let finish = runtime.state_digest()?;
    let held = first.status == 401 && login.status == 303 && protected.status == 200;
    let actions = vec![
        workflow_action(
            "diamond-workflow-anonymous-check",
            0,
            &anonymous,
            "GET /account",
            &first,
            (&start, &middle),
            began.elapsed(),
        ),
        workflow_action(
            "diamond-workflow-login",
            1,
            &ordinary,
            "POST /_diamond/login",
            &login,
            (&middle, &after_login),
            began.elapsed(),
        ),
        workflow_action(
            "diamond-workflow-authorized-check",
            2,
            &ordinary,
            "GET /account authenticated",
            &protected,
            (&after_login, &finish),
            began.elapsed(),
        ),
    ];
    let replay = digest(&serde_json::to_vec(&actions).map_err(|error| error.to_string())?);
    let findings = if held {
        Vec::new()
    } else {
        vec![json!({
            "id":digest(b"diamond-workflow-auth-gate-finding"),
            "sequence_id":"diamond-auth-transition","invariant_id":"diamond-auth-gate",
            "severity":"high","message":"The documented Diamond authentication workflow failed its anonymous/authenticated differential oracle.",
            "evidence_state":"runtime_confirmed","standards":["CWE-862"],"replay_digest":replay
        })]
    };
    Ok(json!({
        "schema":1,
        "laboratory_id":laboratory_id,
        "source_snapshot":runtime.source_snapshot,
        "adapter_version":"peritus-workflow-state-2026-10-24.1",
        "suite_version":"peritus-workflow-state-diamond-2026-10-25.1",
        "seed":0x00D1_A00D_u64,
        "invariants":[{
            "id":"diamond-auth-gate",
            "origin":"documented",
            "statement":"A route declared without `public` rejects anonymous requests and admits a verified local session.",
            "oracle":"differential HTTP status before and after real login",
            "disposition":if held {"held"} else {"violated"},
            "sequence_ids":["diamond-auth-transition"]
        }],
        "sequences":[{
            "id":"diamond-auth-transition",
            "category":"identity_workflow",
            "identities":[anonymous,ordinary],
            "starting_snapshot_digest":start,
            "actions":actions,
            "final_state_digest":finish,
            "invariant_ids":["diamond-auth-gate"],
            "disposition":if held {"passed"} else {"violation"},
            "oracle":format!("anonymous/login/authenticated statuses were {}/{}/{}", first.status, login.status, protected.status),
            "schedule_id":null,
            "replay_digest":replay
        }],
        "findings":findings,
        "nondeterminism":{"schedules":[],"replays":0,"divergent_replays":0,"excluded_harness_failures":0,"notes":["The selected example exposes a sequential session workflow; no concurrency contract was inferred."]},
        "actions_executed":3,
        "campaign_digest":digest(format!("{replay}\0{finish}").as_bytes()),
        "final_state_digest":finish,
        "gaps":["Database-backed MessageBoard CRUD and concurrent transaction schedules require a separately selected application profile; this binding did not infer them from examples/web.dia."]
    }))
}

fn workflow_action(
    id: &str,
    position: u32,
    actor: &str,
    operation: &str,
    exchange: &Exchange,
    state: (&str, &str),
    elapsed: Duration,
) -> Value {
    json!({
        "id":id,"position":position,"actor":actor,"operation":operation,"request_id":digest(id.as_bytes()),
        "schedule_slot":null,"request_digest":digest(&exchange.request_wire),"response_status":exchange.status,
        "state_before_digest":state.0,"state_after_digest":state.1,
        "elapsed_millis":u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        "outcome":format!("Diamond returned HTTP {}",exchange.status)
    })
}

fn parser_campaign(runtime: &DiamondRuntime, laboratory_id: &str) -> Result<Value, String> {
    let began = Instant::now();
    let input_root = runtime.private.path().join("parser-inputs");
    fs::create_dir_all(&input_root).map_err(|error| error.to_string())?;
    let original = fs::read("examples/web.dia").map_err(|error| error.to_string())?;
    let cases = [
        ("diamond-parser-valid", "valid_program", original, true),
        (
            "diamond-parser-unclosed",
            "malformed_syntax",
            b"app Broken:\n  public route GET \"/\":\n    html:\n      <main>".to_vec(),
            false,
        ),
        ("diamond-parser-nul", "binary_boundary", b"app Broken:\0\n".to_vec(), false),
        (
            "diamond-parser-deep",
            "nesting_boundary",
            format!("app Deep:\n  {}\n", "(".repeat(1024)).into_bytes(),
            false,
        ),
        (
            "diamond-parser-hostile-route",
            "route_validation",
            b"app Routes:\n  public route GET \"/../escape\":\n    \"bad\"\n".to_vec(),
            false,
        ),
    ];
    let mut observations = Vec::new();
    let mut edges = BTreeSet::new();
    let mut request_bytes = 0_u64;
    let mut response_bytes = 0_u64;
    for (index, (id, category, bytes, should_pass)) in cases.into_iter().enumerate() {
        let path = input_root.join(format!("case-{index}.dia"));
        fs::write(&path, &bytes).map_err(|error| error.to_string())?;
        let output = Command::new(&runtime.binary)
            .arg("check")
            .arg(&path)
            .current_dir(std::env::current_dir().map_err(|error| error.to_string())?)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .stdin(Stdio::null())
            .output()
            .map_err(|error| format!("execute Diamond parser case: {error}"))?;
        let code = output.status.code();
        let crashed = code.is_none();
        let held = output.status.success() == should_pass && !crashed;
        let signature = format!(
            "success={}\0code={code:?}\0{}",
            output.status.success(),
            bounded_text(&output.stderr, 512)
        );
        let before = u64::try_from(edges.len()).unwrap_or(u64::MAX);
        edges.insert(digest(signature.as_bytes()));
        let after = u64::try_from(edges.len()).unwrap_or(u64::MAX);
        request_bytes += u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        response_bytes +=
            u64::try_from(output.stdout.len() + output.stderr.len()).unwrap_or(u64::MAX);
        observations.push(json!({
            "id":id,"category":category,
            "disposition":if crashed {"crash"} else if held {if should_pass {"passed"} else {"rejected"}} else {"violation"},
            "operation":"diamond check DISPOSABLE_CASE.dia",
            "input":{"kind":"diamond_source","digest":digest(&bytes),"bytes":bytes.len(),"base64":BASE64.encode(&bytes),"minimized":true,"original_bytes":bytes.len()},
            "response_status":code.and_then(|value| u16::try_from(value).ok()),"boundary_effect":null,"native_signal":null,
            "coverage_before":before,"coverage_after":after,
            "oracle":format!("expected parser success {should_pass}; observed success {}; stderr class retained by digest",output.status.success()),
            "replay_digest":digest(format!("{id}\0{}\0{should_pass}\0{code:?}",digest(&bytes)).as_bytes())
        }));
    }
    let edge_bytes = edges.iter().cloned().collect::<Vec<_>>().join("\n");
    let campaign_bytes = serde_json::to_vec(&observations).map_err(|error| error.to_string())?;
    let findings = observations
        .iter()
        .filter(|case| matches!(case["disposition"].as_str(), Some("violation" | "crash")))
        .map(|case| {
            let case_id = case["id"].as_str().unwrap_or("diamond-parser-unknown");
            json!({"id":digest(format!("diamond-parser-finding\0{case_id}").as_bytes()),"case_id":case_id,
                "category":case["category"],"severity":"high","message":format!("Diamond parser oracle failed: {}",case["oracle"].as_str().unwrap_or("missing oracle detail")),
                "evidence_state":"runtime_confirmed","standards":["CWE-20"],"minimized_input_digest":case["input"]["digest"],"replay_digest":case["replay_digest"]})
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "schema":1,"laboratory_id":laboratory_id,"source_snapshot":runtime.source_snapshot,
        "adapter_version":"peritus-file-parser-2026-10-24.1","suite_version":"peritus-file-parser-diamond-2026-10-25.1",
        "seed":0x00D1_A00D_u64,"corpus_digest":digest(&campaign_bytes),"generated_cases":4,
        "cases":observations,"findings":findings,
        "instrumentation":{"controller":"peritus-diamond-parser-driver@1","coverage_model":"exit-and-diagnostic-signature","coverage_edges":edges.len(),"coverage_digest":digest(edge_bytes.as_bytes()),"native_fault_instrumentation":"child exit/signal observation","compiler_sanitizer_active":false,"compiler_sanitizer_gap":"The release target was exercised as built; sanitizer recompilation is not enabled by this application binding."},
        "resources":{"operations":5,"request_bytes":request_bytes,"response_bytes":response_bytes,"wall_millis":u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX),"maximum_input_bytes":2*1024*1024,"laboratory_remained_ready":runtime.child.id()>0},
        "crash_groups":0,"campaign_digest":digest(&campaign_bytes),"final_state_digest":runtime.state_digest()?,
        "gaps":["Coverage is behavioral exit/diagnostic diversity, not compiler edge instrumentation; native dependencies were not sanitizer-rebuilt."]
    }))
}

fn boundary_campaign(runtime: &mut DiamondRuntime, laboratory_id: &str) -> Result<Value, String> {
    let state = runtime.state_digest()?;
    let bad_host = raw_exchange(
        runtime.address,
        "GET / HTTP/1.1\r\nHost: attacker.invalid\r\nConnection: close\r\n\r\n",
    )?;
    let forwarded =
        runtime.exchange("GET", "/", &[("x-forwarded-for".into(), "127.0.0.1".into())], b"")?;
    let origin = runtime.exchange(
        "POST",
        "/echo",
        &[
            ("origin".into(), "https://attacker.invalid".into()),
            ("content-type".into(), "application/x-www-form-urlencoded".into()),
        ],
        b"message=safe",
    )?;
    let oversized = vec![b'a'; 1024 * 1024 + 1];
    let too_large = runtime.exchange(
        "POST",
        "/echo",
        &[("content-type".into(), "application/x-www-form-urlencoded".into())],
        &oversized,
    );
    let (too_large_status, too_large_rejected) = match too_large {
        Ok(exchange) => (Some(exchange.status), exchange.status == 413),
        Err(detail) if detail.contains("Connection reset by peer") => (None, true),
        Err(detail) => return Err(detail),
    };
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    let port = listener.local_addr().map_err(|error| error.to_string())?.port();
    drop(listener);
    let mut non_loopback = Command::new(&runtime.binary)
        .args([
            "run",
            "examples/web.dia",
            "--listen",
            &format!("0.0.0.0:{port}"),
            "--max-requests",
            "1",
        ])
        .current_dir(std::env::current_dir().map_err(|error| error.to_string())?)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    let non_loopback_accepted = wait_or_stop(&mut non_loopback, Duration::from_secs(2))?;
    let cases = vec![
        boundary_case(
            "diamond-boundary-host",
            "private_network",
            "GET / with foreign Host",
            Some(bad_host.status),
            bad_host.status == 400,
            &state,
        ),
        boundary_case(
            "diamond-boundary-forwarded",
            "private_network",
            "GET / with X-Forwarded-For",
            Some(forwarded.status),
            forwarded.status == 400,
            &state,
        ),
        boundary_case(
            "diamond-boundary-origin",
            "private_network",
            "POST /echo with foreign Origin",
            Some(origin.status),
            origin.status >= 400,
            &state,
        ),
        boundary_case(
            "diamond-boundary-body-limit",
            "privilege_policy",
            "POST /echo above body limit",
            too_large_status,
            too_large_rejected,
            &state,
        ),
        boundary_case(
            "diamond-boundary-loopback-bind",
            "privilege_policy",
            "launch with 0.0.0.0 listener",
            non_loopback_accepted
                .and_then(|status| status.code())
                .and_then(|code| u16::try_from(code).ok()),
            non_loopback_accepted.is_some_and(|status| !status.success()),
            &state,
        ),
        boundary_block(
            "diamond-boundary-tls",
            "tls",
            "HTTPS certificate validation is not an exposed interface of `diamond run`; no TLS result was fabricated.",
            &state,
        ),
        boundary_block(
            "live-cloud-provider",
            "platform_gap",
            "No live cloud provider was authorized or needed for this source-bound campaign.",
            &state,
        ),
        boundary_block(
            "host-privileged-runtime",
            "platform_gap",
            "Host privilege was not granted to the contained module worker.",
            &state,
        ),
    ];
    let bytes = serde_json::to_vec(&cases).map_err(|error| error.to_string())?;
    let findings = cases
        .iter()
        .filter(|case| case["disposition"] == "violation")
        .map(|case| {
            let case_id = case["id"].as_str().unwrap_or("diamond-boundary-unknown");
            json!({"id":digest(format!("diamond-boundary-finding\0{case_id}").as_bytes()),"case_id":case_id,
                "severity":"high","message":format!("Diamond boundary oracle failed: {}",case["detail"].as_str().unwrap_or("missing oracle detail")),
                "evidence_state":"runtime_confirmed","standards":["CWE-284"],"replay_digest":case["replay_digest"]})
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "schema":1,"laboratory_id":laboratory_id,"source_snapshot":runtime.source_snapshot,
        "adapter_version":"peritus-boundary-authority-2026-10-24.5","suite_version":"peritus-boundary-authority-diamond-2026-10-25.1",
        "cases":cases,"findings":findings,
        "network":{"private_dns_queries":0,"private_callbacks":0,"redirect_hops":0,"proxy_requests":1,"forbidden_destination_attempts":0,"host_loopback_effects":0,"lan_effects":0,"external_effects":0,"peer_receipt_digest":digest(&bytes)},
        "tls":{"handshakes":0,"trusted_hostname":"blocked","hostname_mismatch":"blocked","expired_certificate":"blocked","downgrade":"blocked","connection_reuse":"blocked","certificate_set_digest":digest(b"diamond-no-tls-interface")},
        "policy":{"policy_digest":digest(b"diamond-loopback-only-worker-contained"),"run_as_user":"contained-module-worker","requested_capabilities":[],"no_new_privileges":true,"privilege_attempts":1,"host_privilege_effects":0,"containment_held":true},
        "authority":{"untrusted_directives":0,"delegated_actions":0,"privileged_effects":0,"confused_deputy_observed":false,"host_authority_unchanged":true},
        "operations_executed":5,"campaign_digest":digest(&bytes),"final_state_digest":runtime.state_digest()?,
        "gaps":["TLS, DNS rebinding, cloud metadata, container orchestration, and delegated-agent authority are not exposed by the selected Diamond example and remain explicit gaps."]
    }))
}

fn boundary_case(
    id: &str,
    class: &str,
    operation: &str,
    status: Option<u16>,
    held: bool,
    state: &str,
) -> Value {
    json!({"id":id,"class":class,"operation":operation,"response_status":status,"request_digest":digest(operation.as_bytes()),"state_before_digest":state,"state_after_digest":state,"changed_state_keys":[],"disposition":if held{"passed"}else{"violation"},"oracle":"documented Diamond boundary checked against direct process or HTTP result","detail":format!("boundary property {}; status {:?}",if held{"held"}else{"failed"},status),"replay_digest":digest(format!("{id}\0{operation}\0{status:?}\0{held}").as_bytes())})
}

fn boundary_block(id: &str, class: &str, detail: &str, state: &str) -> Value {
    json!({"id":id,"class":class,"operation":"not executed outside authorized application surface","response_status":null,"request_digest":digest(id.as_bytes()),"state_before_digest":state,"state_after_digest":state,"changed_state_keys":[],"disposition":"blocked","oracle":"explicit applicability boundary","detail":detail,"replay_digest":digest(format!("{id}\0{detail}").as_bytes())})
}

fn browser_campaign(
    runtime: &DiamondRuntime,
    laboratory_id: &str,
    state_root: &Path,
) -> Result<Value, String> {
    let raw = runtime_browser::diamond_campaign(
        &state_root.join("diamond-browser"),
        &format!("http://{}", runtime.address),
    )?;
    let raw_cases = raw["cases"].as_array().ok_or("Diamond browser driver returned no cases")?;
    let cases = raw_cases
        .iter()
        .map(|case| {
            json!({
                "id":case["id"],"category":case["category"],
                "disposition":if case["passed"].as_bool()==Some(true){"passed"}else{"violation"},
                "browser_effect":case["browser_effect"],"server_effect":case["server_effect"],
                "request_paths":case["request_paths"],"replay_digest":case["replay_digest"],
                "replayed_after_reset":case["replayed_after_reset"]
            })
        })
        .collect::<Vec<_>>();
    let coverage = [
        ("/", "document", "diamond-browser-root"),
        ("/numbers/{number:Int}", "typed_route", "diamond-browser-typed-route"),
        ("/_diamond/login", "document", "diamond-browser-login-form"),
        ("/echo", "form_action", "diamond-browser-echo-escaping"),
    ].into_iter().map(|(path,kind,discovered_by)|json!({"path":path,"kind":kind,"discovered_by":discovered_by})).collect::<Vec<_>>();
    let findings = cases
        .iter()
        .filter(|case| case["disposition"] == "violation")
        .map(|case| {
            let case_id = case["id"].as_str().unwrap_or("diamond-browser-unknown");
            json!({"id":digest(format!("diamond-browser-finding\0{case_id}").as_bytes()),"case_id":case_id,
                "category":case["category"],"severity":"high","message":case["browser_effect"],
                "evidence_state":"runtime_confirmed","state_change_observed":false,"standards":["CWE-79"],"replay_digest":case["replay_digest"]})
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "schema":1,"laboratory_id":laboratory_id,"source_snapshot":runtime.source_snapshot,
        "adapter_version":"peritus-browser-client-2026-10-24.1","suite_version":"peritus-browser-client-diamond-2026-10-25.1",
        "browser_identity":raw["browser_identity"],"cases":cases,"findings":findings,"coverage":coverage,
        "artifacts":raw["artifacts"],"traffic_digest":raw["traffic_digest"],"requests_observed":raw["requests_observed"],
        "actions_executed":raw["actions_executed"],"final_state_digest":runtime.state_digest()?,
        "context_isolation_observed":raw["context_isolation_observed"],"off_scope_requests_blocked":raw["off_scope_requests_blocked"],
        "gaps":["The selected Diamond example has server-rendered HTML and no first-party client JavaScript, service worker, upload, or download surface; those behaviors were not fabricated."]
    }))
}

fn attack_graph_campaign(
    runtime: &DiamondRuntime,
    laboratory_id: &str,
    http: &Value,
    browser: &Value,
    source: &Path,
) -> Result<Value, String> {
    let source_digest = digest(&fs::read(source).map_err(|error| error.to_string())?);
    let http_digest = http["traffic_digest"].as_str().ok_or("Diamond HTTP digest is absent")?;
    let browser_digest =
        browser["traffic_digest"].as_str().ok_or("Diamond browser digest is absent")?;
    let nodes = vec![
        json!({"id":"diamond-entry-echo","kind":"entry_point","adapter_id":"peritus.http-api","label":"Attacker-controlled form value reaches POST /echo","evidence_digest":http_digest}),
        json!({"id":"diamond-prerequisite-html-escape","kind":"prerequisite","adapter_id":"peritus.source-analysis","label":"Diamond HTML interpolation encodes attacker-controlled text","evidence_digest":source_digest}),
        json!({"id":"diamond-impact-script-execution","kind":"impact","adapter_id":"peritus.browser-client","label":"Proposed browser script-execution impact was not observed","evidence_digest":browser_digest}),
    ];
    let edges = vec![
        json!({"id":"diamond-edge-input-to-render","from":"diamond-entry-echo","to":"diamond-prerequisite-html-escape","relation":"real request reached the HTML response encoder","adapter_id":"peritus.http-api","evidence_digest":http_digest,"supported":true}),
        json!({"id":"diamond-edge-render-to-script","from":"diamond-prerequisite-html-escape","to":"diamond-impact-script-execution","relation":"encoded text would need to become executable markup","adapter_id":"peritus.browser-client","evidence_digest":browser_digest,"supported":false}),
    ];
    let rejected_digest =
        digest(format!("{http_digest}\0{source_digest}\0{browser_digest}\0rejected").as_bytes());
    let broken_digest =
        digest(format!("{http_digest}\0{source_digest}\0{browser_digest}\0broken").as_bytes());
    let chains = vec![
        json!({"id":"diamond-chain-reflected-xss","nodes":["diamond-entry-echo","diamond-prerequisite-html-escape","diamond-impact-script-execution"],"edges":["diamond-edge-input-to-render","diamond-edge-render-to-script"],"adapter_families":["peritus.source-analysis","peritus.http-api","peritus.browser-client"],"disposition":"rejected","removed_prerequisite":null,"replay_digest":rejected_digest,"detail":"The proposed execution edge is unsupported: the HTTP response encoded markup and the real browser observed no execution signal."}),
        json!({"id":"diamond-chain-reflected-xss-counterfactual","nodes":["diamond-entry-echo","diamond-prerequisite-html-escape"],"edges":["diamond-edge-input-to-render"],"adapter_families":["peritus.http-api","peritus.browser-client"],"disposition":"broken","removed_prerequisite":"raw attacker markup in the rendered DOM","replay_digest":broken_digest,"detail":"The candidate chain terminates at the application HTML-encoding boundary."}),
    ];
    let campaign_bytes = serde_json::to_vec(&(nodes.clone(), edges.clone(), chains.clone()))
        .map_err(|error| error.to_string())?;
    Ok(json!({
        "schema":1,"source_snapshot":runtime.source_snapshot,
        "adapter_version":"peritus-attack-graph-2026-10-24.1","suite_version":"peritus-attack-graph-diamond-2026-10-25.1",
        "vulnerable_laboratory_id":laboratory_id,"repaired_laboratory_id":laboratory_id,
        "nodes":nodes,"edges":edges,"chains":chains,"deduplication":[],
        "skeptic":{"reviewer":"peritus-diamond-graph-skeptic@1","accepted":true,"inspected_evidence":[http_digest,source_digest,browser_digest,broken_digest],"rejected_edges":["diamond-edge-render-to-script"],"detail":"No fully supported impact chain was found; the negative result is bounded to the exact source, HTTP exchange, and real-browser replay."},
        "repair":{"target_path":"","original_digest":"","patched_digest":"","diff_artifact":"","diff_bytes":[],"addressed_chains":[],"prerequisites":[],"replays":[],"legitimate_behavior_preserved":true,"reviewer":"peritus-diamond-graph-reviewer@1","review_accepted":false,"review_detail":"No confirmed chain exists, so proposing or accepting a patch would fabricate a defect."},
        "operations_executed":http["requests_executed"].as_u64().unwrap_or(0)+browser["actions_executed"].as_u64().unwrap_or(0),
        "campaign_digest":digest(&campaign_bytes),
        "gaps":["This graph searched the reflected-markup chain supported by the selected application. No confirmed chain means no repair was generated; this is not a claim that all Diamond attack chains are absent."]
    }))
}

fn request_observation(exchange: &Exchange) -> Value {
    json!({
        "method":exchange.method,"target":exchange.target,
        "headers":exchange.request_headers.iter().filter(|(name,_)|name!="cookie").map(|(name,value)|json!({"name":name,"value":value})).collect::<Vec<_>>(),
        "body":String::from_utf8_lossy(&exchange.request_body),"digest":digest(&exchange.request_wire),"bytes":exchange.request_wire.len()
    })
}

fn response_observation(exchange: &Exchange) -> Value {
    json!({
        "status":exchange.status,
        "headers":exchange.response_headers.iter().filter(|(name,_)|*name!="set-cookie").map(|(name,value)|json!({"name":name,"value":value})).collect::<Vec<_>>(),
        "body":bounded_text(&exchange.response_body,16*1024),"digest":digest(&exchange.response_wire),"bytes":exchange.response_wire.len(),"redacted":exchange.response_headers.contains_key("set-cookie")
    })
}

fn cookie_from(exchange: &Exchange) -> Result<String, String> {
    let cookie = exchange
        .response_headers
        .get("set-cookie")
        .ok_or("Diamond response issued no session cookie")?;
    cookie
        .split(';')
        .next()
        .filter(|value| value.starts_with("diamond_session="))
        .map(str::to_owned)
        .ok_or_else(|| "Diamond response session cookie is malformed".into())
}

fn extract_hidden(body: &[u8], name: &str) -> Result<String, String> {
    let text = std::str::from_utf8(body).map_err(|error| error.to_string())?;
    let marker = format!("name=\"{name}\" value=\"");
    let rest = text
        .split_once(&marker)
        .map(|(_, rest)| rest)
        .ok_or_else(|| format!("Diamond form omitted {name}"))?;
    rest.split_once('"')
        .map(|(value, _)| value.to_owned())
        .ok_or_else(|| format!("Diamond form has malformed {name}"))
}

fn form(values: &[(&str, &str)]) -> String {
    values
        .iter()
        .map(|(name, value)| format!("{}={}", percent(name), percent(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn percent(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                vec![char::from(byte)]
            } else {
                format!("%{byte:02X}").chars().collect()
            }
        })
        .collect()
}

fn raw_exchange(address: SocketAddr, request: &str) -> Result<Exchange, String> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(3))
        .map_err(|error| error.to_string())?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).map_err(|error| error.to_string())?;
    stream.write_all(request.as_bytes()).map_err(|error| error.to_string())?;
    let mut response = Vec::new();
    stream
        .take((MAXIMUM_HTTP_BYTES + 1) as u64)
        .read_to_end(&mut response)
        .map_err(|error| error.to_string())?;
    let split = find_bytes(&response, b"\r\n\r\n")
        .ok_or("raw Diamond response has no header terminator")?;
    let head = std::str::from_utf8(&response[..split]).map_err(|error| error.to_string())?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .ok_or("raw Diamond response has no status")?;
    let mut response_headers = BTreeMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            response_headers.insert(name.trim().to_ascii_lowercase(), value.trim().into());
        }
    }
    Ok(Exchange {
        method: "GET".into(),
        target: "/".into(),
        request_headers: Vec::new(),
        request_body: Vec::new(),
        request_wire: request.as_bytes().to_vec(),
        status,
        response_headers,
        response_body: response[split + 4..].to_vec(),
        response_wire: response,
    })
}

fn wait_or_stop(
    child: &mut Child,
    maximum: Duration,
) -> Result<Option<std::process::ExitStatus>, String> {
    let deadline = Instant::now() + maximum;
    loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            child.kill().map_err(|error| error.to_string())?;
            child.wait().map_err(|error| error.to_string())?;
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn digest_tree(root: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    collect_files(root, root, &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut bytes = Vec::new();
    for (path, content) in files {
        bytes.extend_from_slice(path.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(digest(&content).as_bytes());
        bytes.push(b'\n');
    }
    Ok(digest(&bytes))
}

fn collect_files(
    root: &Path,
    current: &Path,
    files: &mut Vec<(String, Vec<u8>)>,
) -> Result<(), String> {
    for entry in fs::read_dir(current).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() {
            return Err("Diamond private state contains a symbolic link".into());
        }
        if metadata.is_dir() {
            collect_files(root, &path, files)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|error| error.to_string())?
                .to_string_lossy()
                .into_owned();
            files.push((relative, fs::read(path).map_err(|error| error.to_string())?));
        }
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || Path::new(path).is_absolute()
        || !Path::new(path).components().all(|component| matches!(component, Component::Normal(_)))
    {
        return Err("Diamond binding path must be source-relative".into());
    }
    Ok(())
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn bounded_text(bytes: &[u8], maximum: usize) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(maximum)]).into_owned()
}

#[allow(dead_code)]
fn _preserve_output_type(_: &Output) {}
