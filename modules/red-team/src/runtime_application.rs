//! Source-bound generic web runtime and the Comms/Bun attack profile.

use crate::{
    application_binding::{ApplicationAttackCase, ApplicationCampaign, ApplicationFinding},
    digest, runtime_browser,
};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const MAXIMUM_HTTP_BYTES: usize = 2 * 1024 * 1024;
const OPERATOR_TOKEN: &str = "peritus-disposable-operator-token";
const BROKER_TOKEN: &str = "peritus-disposable-broker-token-0123456789";
const WEBHOOK_SECRET: &str = "peritus-disposable-webhook-secret";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: u16,
    profile: String,
    laboratory_id: String,
    source_snapshot: String,
    #[serde(default)]
    hypotheses: Vec<Value>,
}

struct Exchange {
    request: Vec<u8>,
    response: Vec<u8>,
    status: u16,
    body: Vec<u8>,
}

struct WebRuntime {
    child: Child,
    address: SocketAddr,
    _private: tempfile::TempDir,
}

impl Drop for WebRuntime {
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
) -> Result<ApplicationCampaign, String> {
    let request: Request = serde_json::from_value(input).map_err(|error| error.to_string())?;
    if request.schema != 1
        || request.source_snapshot != source_snapshot
        || request.laboratory_id.len() != 64
        || request.hypotheses.len() > 256
    {
        return Err("generic application request has an invalid source identity or bound".into());
    }
    let root = env::current_dir().map_err(|error| error.to_string())?;
    let profile = effective_profile(&root, &request.profile)?;
    let entrypoint = require_web_source(&root, &profile)?;
    let (runtime_path, runtime_arguments, runtime_name, preparation) =
        prepare_runtime(&root, &profile)?;
    let mut campaign = ApplicationCampaign {
        schema: 1,
        profile: profile.clone(),
        laboratory_id: request.laboratory_id,
        source_snapshot,
        runtime: runtime_name,
        entrypoint,
        launch_attempted: true,
        ready: false,
        dependency_preparation: preparation,
        cases: Vec::new(),
        browser_cases: Vec::new(),
        findings: Vec::new(),
        operations_executed: 0,
        requests_executed: 0,
        traffic_digest: digest(b"generic-application-launch-pending"),
        final_state_digest: digest(b"generic-application-state-pending"),
        process_cleanup_complete: false,
        off_scope_requests_blocked: 0,
        gaps: Vec::new(),
        surfaces_exercised: Vec::new(),
    };
    let mut runtime =
        match WebRuntime::launch(&root, &runtime_path, &runtime_arguments, &profile, request_key) {
            Ok(runtime) => runtime,
            Err(error) => {
                campaign.gaps.push(format!("real application launch failed: {error}"));
                campaign.traffic_digest = digest(campaign.gaps.join("\n").as_bytes());
                campaign.final_state_digest = directory_digest(&root)?;
                campaign.process_cleanup_complete = true;
                return Ok(campaign);
            }
        };
    campaign.ready = true;
    let initial_state = directory_digest(&root)?;
    let exchanges = if profile == "comms-bun.v1" {
        comms_campaign(&runtime)?
    } else {
        generic_campaign(&root, &runtime)?
    };
    for (case, exchange) in exchanges {
        if case.disposition == "violation" {
            campaign.findings.push(ApplicationFinding {
                id: format!("finding-{}", case.id),
                case_id: case.id.clone(),
                class: case.class.clone(),
                severity: "high".into(),
                message: format!("Runtime oracle failed: {}", case.oracle),
                evidence_state: "runtime_confirmed".into(),
                replay_digest: case.replay_digest.clone(),
            });
        }
        campaign.cases.push(case);
        campaign.requests_executed += 1;
        campaign.operations_executed += 1;
        campaign.traffic_digest = digest(
            format!(
                "{}\0{}\0{}",
                campaign.traffic_digest,
                digest(&exchange.request),
                digest(&exchange.response)
            )
            .as_bytes(),
        );
    }
    match runtime_browser::generic_web_campaign(
        &state_root.join("generic-application-browser"),
        &format!("http://{}", runtime.address),
        &profile,
    ) {
        Ok(value) => {
            let browser_cases: Vec<ApplicationAttackCase> = serde_json::from_value(
                value.get("cases").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
            )
            .map_err(|error| format!("decode browser attack cases: {error}"))?;
            campaign.off_scope_requests_blocked =
                value.get("off_scope_requests_blocked").and_then(Value::as_u64).unwrap_or_default();
            for case in browser_cases {
                if case.disposition == "violation" {
                    campaign.findings.push(ApplicationFinding {
                        id: format!("finding-{}", case.id),
                        case_id: case.id.clone(),
                        class: case.class.clone(),
                        severity: "high".into(),
                        message: format!("Runtime oracle failed: {}", case.oracle),
                        evidence_state: "runtime_confirmed".into(),
                        replay_digest: case.replay_digest.clone(),
                    });
                }
                campaign.operations_executed += 1;
                campaign.browser_cases.push(case);
            }
            if !campaign.browser_cases.is_empty() {
                campaign.surfaces_exercised.push("browser_client".into());
            }
            if let Some(artifacts) = value.get("artifacts_digest").and_then(Value::as_str) {
                campaign.traffic_digest =
                    digest(format!("{}\0{artifacts}", campaign.traffic_digest).as_bytes());
            }
        }
        Err(error) => {
            campaign.gaps.push(format!("real browser campaign could not complete: {error}"))
        }
    }
    campaign.process_cleanup_complete = runtime.shutdown();
    campaign.surfaces_exercised.extend(
        [
            "attack_graph",
            "boundary_authority",
            "file_parser",
            "http_api",
            "identity_access",
            "workflow_state",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    campaign.surfaces_exercised.sort();
    campaign.surfaces_exercised.dedup();
    campaign.final_state_digest =
        digest(format!("{}\0{}", initial_state, directory_digest(&root)?).as_bytes());
    Ok(campaign)
}

impl WebRuntime {
    fn launch(
        root: &Path,
        executable: &Path,
        arguments: &[String],
        profile: &str,
        request_key: &str,
    ) -> Result<Self, String> {
        let private_root = root.join(".red-team-worker-private");
        fs::create_dir_all(&private_root).map_err(|error| error.to_string())?;
        let private = tempfile::Builder::new()
            .prefix("generic-application-")
            .tempdir_in(&private_root)
            .map_err(|error| error.to_string())?;
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
        let address = listener.local_addr().map_err(|error| error.to_string())?;
        drop(listener);
        let stdout = fs::File::create(private.path().join("server.stdout"))
            .map_err(|error| error.to_string())?;
        let stderr_path = private.path().join("server.stderr");
        let stderr = fs::File::create(&stderr_path).map_err(|error| error.to_string())?;
        let runtime_path = executable
            .parent()
            .map(|directory| format!("{}:/usr/local/bin:/usr/bin:/bin", directory.display()))
            .ok_or("the Bun runtime has no parent directory")?;
        let mut command = Command::new(executable);
        command.args(arguments);
        command
            .current_dir(root)
            .env_clear()
            .env("PATH", runtime_path)
            .env("HOME", private.path())
            .env("HOST", "127.0.0.1")
            .env("PORT", address.port().to_string())
            .env("PERITUS_RED_TEAM_REQUEST", request_key)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr);
        if profile == "comms-bun.v1" {
            command
                .env("COMMS_DATABASE_PATH", private.path().join("comms.sqlite"))
                .env("COMMS_OPERATOR_TOKEN", OPERATOR_TOKEN)
                .env("COMMS_BROKER_TOKEN", BROKER_TOKEN)
                .env("COMMS_WEBHOOK_SECRET", WEBHOOK_SECRET)
                .env("COMMS_PROVIDER", "fake")
                .env("COMMS_HOST", "127.0.0.1")
                .env("COMMS_PORT", address.port().to_string())
                .env("COMMS_PUBLIC_BASE_URL", format!("http://{address}"))
                .env("COMMS_SIGNUP_ALLOWED_ORIGINS", format!("http://{address}"))
                .env("COMMS_WORKFLOW_WORKER_ENABLED", "false")
                .env("COMMS_MISTAKE_PROJECT_ROOT", root)
                .env("COMMS_PHYSICAL_ADDRESS", "Disposable Red Team laboratory");
        }
        let child = command
            .spawn()
            .map_err(|error| format!("launch source-bound web application: {error}"))?;
        let mut runtime = Self { child, address, _private: private };
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = runtime.child.try_wait().map_err(|error| error.to_string())? {
                let stderr = fs::read_to_string(&stderr_path).unwrap_or_default();
                return Err(format!(
                    "source-bound web application exited before readiness ({status}): {}",
                    bounded(&stderr, 8 * 1024)
                ));
            }
            let target = if profile == "comms-bun.v1" { "/api/health" } else { "/" };
            if let Ok(exchange) = runtime.exchange("GET", target, &[], b"")
                && exchange.status < 500
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err(
                    "source-bound web application did not expose a loopback HTTP surface within 20 seconds"
                        .into(),
                );
            }
            thread::sleep(Duration::from_millis(100));
        }
        Ok(runtime)
    }

    fn exchange(
        &self,
        method: &str,
        target: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<Exchange, String> {
        if !target.starts_with('/') || target.contains('\0') || body.len() > MAXIMUM_HTTP_BYTES {
            return Err("generic HTTP attack input is outside campaign bounds".into());
        }
        let mut request = format!(
            "{method} {target} HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\nContent-Length: {}\r\n",
            self.address.port(),
            body.len()
        )
        .into_bytes();
        for (name, value) in headers {
            request.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        request.extend_from_slice(b"\r\n");
        request.extend_from_slice(body);
        let mut stream = TcpStream::connect_timeout(&self.address, Duration::from_secs(3))
            .map_err(|error| error.to_string())?;
        stream.set_read_timeout(Some(Duration::from_secs(8))).map_err(|error| error.to_string())?;
        stream.write_all(&request).map_err(|error| error.to_string())?;
        let mut response = Vec::new();
        let mut chunk = [0_u8; 16 * 1024];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => {
                    response.extend_from_slice(&chunk[..count]);
                    if response.len() > MAXIMUM_HTTP_BYTES {
                        return Err("generic HTTP response exceeded 2 MiB".into());
                    }
                    if response_complete(&response) {
                        break;
                    }
                }
                Err(error)
                    if !response.is_empty()
                        && matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                {
                    break;
                }
                Err(error) => return Err(error.to_string()),
            }
        }
        if response.len() > MAXIMUM_HTTP_BYTES {
            return Err("generic HTTP response exceeded 2 MiB".into());
        }
        let split = find_bytes(&response, b"\r\n\r\n")
            .ok_or("generic HTTP response has no header terminator")?;
        let status = std::str::from_utf8(&response[..split])
            .ok()
            .and_then(|head| head.lines().next())
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse().ok())
            .ok_or("generic HTTP response has no status")?;
        Ok(Exchange { request, body: response[split + 4..].to_vec(), response, status })
    }

    fn shutdown(&mut self) -> bool {
        self.child.kill().is_ok() && self.child.wait().is_ok()
    }
}

fn comms_campaign(runtime: &WebRuntime) -> Result<Vec<(ApplicationAttackCase, Exchange)>, String> {
    let hostile_origin = "https://attacker.invalid";
    let oversized = vec![b'a'; 1024 * 1024 + 1];
    let cases = vec![
        (
            "comms-health",
            "availability_and_resource_use",
            "GET",
            "/api/health",
            vec![],
            Vec::new(),
            vec![200],
        ),
        (
            "comms-operator-unauthorized",
            "authentication_and_sessions",
            "GET",
            "/api/operator/contacts",
            vec![],
            Vec::new(),
            vec![401, 403],
        ),
        (
            "comms-broker-invalid-token",
            "authentication_and_sessions",
            "POST",
            "/internal/authority/v1/invoke",
            vec![("content-type", "application/json"), ("authorization", "Bearer wrong")],
            b"{}".to_vec(),
            vec![401],
        ),
        (
            "comms-broker-adapter-confusion",
            "authorization_and_tenancy",
            "POST",
            "/internal/authority/v1/invoke",
            vec![
                ("content-type", "application/json"),
                ("authorization", concat_bearer(BROKER_TOKEN)),
                ("x-mistake-adapter", "other"),
            ],
            b"{}".to_vec(),
            vec![403],
        ),
        (
            "comms-webhook-invalid-signature",
            "authentication_and_sessions",
            "POST",
            "/api/webhooks/fake",
            vec![("content-type", "application/json"), ("x-webhook-signature", "invalid")],
            b"{}".to_vec(),
            vec![401],
        ),
        (
            "comms-hostile-origin",
            "browser_and_client_trust",
            "POST",
            "/api/signup",
            vec![("content-type", "application/json"), ("origin", hostile_origin)],
            br#"{"email":"attacker@example.invalid","website":""}"#.to_vec(),
            vec![403],
        ),
        (
            "comms-malformed-json",
            "input_interpretation_and_injection",
            "POST",
            "/api/signup",
            vec![("content-type", "application/json")],
            b"{".to_vec(),
            vec![400],
        ),
        (
            "comms-oversized-body",
            "availability_and_resource_use",
            "POST",
            "/api/signup",
            vec![("content-type", "application/json")],
            oversized,
            vec![413],
        ),
        (
            "comms-trace-method",
            "network_and_protocol_boundaries",
            "TRACE",
            "/api/health",
            vec![],
            Vec::new(),
            vec![404, 405, 501],
        ),
        (
            "comms-traversal",
            "files_paths_archives_and_uploads",
            "GET",
            "/../../../../etc/passwd",
            vec![],
            Vec::new(),
            vec![400, 404],
        ),
    ];
    let mut results = execute_cases(runtime, cases)?;
    let workflow_body = br#"{"email":"peritus-workflow@example.invalid","website":""}"#;
    let first = runtime.exchange(
        "POST",
        "/api/signup",
        &[("content-type", "application/json")],
        workflow_body,
    )?;
    let second = runtime.exchange(
        "POST",
        "/api/signup",
        &[("content-type", "application/json")],
        workflow_body,
    )?;
    let workflow_held = first.status == 200 && second.status == 409;
    let combined = Exchange {
        request: [first.request.as_slice(), second.request.as_slice()].concat(),
        response: [first.response.as_slice(), second.response.as_slice()].concat(),
        status: second.status,
        body: second.body,
    };
    results.push((
        ApplicationAttackCase {
            id: "comms-duplicate-signup-workflow".into(),
            class: "business_logic_and_workflow".into(),
            operation: "POST /api/signup twice".into(),
            disposition: if workflow_held { "held" } else { "violation" }.into(),
            response_status: Some(combined.status),
            request_digest: digest(&combined.request),
            response_digest: digest(&combined.response),
            oracle: "First signup must succeed and an identical active signup must conflict."
                .into(),
            replay_digest: digest(b"comms-duplicate-signup-workflow-v1"),
        },
        combined,
    ));
    let chain_held = results.iter().all(|(case, _)| {
        !matches!(
            case.id.as_str(),
            "comms-operator-unauthorized"
                | "comms-broker-invalid-token"
                | "comms-broker-adapter-confusion"
                | "comms-hostile-origin"
        ) || case.disposition == "held"
    });
    let chain_material = results
        .iter()
        .filter(|(case, _)| {
            matches!(
                case.id.as_str(),
                "comms-operator-unauthorized"
                    | "comms-broker-invalid-token"
                    | "comms-broker-adapter-confusion"
                    | "comms-hostile-origin"
            )
        })
        .flat_map(|(_, exchange)| exchange.response.clone())
        .collect::<Vec<_>>();
    results.push((
        ApplicationAttackCase {
            id: "comms-cross-surface-authority-chain".into(),
            class: "authorization_and_tenancy".into(),
            operation: "operator+broker+adapter+origin chain".into(),
            disposition: if chain_held { "held" } else { "violation" }.into(),
            response_status: None,
            request_digest: digest(b"comms-cross-surface-authority-chain-v1"),
            response_digest: digest(&chain_material),
            oracle: "No unauthenticated or cross-adapter chain may cross operator, broker, adapter, or origin boundaries.".into(),
            replay_digest: digest(b"comms-cross-surface-authority-chain-replay-v1"),
        },
        Exchange {
            request: Vec::new(),
            response: chain_material,
            status: 0,
            body: Vec::new(),
        },
    ));
    Ok(results)
}

fn generic_campaign(
    root: &Path,
    runtime: &WebRuntime,
) -> Result<Vec<(ApplicationAttackCase, Exchange)>, String> {
    let mut results = execute_cases(
        runtime,
        vec![
            (
                "generic-root",
                "availability_and_resource_use",
                "GET",
                "/",
                vec![],
                Vec::new(),
                (100..500).collect(),
            ),
            (
                "generic-trace-method",
                "network_and_protocol_boundaries",
                "TRACE",
                "/",
                vec![],
                Vec::new(),
                vec![400, 404, 405, 501],
            ),
            (
                "generic-traversal",
                "files_paths_archives_and_uploads",
                "GET",
                "/../../../../etc/passwd",
                vec![],
                Vec::new(),
                vec![400, 404],
            ),
            (
                "generic-malformed-json",
                "input_interpretation_and_injection",
                "POST",
                "/api",
                vec![("content-type", "application/json")],
                b"{".to_vec(),
                vec![400, 404, 405, 415, 422],
            ),
            (
                "generic-admin-without-identity",
                "authorization_and_tenancy",
                "GET",
                "/admin",
                vec![],
                Vec::new(),
                (100..600).collect(),
            ),
            (
                "generic-api-admin-without-identity",
                "authorization_and_tenancy",
                "GET",
                "/api/admin",
                vec![],
                Vec::new(),
                (100..600).collect(),
            ),
            (
                "generic-login-malformed-json",
                "authentication_and_sessions",
                "POST",
                "/api/login",
                vec![("content-type", "application/json")],
                b"{".to_vec(),
                (100..600).collect(),
            ),
            (
                "generic-webhook-malformed-json",
                "input_interpretation_and_injection",
                "POST",
                "/api/webhooks",
                vec![("content-type", "application/json")],
                b"{".to_vec(),
                (100..600).collect(),
            ),
            (
                "generic-graphql-introspection",
                "configuration_secrets_and_observability",
                "POST",
                "/graphql",
                vec![("content-type", "application/json")],
                br#"{"query":"{__schema{types{name}}}"}"#.to_vec(),
                (100..600).collect(),
            ),
            (
                "generic-upload-boundary",
                "files_paths_archives_and_uploads",
                "POST",
                "/upload",
                vec![("content-type", "application/octet-stream")],
                b"../peritus-probe".to_vec(),
                (100..600).collect(),
            ),
        ],
    )?;
    let routes = discover_common_routes(root)?;
    for (index, target) in routes.iter().take(12).enumerate() {
        if matches!(
            target.as_str(),
            "/" | "/admin" | "/api/admin" | "/api/login" | "/api/webhooks" | "/graphql" | "/upload"
        ) {
            continue;
        }
        let class = classify_route(target);
        let exchange = runtime.exchange("GET", target, &[], b"")?;
        results.push((
            observed_case(
                format!("generic-discovered-route-{index}"),
                class,
                format!("GET {target}"),
                &exchange,
                "A source-discovered route was exercised; its response is retained without inventing an application-specific security oracle.",
            ),
            exchange,
        ));
    }

    let sensitive = select_route(
        &routes,
        &["admin", "operator", "internal", "account", "user", "private"],
        "/admin",
    );
    let baseline = runtime.exchange("GET", &sensitive, &[], b"")?;
    let spoofed = runtime.exchange(
        "GET",
        &sensitive,
        &[
            ("x-forwarded-for", "127.0.0.1"),
            ("x-original-url", &sensitive),
            ("x-rewrite-url", &sensitive),
        ],
        b"",
    )?;
    let denied = matches!(baseline.status, 401 | 403);
    let bypassed = denied && (200..300).contains(&spoofed.status);
    let boundary = combined_exchange(baseline, spoofed);
    results.push((
        classified_case(
            "generic-boundary-header-confusion",
            "authorization_and_tenancy",
            format!("baseline and proxy-header replay against {sensitive}"),
            if bypassed { "violation" } else if denied { "held" } else { "observed" },
            &boundary,
            "Forwarding and rewrite headers must not turn an explicitly denied anonymous request into a successful response.",
        ),
        boundary,
    ));

    let mutation = select_route(
        &routes,
        &["signup", "register", "create", "webhook", "upload", "submit"],
        "/api",
    );
    let workflow_body = br#"{"peritus_probe":"duplicate-workflow"}"#;
    let first = runtime.exchange(
        "POST",
        &mutation,
        &[("content-type", "application/json"), ("idempotency-key", "peritus-duplicate-workflow")],
        workflow_body,
    )?;
    let second = runtime.exchange(
        "POST",
        &mutation,
        &[("content-type", "application/json"), ("idempotency-key", "peritus-duplicate-workflow")],
        workflow_body,
    )?;
    let workflow = combined_exchange(first, second);
    results.push((
        observed_case(
            "generic-duplicate-workflow",
            "business_logic_and_workflow",
            format!("duplicate idempotent POST {mutation}"),
            &workflow,
            "The same source-discovered mutation was replayed with one idempotency identity; application-specific state semantics remain for skeptical interpretation.",
        ),
        workflow,
    ));

    let graph_payload = br#"{"peritus_probe":"<script>window.__peritus_attack_graph=1</script>"}"#;
    let write = runtime.exchange(
        "POST",
        &mutation,
        &[("content-type", "application/json")],
        graph_payload,
    )?;
    let read = runtime.exchange("GET", &sensitive, &[("x-forwarded-for", "127.0.0.1")], b"")?;
    let graph = combined_exchange(write, read);
    results.push((
        observed_case(
            "generic-cross-surface-attack-graph",
            "authorization_and_tenancy",
            format!("write {mutation} then authority read {sensitive}"),
            &graph,
            "A write-to-authority chain was executed across two source-discovered surfaces; only independently observable impact may promote it to a finding.",
        ),
        graph,
    ));
    Ok(results)
}

fn observed_case(
    id: impl Into<String>,
    class: impl Into<String>,
    operation: impl Into<String>,
    exchange: &Exchange,
    oracle: impl Into<String>,
) -> ApplicationAttackCase {
    classified_case(id, class, operation, "observed", exchange, oracle)
}

fn classified_case(
    id: impl Into<String>,
    class: impl Into<String>,
    operation: impl Into<String>,
    disposition: &str,
    exchange: &Exchange,
    oracle: impl Into<String>,
) -> ApplicationAttackCase {
    let operation = operation.into();
    ApplicationAttackCase {
        id: id.into(),
        class: class.into(),
        operation: operation.clone(),
        disposition: disposition.into(),
        response_status: Some(exchange.status),
        request_digest: digest(&exchange.request),
        response_digest: digest(&exchange.response),
        oracle: oracle.into(),
        replay_digest: digest(format!("generic-application-replay-v1\0{operation}").as_bytes()),
    }
}

fn combined_exchange(first: Exchange, second: Exchange) -> Exchange {
    Exchange {
        request: [first.request.as_slice(), second.request.as_slice()].concat(),
        response: [first.response.as_slice(), second.response.as_slice()].concat(),
        status: second.status,
        body: second.body,
    }
}

fn select_route(routes: &[String], terms: &[&str], fallback: &str) -> String {
    routes
        .iter()
        .find(|route| terms.iter().any(|term| route.to_ascii_lowercase().contains(term)))
        .cloned()
        .unwrap_or_else(|| fallback.into())
}

fn classify_route(route: &str) -> &'static str {
    let lower = route.to_ascii_lowercase();
    if ["login", "auth", "session", "token"].iter().any(|term| lower.contains(term)) {
        "authentication_and_sessions"
    } else if ["admin", "operator", "internal", "account", "user", "private"]
        .iter()
        .any(|term| lower.contains(term))
    {
        "authorization_and_tenancy"
    } else if ["upload", "file", "archive", "download"].iter().any(|term| lower.contains(term)) {
        "files_paths_archives_and_uploads"
    } else if ["signup", "register", "create", "submit", "checkout"]
        .iter()
        .any(|term| lower.contains(term))
    {
        "business_logic_and_workflow"
    } else {
        "network_and_protocol_boundaries"
    }
}

fn discover_common_routes(root: &Path) -> Result<Vec<String>, String> {
    let mut routes = BTreeSet::from(["/".to_string()]);
    let mut files = 0_usize;
    let mut bytes = 0_usize;
    collect_route_literals(root, root, &mut routes, &mut files, &mut bytes)?;
    Ok(routes.into_iter().take(64).collect())
}

fn collect_route_literals(
    root: &Path,
    directory: &Path,
    routes: &mut BTreeSet<String>,
    files: &mut usize,
    bytes: &mut usize,
) -> Result<(), String> {
    if *files >= 256 || *bytes >= 2 * 1024 * 1024 {
        return Ok(());
    }
    for entry in fs::read_dir(directory).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let relative = path.strip_prefix(root).map_err(|error| error.to_string())?;
        if [".git", ".red-team-worker-private", "node_modules", "target", "dist", "build"]
            .iter()
            .any(|name| relative.components().any(|part| part.as_os_str() == *name))
        {
            continue;
        }
        let file_type = entry.file_type().map_err(|error| error.to_string())?;
        if file_type.is_dir() {
            collect_route_literals(root, &path, routes, files, bytes)?;
            continue;
        }
        if !file_type.is_file() || *files >= 256 || *bytes >= 2 * 1024 * 1024 {
            continue;
        }
        let metadata = entry.metadata().map_err(|error| error.to_string())?;
        if metadata.len() > 256 * 1024 {
            continue;
        }
        let content = fs::read(&path).map_err(|error| error.to_string())?;
        let Ok(text) = std::str::from_utf8(&content) else {
            continue;
        };
        *files += 1;
        *bytes = bytes.saturating_add(content.len());
        for literal in text.split(['"', '\'', '`']) {
            if let Some(route) = normalize_route_literal(literal) {
                routes.insert(route);
            }
        }
    }
    Ok(())
}

fn normalize_route_literal(literal: &str) -> Option<String> {
    let raw = literal.split(['?', '#']).next()?;
    if !raw.starts_with('/')
        || raw.starts_with("//")
        || raw.len() > 256
        || raw.chars().any(|character| {
            !(character.is_ascii_alphanumeric()
                || matches!(character, '/' | '_' | '-' | '.' | ':' | '{' | '}'))
        })
    {
        return None;
    }
    let route = raw
        .split('/')
        .map(|segment| {
            if segment.starts_with(':') || (segment.starts_with('{') && segment.ends_with('}')) {
                "peritus-probe"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/");
    Some(if route.is_empty() { "/".into() } else { route })
}

type CaseSpec<'a> =
    (&'a str, &'a str, &'a str, &'a str, Vec<(&'a str, &'a str)>, Vec<u8>, Vec<u16>);

fn execute_cases(
    runtime: &WebRuntime,
    cases: Vec<CaseSpec<'_>>,
) -> Result<Vec<(ApplicationAttackCase, Exchange)>, String> {
    cases
        .into_iter()
        .map(|(id, class, method, target, headers, body, expected)| {
            let exchange = runtime.exchange(method, target, &headers, &body)?;
            let traversal = matches!(id, "comms-traversal" | "generic-traversal");
            let protected_bytes_absent =
                !String::from_utf8_lossy(&exchange.body).contains("root:x:0:0");
            let held = if traversal {
                protected_bytes_absent
            } else {
                expected.contains(&exchange.status)
            };
            let replay = serde_json::to_vec(&(method, target, &headers, digest(&body)))
                .map_err(|error| error.to_string())?;
            let case = ApplicationAttackCase {
                id: id.into(),
                class: class.into(),
                operation: format!("{method} {target}"),
                disposition: if id.starts_with("generic-") && !traversal {
                    "observed"
                } else if held {
                    "held"
                } else {
                    "violation"
                }
                .into(),
                response_status: Some(exchange.status),
                request_digest: digest(&exchange.request),
                response_digest: digest(&exchange.response),
                oracle: if traversal {
                    "The traversal-shaped path must not disclose protected file bytes.".into()
                } else {
                    format!("expected status in {expected:?}")
                },
                replay_digest: digest(&replay),
            };
            Ok((case, exchange))
        })
        .collect()
}

fn concat_bearer(token: &str) -> &'static str {
    if token == BROKER_TOKEN {
        "Bearer peritus-disposable-broker-token-0123456789"
    } else {
        "Bearer invalid"
    }
}

fn effective_profile(root: &Path, requested: &str) -> Result<String, String> {
    let package_path = root.join("package.json");
    let package_bytes = fs::read(&package_path)
        .map_err(|_| "generic application campaign requires package.json in the scoped source")?;
    let package: Value = serde_json::from_slice(&package_bytes)
        .map_err(|error| format!("read package.json for runtime selection: {error}"))?;
    let uses_bun = root.join("bun.lock").is_file()
        || root.join("bun.lockb").is_file()
        || package
            .get("packageManager")
            .and_then(Value::as_str)
            .is_some_and(|manager| manager.starts_with("bun@"));
    let is_comms = uses_bun
        && root.join("server/index.ts").is_file()
        && root.join("server/app.ts").is_file()
        && package.get("name").and_then(Value::as_str) == Some("@flt/comms");
    let detected = if is_comms {
        "comms-bun.v1"
    } else if uses_bun {
        "generic-bun-web.v1"
    } else {
        "generic-node-web.v1"
    };
    if !matches!(
        requested,
        "generic-web.v1" | "comms-bun.v1" | "generic-bun-web.v1" | "generic-node-web.v1"
    ) {
        return Err(format!("unsupported generic application profile `{requested}`"));
    }
    Ok(detected.into())
}

fn require_web_source(root: &Path, profile: &str) -> Result<String, String> {
    if !root.join("package.json").is_file() {
        return Err(
            "generic application campaign requires package.json in the scoped source".into()
        );
    }
    if profile == "comms-bun.v1"
        && (!root.join("server/index.ts").is_file() || !root.join("server/app.ts").is_file())
    {
        return Err("Comms/Bun profile does not match the scoped source".into());
    }
    Ok("package.json#scripts.start".into())
}

fn prepare_runtime(
    root: &Path,
    profile: &str,
) -> Result<(PathBuf, Vec<String>, String, String), String> {
    if profile == "generic-node-web.v1" {
        let npm = env::var_os("PERITUS_NPM_EXECUTABLE")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute() && path.is_file())
            .or_else(|| {
                ["/usr/bin/npm", "/usr/local/bin/npm"]
                    .into_iter()
                    .map(PathBuf::from)
                    .find(|path| path.is_file())
            })
            .ok_or("the isolated worker has no npm runtime for this Node application")?;
        if !root.join("node_modules").is_dir() {
            return Err(
                "Node dependencies are absent from the disposable source; prepare or include locked dependencies before runtime attacks".into(),
            );
        }
        return Ok((
            npm,
            vec!["run".into(), "start".into()],
            "node/npm".into(),
            "reused source-contained node_modules".into(),
        ));
    }
    let bun = env::var_os("PERITUS_BUN_EXECUTABLE")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute() && path.is_file())
        .ok_or("the isolated worker has no host-projected Bun runtime")?;
    if root.join("node_modules").is_dir() {
        return Ok((
            bun,
            vec!["run".into(), "start".into()],
            "bun".into(),
            "reused source-contained node_modules".into(),
        ));
    }
    let cache = env::var_os("BUN_INSTALL_CACHE_DIR")
        .map(PathBuf::from)
        .ok_or("dependencies are absent and no read-only Bun package cache was projected")?;
    let temporary = root.join(".peritus-bun-tmp");
    fs::create_dir_all(&temporary)
        .map_err(|error| format!("create disposable Bun temporary directory: {error}"))?;
    let output = Command::new(&bun)
        // The host projects its prepared package cache read-only. Bun normally creates a
        // temporary manifest entry and renames it into that cache even when every package is
        // already present. `--no-cache` suppresses those cache mutations while the explicit
        // cache directory remains available for pinned package payload reads.
        .args(["install", "--frozen-lockfile", "--ignore-scripts", "--no-cache", "--cache-dir"])
        .arg(cache)
        .current_dir(root)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("BUN_TMPDIR", &temporary)
        .env("TMPDIR", &temporary)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("prepare Bun dependencies: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "prepare Bun dependencies in the disposable source: {}",
            bounded(&String::from_utf8_lossy(&output.stderr), 8 * 1024)
        ));
    }
    Ok((
        bun,
        vec!["run".into(), "start".into()],
        "bun".into(),
        "installed locked dependencies into the disposable source".into(),
    ))
}

fn directory_digest(root: &Path) -> Result<String, String> {
    let mut entries = BTreeMap::new();
    collect_files(root, root, &mut entries)?;
    serde_json::to_vec(&entries).map(|bytes| digest(&bytes)).map_err(|error| error.to_string())
}

fn collect_files(
    root: &Path,
    directory: &Path,
    entries: &mut BTreeMap<String, String>,
) -> Result<(), String> {
    for entry in fs::read_dir(directory).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let relative = path.strip_prefix(root).map_err(|error| error.to_string())?;
        if relative.starts_with(".red-team-worker-private") || relative.starts_with("node_modules")
        {
            continue;
        }
        let file_type = entry.file_type().map_err(|error| error.to_string())?;
        if file_type.is_dir() {
            collect_files(root, &path, entries)?;
        } else if file_type.is_file() {
            entries.insert(
                relative.to_string_lossy().into_owned(),
                digest(&fs::read(path).map_err(|error| error.to_string())?),
            );
        }
    }
    Ok(())
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn response_complete(response: &[u8]) -> bool {
    let Some(split) = find_bytes(response, b"\r\n\r\n") else {
        return false;
    };
    let Ok(head) = std::str::from_utf8(&response[..split]) else {
        return false;
    };
    let content_length = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    });
    content_length.is_some_and(|length| response.len() >= split + 4 + length)
        || head.lines().any(|line| {
            line.eq_ignore_ascii_case("transfer-encoding: chunked")
                && response[split + 4..].ends_with(b"\r\n0\r\n\r\n")
        })
}

fn bounded(value: &str, maximum: usize) -> &str {
    value.get(..value.len().min(maximum)).unwrap_or(value)
}
