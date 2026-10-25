//! Pinned HTTP and API campaign owned by the Red Team module.
//!
//! The suite emits real HTTP/1.1 and WebSocket traffic through the laboratory's private Unix
//! socket. Target responses and copied-store changes are observed by the module. Only violations
//! established by the pinned oracle become runtime-confirmed findings.

use peritus_plugin_sdk::{
    ModuleHttpApiCampaignRequest, ModuleHttpApiCaseObservation, ModuleHttpApiDisposition,
    ModuleHttpApiFindingObservation, ModuleHttpApiObservation, ModuleHttpApiProtocol,
    ModuleHttpHeader, ModuleHttpRequestObservation, ModuleHttpResponseObservation,
    ModuleHttpRouteObservation, ModuleSourceSeverity,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;

pub(super) const PROFILE: &str = "peritus.http-api.standard@1";
pub(super) const ADAPTER_VERSION: &str = "peritus-http-api-2026-10-24.1";
pub(super) const SUITE_VERSION: &str = "peritus-http-api-suite-2026-10-24.1";

#[derive(Clone, Debug)]
pub(super) struct WireRequest {
    pub(super) method: String,
    pub(super) target: String,
    pub(super) headers: Vec<(String, String)>,
    pub(super) body: String,
    pub(super) websocket_message: Option<String>,
    pub(super) maximum_request_bytes: u64,
    pub(super) maximum_response_bytes: u64,
}

#[derive(Clone, Debug)]
pub(super) struct Exchange {
    pub(super) request_digest: String,
    pub(super) request_bytes: u64,
    pub(super) response_status: u16,
    pub(super) response_headers: Vec<(String, String)>,
    pub(super) response_body: String,
    pub(super) response_digest: String,
    pub(super) response_body_digest: String,
    pub(super) response_bytes: u64,
    pub(super) response_redacted: bool,
    pub(super) secret_disclosed: bool,
    pub(super) websocket_echo: Option<String>,
    pub(super) state_before_digest: String,
    pub(super) state_after_digest: String,
    pub(super) changed_state_keys: Vec<String>,
}

#[derive(Clone, Copy)]
enum Oracle {
    Status(u16),
    InvalidRejected,
    Unreachable,
    ContentTypeRejected,
    MethodRejected,
    ExternalRedirectRejected,
    HostHeaderRejected,
    GenericError,
    SecretNotDisclosed,
    UnauthorizedMutationRejected,
    DuplicateEffectRejected,
    GraphQlIntrospectionRejected,
    JsonRpcAdd,
    WebSocketEcho,
}

struct Case {
    id: &'static str,
    protocol: ModuleHttpApiProtocol,
    category: &'static str,
    method: &'static str,
    target: &'static str,
    headers: &'static [(&'static str, &'static str)],
    body: &'static str,
    websocket_message: Option<&'static str>,
    oracle: Oracle,
}

/// Executes the pinned suite through a module-owned exchange function.
pub(super) fn execute(
    request: ModuleHttpApiCampaignRequest,
    source_snapshot: String,
    mut exchange: impl FnMut(&WireRequest) -> Result<Exchange, String>,
) -> Result<ModuleHttpApiObservation, String> {
    validate(&request)?;
    let suite = suite();
    if usize::try_from(request.maximum_requests).map_err(|_| "request limit overflow")?
        < suite.len()
    {
        return Err(format!(
            "the pinned suite requires {} exchanges but the request admitted only {}",
            suite.len(),
            request.maximum_requests
        ));
    }
    let mut cases = Vec::with_capacity(suite.len());
    let mut findings = Vec::new();
    let mut routes = Vec::new();
    let mut imported_schema_digest = None;
    let mut traffic = Sha256::new();
    traffic.update(b"peritus-http-api-traffic-v1\0");
    let mut request_bytes = 0_u64;
    let mut response_bytes = 0_u64;
    let mut final_state_digest = String::new();
    for specification in suite {
        let wire = WireRequest {
            method: specification.method.into(),
            target: specification.target.into(),
            headers: specification
                .headers
                .iter()
                .map(|(name, value)| ((*name).into(), (*value).into()))
                .collect(),
            body: specification.body.into(),
            websocket_message: specification.websocket_message.map(str::to_owned),
            maximum_request_bytes: request.maximum_request_bytes,
            maximum_response_bytes: request.maximum_response_bytes,
        };
        let observed = exchange(&wire)?;
        request_bytes = request_bytes.saturating_add(observed.request_bytes);
        response_bytes = response_bytes.saturating_add(observed.response_bytes);
        final_state_digest.clone_from(&observed.state_after_digest);
        traffic.update(observed.request_digest.as_bytes());
        traffic.update([0]);
        traffic.update(observed.response_digest.as_bytes());
        traffic.update([0]);
        if specification.id == "openapi-import" && observed.response_status == 200 {
            imported_schema_digest = Some(observed.response_body_digest.clone());
            routes = parse_routes(&observed.response_body)?;
        }
        let (disposition, oracle_detail) = evaluate(specification.oracle, &observed);
        let request_observation = ModuleHttpRequestObservation {
            method: wire.method,
            target: wire.target,
            headers: wire
                .headers
                .into_iter()
                .map(|(name, value)| ModuleHttpHeader { name, value })
                .collect(),
            body: wire.body,
            digest: observed.request_digest.clone(),
            bytes: observed.request_bytes,
        };
        let response_observation = ModuleHttpResponseObservation {
            status: observed.response_status,
            headers: observed
                .response_headers
                .into_iter()
                .map(|(name, value)| ModuleHttpHeader { name, value })
                .collect(),
            body: observed.response_body,
            digest: observed.response_digest.clone(),
            bytes: observed.response_bytes,
            redacted: observed.response_redacted,
        };
        let minimized = matches!(
            disposition,
            ModuleHttpApiDisposition::Violation
                | ModuleHttpApiDisposition::Rejected
                | ModuleHttpApiDisposition::Unreachable
        );
        let case = ModuleHttpApiCaseObservation {
            id: specification.id.into(),
            protocol: specification.protocol,
            category: specification.category.into(),
            disposition,
            request: request_observation,
            response: response_observation,
            state_before_digest: observed.state_before_digest,
            state_after_digest: observed.state_after_digest,
            changed_state_keys: observed.changed_state_keys,
            oracle: oracle_detail.clone(),
            minimized,
        };
        if disposition == ModuleHttpApiDisposition::Violation {
            findings.push(finding(&case, oracle_detail));
        }
        cases.push(case);
    }
    Ok(ModuleHttpApiObservation {
        schema: 1,
        laboratory_id: request.laboratory_id,
        source_snapshot,
        adapter_version: ADAPTER_VERSION.into(),
        suite_version: SUITE_VERSION.into(),
        imported_schema_digest,
        routes,
        requests_executed: u64::try_from(cases.len()).unwrap_or(u64::MAX),
        cases,
        findings,
        traffic_digest: hex(&traffic.finalize()),
        request_bytes,
        response_bytes,
        final_state_digest,
        gaps: vec![
            "HTTP/2, HTTP/3, TLS, multipart uploads and non-JSON body grammars are not exercised by this initial adapter.".into(),
            "GraphQL subscriptions, WebSocket fragmentation/extensions and RPC transports other than JSON-RPC over HTTP remain unimplemented.".into(),
            "The pinned suite discovers live OpenAPI paths and parameters but does not yet synthesize arbitrary schema-derived values.".into(),
            "Authentication, role/tenant differential testing and browser trust properties belong to later registered adapter phases.".into(),
        ],
    })
}

fn validate(request: &ModuleHttpApiCampaignRequest) -> Result<(), String> {
    if request.schema != 1 || request.profile != PROFILE {
        return Err(
            "HTTP/API campaigns require schema 1 and the registered standard profile".into()
        );
    }
    if request.laboratory_id.len() != 64 || request.endpoint_handle.len() != 64 {
        return Err("HTTP/API campaign laboratory identities are malformed".into());
    }
    if !(21..=128).contains(&request.maximum_requests)
        || !(1_024..=256 * 1_024).contains(&request.maximum_request_bytes)
        || !(1_024..=2 * 1_024 * 1_024).contains(&request.maximum_response_bytes)
    {
        return Err("HTTP/API campaign bounds are outside the registered profile".into());
    }
    Ok(())
}

fn evaluate(oracle: Oracle, exchange: &Exchange) -> (ModuleHttpApiDisposition, String) {
    let header = |name: &str| {
        exchange
            .response_headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    };
    match oracle {
        Oracle::Status(expected) => {
            if exchange.response_status == expected {
                (ModuleHttpApiDisposition::Passed, format!("status {expected} observed"))
            } else if exchange.response_status == 404 {
                (ModuleHttpApiDisposition::Unreachable, "required route returned 404".into())
            } else {
                (
                    ModuleHttpApiDisposition::Unreachable,
                    format!(
                        "required ordinary response was {expected}, observed {}",
                        exchange.response_status
                    ),
                )
            }
        }
        Oracle::InvalidRejected => rejected(exchange, "malformed JSON was rejected"),
        Oracle::Unreachable => {
            if exchange.response_status == 404 {
                (ModuleHttpApiDisposition::Unreachable, "unknown route returned 404".into())
            } else {
                (
                    ModuleHttpApiDisposition::Violation,
                    "unknown route was unexpectedly reachable".into(),
                )
            }
        }
        Oracle::ContentTypeRejected => vulnerability_rejected(
            exchange,
            exchange.response_status < 400,
            "JSON operation accepted a text/plain body",
            "unsupported media type was rejected",
        ),
        Oracle::MethodRejected => vulnerability_rejected(
            exchange,
            exchange.response_status < 400,
            "undeclared HTTP method performed the operation",
            "undeclared HTTP method was rejected",
        ),
        Oracle::ExternalRedirectRejected => vulnerability_rejected(
            exchange,
            exchange.response_status / 100 == 3
                && header("location")
                    .is_some_and(|value| value.starts_with("https://attacker.invalid")),
            "untrusted redirect target reached the Location header",
            "external redirect target was rejected",
        ),
        Oracle::HostHeaderRejected => vulnerability_rejected(
            exchange,
            header("location").is_some_and(|value| value.contains("attacker.invalid")),
            "forwarded host input controlled an absolute response URL",
            "forwarded host input did not control the response",
        ),
        Oracle::GenericError => vulnerability_rejected(
            exchange,
            exchange.response_body.contains("Traceback (most recent call last)")
                || exchange.response_body.contains("/private/"),
            "error response disclosed an implementation traceback or private path",
            "error response was generic",
        ),
        Oracle::SecretNotDisclosed => vulnerability_rejected(
            exchange,
            exchange.secret_disclosed,
            "injection-shaped lookup disclosed the exact target-only canary",
            "injection-shaped lookup did not disclose the canary",
        ),
        Oracle::UnauthorizedMutationRejected => vulnerability_rejected(
            exchange,
            exchange.response_status < 400
                && exchange.changed_state_keys.iter().any(|key| key == "admin_deletes"),
            "unauthenticated DELETE changed protected copied state",
            "unauthenticated mutation was rejected without protected state change",
        ),
        Oracle::DuplicateEffectRejected => vulnerability_rejected(
            exchange,
            exchange.response_status < 400
                && exchange.changed_state_keys.iter().any(|key| key == "workflow_completions"),
            "duplicate workflow completion repeated the copied-state effect",
            "duplicate workflow completion was rejected without repeating the effect",
        ),
        Oracle::GraphQlIntrospectionRejected => vulnerability_rejected(
            exchange,
            exchange.response_status == 200 && exchange.response_body.contains("__schema"),
            "anonymous GraphQL introspection returned schema data contrary to the pinned policy",
            "anonymous GraphQL introspection was rejected",
        ),
        Oracle::JsonRpcAdd => {
            if exchange.response_status == 200 && exchange.response_body.contains("\"result\":5") {
                (
                    ModuleHttpApiDisposition::Passed,
                    "JSON-RPC add returned the independently expected result 5".into(),
                )
            } else {
                (
                    ModuleHttpApiDisposition::Unreachable,
                    "JSON-RPC ordinary operation did not return result 5".into(),
                )
            }
        }
        Oracle::WebSocketEcho => {
            if exchange.websocket_echo.as_deref() == Some("phase13-echo") {
                (
                    ModuleHttpApiDisposition::Passed,
                    "WebSocket upgrade and framed echo matched".into(),
                )
            } else {
                (
                    ModuleHttpApiDisposition::Unreachable,
                    "WebSocket framed echo was not observed".into(),
                )
            }
        }
    }
}

fn rejected(exchange: &Exchange, detail: &str) -> (ModuleHttpApiDisposition, String) {
    if (400..500).contains(&exchange.response_status) {
        (ModuleHttpApiDisposition::Rejected, detail.into())
    } else {
        (
            ModuleHttpApiDisposition::Violation,
            format!("{detail} was expected, observed status {}", exchange.response_status),
        )
    }
}

fn vulnerability_rejected(
    exchange: &Exchange,
    violated: bool,
    violation: &str,
    rejection: &str,
) -> (ModuleHttpApiDisposition, String) {
    if violated {
        (ModuleHttpApiDisposition::Violation, violation.into())
    } else if exchange.response_status == 404 {
        (ModuleHttpApiDisposition::Unreachable, "the probed route was not reachable".into())
    } else {
        (ModuleHttpApiDisposition::Rejected, rejection.into())
    }
}

fn finding(
    observation: &ModuleHttpApiCaseObservation,
    message: String,
) -> ModuleHttpApiFindingObservation {
    let mut hasher = Sha256::new();
    hasher.update(b"peritus-http-api-finding-v1\0");
    hasher.update(observation.id.as_bytes());
    hasher.update([0]);
    hasher.update(observation.request.digest.as_bytes());
    hasher.update([0]);
    hasher.update(observation.response.digest.as_bytes());
    let (severity, standards) = match observation.category.as_str() {
        "injection" => (ModuleSourceSeverity::Critical, vec!["CWE-89".into()]),
        "authorization" => (ModuleSourceSeverity::High, vec!["CWE-862".into()]),
        "redirect" | "host-header" => (ModuleSourceSeverity::Medium, vec!["CWE-601".into()]),
        "error-disclosure" => (ModuleSourceSeverity::Medium, vec!["CWE-209".into()]),
        "workflow-replay" => (ModuleSourceSeverity::High, vec!["CWE-841".into()]),
        "graphql-introspection" => (ModuleSourceSeverity::Low, vec!["CWE-200".into()]),
        _ => (ModuleSourceSeverity::Medium, vec!["CWE-20".into()]),
    };
    ModuleHttpApiFindingObservation {
        id: hex(&hasher.finalize()),
        case_id: observation.id.clone(),
        category: observation.category.clone(),
        severity,
        message,
        evidence_state: "runtime_confirmed".into(),
        state_change_observed: observation.state_before_digest != observation.state_after_digest,
        standards,
        replay_request_digest: observation.request.digest.clone(),
    }
}

fn parse_routes(body: &str) -> Result<Vec<ModuleHttpRouteObservation>, String> {
    let document: Value = serde_json::from_str(body)
        .map_err(|error| format!("live OpenAPI response was invalid JSON: {error}"))?;
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .ok_or_else(|| "live OpenAPI response has no paths object".to_string())?;
    let mut routes = Vec::new();
    for (path, item) in paths {
        let Some(item) = item.as_object() else { continue };
        let mut methods = BTreeSet::new();
        let mut parameters = BTreeSet::new();
        for (method, operation) in item {
            if matches!(method.as_str(), "get" | "post" | "put" | "patch" | "delete") {
                methods.insert(method.to_ascii_uppercase());
            }
            if let Some(values) = operation.get("parameters").and_then(Value::as_array) {
                for value in values {
                    if let Some(name) = value.get("name").and_then(Value::as_str) {
                        parameters.insert(name.to_owned());
                    }
                }
            }
        }
        routes.push(ModuleHttpRouteObservation {
            path: path.clone(),
            methods: methods.into_iter().collect(),
            parameters: parameters.into_iter().collect(),
            source: "openapi-live-response".into(),
        });
    }
    routes.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(routes)
}

fn suite() -> Vec<Case> {
    vec![
        case(
            "openapi-import",
            ModuleHttpApiProtocol::OpenApi,
            "schema",
            "GET",
            "/openapi.json",
            &[],
            "",
            None,
            Oracle::Status(200),
        ),
        case(
            "health",
            ModuleHttpApiProtocol::Rest,
            "ordinary",
            "GET",
            "/health",
            &[],
            "",
            None,
            Oracle::Status(200),
        ),
        case(
            "rest-create",
            ModuleHttpApiProtocol::Rest,
            "ordinary",
            "POST",
            "/items",
            &[("content-type", "application/json")],
            "{\"name\":\"phase13\"}",
            None,
            Oracle::Status(201),
        ),
        case(
            "rest-list",
            ModuleHttpApiProtocol::Rest,
            "ordinary",
            "GET",
            "/items",
            &[],
            "",
            None,
            Oracle::Status(200),
        ),
        case(
            "malformed-json",
            ModuleHttpApiProtocol::Rest,
            "parsing",
            "POST",
            "/items",
            &[("content-type", "application/json")],
            "{",
            None,
            Oracle::InvalidRejected,
        ),
        case(
            "content-type-confusion",
            ModuleHttpApiProtocol::Rest,
            "content-type",
            "POST",
            "/items",
            &[("content-type", "text/plain")],
            "{\"name\":\"confused\"}",
            None,
            Oracle::ContentTypeRejected,
        ),
        case(
            "undeclared-method",
            ModuleHttpApiProtocol::Rest,
            "method",
            "PUT",
            "/items",
            &[("content-type", "application/json")],
            "{\"name\":\"method\"}",
            None,
            Oracle::MethodRejected,
        ),
        case(
            "external-redirect",
            ModuleHttpApiProtocol::Rest,
            "redirect",
            "GET",
            "/redirect?next=https%3A%2F%2Fattacker.invalid%2Fx",
            &[],
            "",
            None,
            Oracle::ExternalRedirectRejected,
        ),
        case(
            "forwarded-host",
            ModuleHttpApiProtocol::Rest,
            "host-header",
            "GET",
            "/host-link",
            &[("x-forwarded-host", "attacker.invalid")],
            "",
            None,
            Oracle::HostHeaderRejected,
        ),
        case(
            "error-detail",
            ModuleHttpApiProtocol::Rest,
            "error-disclosure",
            "GET",
            "/error",
            &[],
            "",
            None,
            Oracle::GenericError,
        ),
        case(
            "lookup-injection",
            ModuleHttpApiProtocol::Rest,
            "injection",
            "GET",
            "/lookup?id=1%20OR%201%3D1",
            &[],
            "",
            None,
            Oracle::SecretNotDisclosed,
        ),
        case(
            "unauthorized-delete",
            ModuleHttpApiProtocol::Rest,
            "authorization",
            "DELETE",
            "/admin",
            &[],
            "",
            None,
            Oracle::UnauthorizedMutationRejected,
        ),
        case(
            "workflow-start",
            ModuleHttpApiProtocol::Rest,
            "ordinary",
            "POST",
            "/workflow/start",
            &[("content-type", "application/json")],
            "{}",
            None,
            Oracle::Status(200),
        ),
        case(
            "workflow-finish",
            ModuleHttpApiProtocol::Rest,
            "ordinary",
            "POST",
            "/workflow/finish",
            &[("content-type", "application/json")],
            "{\"token\":\"workflow-1\"}",
            None,
            Oracle::Status(200),
        ),
        case(
            "workflow-replay",
            ModuleHttpApiProtocol::Rest,
            "workflow-replay",
            "POST",
            "/workflow/finish",
            &[("content-type", "application/json")],
            "{\"token\":\"workflow-1\"}",
            None,
            Oracle::DuplicateEffectRejected,
        ),
        case(
            "graphql-query",
            ModuleHttpApiProtocol::GraphQl,
            "ordinary",
            "POST",
            "/graphql",
            &[("content-type", "application/json")],
            "{\"query\":\"{ ping }\"}",
            None,
            Oracle::Status(200),
        ),
        case(
            "graphql-introspection",
            ModuleHttpApiProtocol::GraphQl,
            "graphql-introspection",
            "POST",
            "/graphql",
            &[("content-type", "application/json")],
            "{\"query\":\"{ __schema { queryType { name } } }\"}",
            None,
            Oracle::GraphQlIntrospectionRejected,
        ),
        case(
            "json-rpc-add",
            ModuleHttpApiProtocol::JsonRpc,
            "ordinary",
            "POST",
            "/rpc",
            &[("content-type", "application/json")],
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"math.add\",\"params\":[2,3]}",
            None,
            Oracle::JsonRpcAdd,
        ),
        case(
            "json-rpc-unknown",
            ModuleHttpApiProtocol::JsonRpc,
            "parsing",
            "POST",
            "/rpc",
            &[("content-type", "application/json")],
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"shell.exec\",\"params\":[]}",
            None,
            Oracle::InvalidRejected,
        ),
        case(
            "websocket-echo",
            ModuleHttpApiProtocol::WebSocket,
            "ordinary",
            "GET",
            "/ws",
            &[],
            "",
            Some("phase13-echo"),
            Oracle::WebSocketEcho,
        ),
        case(
            "unknown-route",
            ModuleHttpApiProtocol::Rest,
            "route-reachability",
            "GET",
            "/not-implemented",
            &[],
            "",
            None,
            Oracle::Unreachable,
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
const fn case(
    id: &'static str,
    protocol: ModuleHttpApiProtocol,
    category: &'static str,
    method: &'static str,
    target: &'static str,
    headers: &'static [(&'static str, &'static str)],
    body: &'static str,
    websocket_message: Option<&'static str>,
    oracle: Oracle,
) -> Case {
    Case { id, protocol, category, method, target, headers, body, websocket_message, oracle }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
