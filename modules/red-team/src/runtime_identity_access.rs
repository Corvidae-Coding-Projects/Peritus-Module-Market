//! Module-owned authentication, session, authorization, and tenancy campaign.
//!
//! Credential bytes are derived and consumed only inside this adapter. The module receives opaque
//! role/tenant handles, status/state oracles, and a module-private credential-free projection.

use super::{
    runtime_http_api::{Exchange, WireRequest},
    runtime_laboratory::{Broker, IdentityLaboratorySession},
};
use peritus_plugin_sdk::{
    ModuleIdentityAccessCampaignRequest, ModuleIdentityAccessCaseObservation,
    ModuleIdentityAccessDisposition, ModuleIdentityAccessFindingObservation,
    ModuleIdentityAccessObservation, ModuleIdentityRedactionObservation,
    ModuleIdentityRoleObservation, ModuleIdentitySessionPhase, ModuleIdentitySessionTransition,
    ModuleSourceSeverity,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeSet, fs, path::Path};

const PROFILE: &str = "peritus.identity-access.standard@1";
const IDENTITY_PROFILE: &str = "peritus.identity-topology.multitenant@1";
const ADAPTER_VERSION: &str = "peritus-identity-access-2026-10-24.1";
const SUITE_VERSION: &str = "peritus-identity-access-suite-2026-10-24.1";

#[derive(Default)]
struct Vault {
    values: BTreeSet<String>,
    request_fields_redacted: u64,
    response_fields_redacted: u64,
}

impl Vault {
    fn retain(&mut self, value: impl Into<String>) -> String {
        let value = value.into();
        self.values.insert(value.clone());
        value
    }

    fn request_field(&mut self) {
        self.request_fields_redacted = self.request_fields_redacted.saturating_add(1);
    }

    fn response_field(&mut self, value: String) -> String {
        self.response_fields_redacted = self.response_fields_redacted.saturating_add(1);
        self.retain(value)
    }

    fn projection_clean(&self, bytes: &[u8]) -> bool {
        self.values.iter().all(|value| !contains(bytes, value.as_bytes()))
    }
}

struct Run<'a> {
    request: &'a ModuleIdentityAccessCampaignRequest,
    laboratory: &'a Broker,
    traffic: Sha256,
    operations: u64,
    final_state_digest: String,
}

impl<'a> Run<'a> {
    fn new(request: &'a ModuleIdentityAccessCampaignRequest, laboratory: &'a Broker) -> Self {
        let mut traffic = Sha256::new();
        traffic.update(b"peritus-identity-access-traffic-v1\0");
        Self { request, laboratory, traffic, operations: 0, final_state_digest: String::new() }
    }

    fn exchange(
        &mut self,
        method: &str,
        target: &str,
        body: Value,
        bearer: Option<&str>,
        vault: &mut Vault,
    ) -> Result<Exchange, String> {
        if self.operations >= u64::from(self.request.maximum_operations) {
            return Err("identity campaign exceeded its admitted operation bound".into());
        }
        let mut headers = vec![
            ("host".into(), "laboratory.invalid".into()),
            ("content-type".into(), "application/json".into()),
        ];
        if let Some(token) = bearer {
            vault.request_field();
            headers.push(("authorization".into(), format!("Bearer {token}")));
        }
        let wire = WireRequest {
            method: method.into(),
            target: target.into(),
            headers,
            body: if body.is_null() { String::new() } else { body.to_string() },
            websocket_message: None,
            maximum_request_bytes: 128 * 1024,
            maximum_response_bytes: self.request.maximum_response_bytes,
        };
        let observed = self.laboratory.http_exchange(
            &self.request.laboratory_id,
            &self.request.endpoint_handle,
            &wire,
        )?;
        self.operations = self.operations.saturating_add(1);
        self.traffic.update(observed.request_digest.as_bytes());
        self.traffic.update([0]);
        self.traffic.update(observed.response_digest.as_bytes());
        self.traffic.update([0]);
        self.final_state_digest.clone_from(&observed.state_after_digest);
        Ok(observed)
    }
}

enum Oracle {
    Allowed(u16),
    MustReject,
    MustRejectMutation(&'static str),
}

struct CaseSpec<'a> {
    id: &'a str,
    category: &'a str,
    actor: &'a str,
    target: Option<&'a str>,
    operation: &'a str,
    oracle: Oracle,
}

/// Executes or recovers one exact credential-free campaign observation.
pub(super) fn execute(
    request: ModuleIdentityAccessCampaignRequest,
    request_key: &str,
    module_id: &str,
    module_digest: &str,
    host_state: &Path,
    laboratory: &Broker,
) -> Result<ModuleIdentityAccessObservation, String> {
    validate_request(&request)?;
    let session = laboratory.identity_session(&request.laboratory_id, &request.endpoint_handle)?;
    let identity = digest(
        format!(
            "peritus.identity-campaign.v1\0{module_id}\0{module_digest}\0{request_key}\0{}\0{}",
            request.laboratory_id, request.endpoint_handle
        )
        .as_bytes(),
    );
    let root = host_state.join("identity-campaigns-v1");
    fs::create_dir_all(&root).map_err(|error| error.to_string())?;
    let retained = root.join(&identity).join("observation.json");
    if retained.is_file() && !retained.is_symlink() {
        let observation: ModuleIdentityAccessObservation =
            serde_json::from_slice(&fs::read(retained).map_err(|error| error.to_string())?)
                .map_err(|error| format!("retained identity observation is invalid: {error}"))?;
        if observation.source_snapshot != session.source_snapshot
            || !observation.redaction.provider_projection_clean
        {
            return Err("retained identity observation does not match the live laboratory".into());
        }
        return Ok(observation);
    }
    let observation = campaign(&request, laboratory, &session)?;
    let staging = tempfile::Builder::new()
        .prefix("identity-campaign-")
        .tempdir_in(&root)
        .map_err(|error| error.to_string())?;
    write_private(
        &staging.path().join("observation.json"),
        &serde_json::to_vec(&observation).map_err(|error| error.to_string())?,
    )?;
    fs::rename(staging.keep(), root.join(identity))
        .map_err(|error| format!("retain identity campaign: {error}"))?;
    Ok(observation)
}

fn validate_request(request: &ModuleIdentityAccessCampaignRequest) -> Result<(), String> {
    if request.schema != 1
        || request.profile != PROFILE
        || request.identity_profile != IDENTITY_PROFILE
    {
        return Err("identity campaign requires schema 1 and registered profiles".into());
    }
    if request.laboratory_id.len() != 64
        || request.endpoint_handle.len() != 64
        || !request.laboratory_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !request.endpoint_handle.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("identity campaign requires opaque laboratory and endpoint identities".into());
    }
    if !(24..=128).contains(&request.maximum_operations)
        || !(64 * 1024..=1024 * 1024).contains(&request.maximum_response_bytes)
    {
        return Err("identity campaign bounds are outside the registered profile".into());
    }
    Ok(())
}

fn campaign(
    request: &ModuleIdentityAccessCampaignRequest,
    laboratory: &Broker,
    session: &IdentityLaboratorySession,
) -> Result<ModuleIdentityAccessObservation, String> {
    let identity = |label: &str| opaque(&request.laboratory_id, "identity", label);
    let tenant = |label: &str| opaque(&request.laboratory_id, "tenant", label);
    let anonymous = identity("anonymous");
    let alice = identity("alice");
    let bob = identity("bob");
    let carol = identity("carol");
    let admin = identity("admin");
    let red = tenant("red");
    let blue = tenant("blue");
    let identities = vec![
        ModuleIdentityRoleObservation {
            identity_handle: anonymous.clone(),
            role: "anonymous".into(),
            tenant_handle: None,
            privileged: false,
            credential_source: "none".into(),
        },
        role(&alice, "ordinary", &red, false),
        role(&bob, "ordinary", &red, false),
        role(&carol, "ordinary", &blue, false),
        role(&admin, "administrator", &red, true),
    ];
    let mut vault = Vault::default();
    let alice_password = vault.retain(credential(&session.credential_seed, "password:alice"));
    let bob_password = vault.retain(credential(&session.credential_seed, "password:bob"));
    let carol_password = vault.retain(credential(&session.credential_seed, "password:carol"));
    let admin_password = vault.retain(credential(&session.credential_seed, "password:admin"));
    let admin_factor = vault.retain(credential(&session.credential_seed, "factor:admin"));
    let mut run = Run::new(request, laboratory);
    let mut cases = Vec::new();
    let mut findings = Vec::new();
    let mut transitions = Vec::new();

    let health = run.exchange("GET", "/health", Value::Null, None, &mut vault)?;
    admit_case(
        &mut cases,
        &mut findings,
        CaseSpec {
            id: "anonymous-public-health",
            category: "anonymous_access",
            actor: &anonymous,
            target: None,
            operation: "GET /health",
            oracle: Oracle::Allowed(200),
        },
        &health,
    );
    vault.request_field();
    let invalid_login = run.exchange(
        "POST",
        "/auth/login",
        json!({"username":"alice","password":"invalid-credential"}),
        None,
        &mut vault,
    )?;
    admit_case(
        &mut cases,
        &mut findings,
        CaseSpec {
            id: "invalid-login-rejected",
            category: "authentication",
            actor: &alice,
            target: None,
            operation: "POST /auth/login",
            oracle: Oracle::MustReject,
        },
        &invalid_login,
    );

    let alice_login = login(&mut run, &mut vault, "alice", &alice_password)?;
    admit_case(
        &mut cases,
        &mut findings,
        CaseSpec {
            id: "ordinary-login",
            category: "authentication",
            actor: &alice,
            target: None,
            operation: "POST /auth/login",
            oracle: Oracle::Allowed(200),
        },
        &alice_login.0,
    );
    transitions.push(transition(
        "ordinary-login",
        &alice,
        ModuleIdentitySessionPhase::Anonymous,
        ModuleIdentitySessionPhase::Authenticated,
        "login",
    ));
    let alice_token = alice_login.1;
    let own =
        run.exchange("GET", "/objects/red-alice", Value::Null, Some(&alice_token), &mut vault)?;
    admit_case(
        &mut cases,
        &mut findings,
        CaseSpec {
            id: "owner-read",
            category: "ownership",
            actor: &alice,
            target: Some(&alice),
            operation: "GET /objects/{owned}",
            oracle: Oracle::Allowed(200),
        },
        &own,
    );
    let anonymous_object =
        run.exchange("GET", "/objects/red-alice", Value::Null, None, &mut vault)?;
    admit_case(
        &mut cases,
        &mut findings,
        CaseSpec {
            id: "anonymous-protected-read",
            category: "missing_authentication",
            actor: &anonymous,
            target: Some(&alice),
            operation: "GET /objects/{owned}",
            oracle: Oracle::MustReject,
        },
        &anonymous_object,
    );
    let vertical =
        run.exchange("GET", "/admin/report", Value::Null, Some(&alice_token), &mut vault)?;
    admit_case(
        &mut cases,
        &mut findings,
        CaseSpec {
            id: "ordinary-to-privileged",
            category: "vertical_authorization",
            actor: &alice,
            target: Some(&admin),
            operation: "GET /admin/report",
            oracle: Oracle::MustReject,
        },
        &vertical,
    );
    let cross_tenant =
        run.exchange("GET", "/objects/blue-carol", Value::Null, Some(&alice_token), &mut vault)?;
    admit_case(
        &mut cases,
        &mut findings,
        CaseSpec {
            id: "cross-tenant-read",
            category: "tenant_isolation",
            actor: &alice,
            target: Some(&carol),
            operation: "GET /objects/{cross-tenant}",
            oracle: Oracle::MustReject,
        },
        &cross_tenant,
    );
    let ownership = run.exchange(
        "PATCH",
        "/objects/red-bob",
        json!({"value":"phase15-mutated"}),
        Some(&alice_token),
        &mut vault,
    )?;
    admit_case(
        &mut cases,
        &mut findings,
        CaseSpec {
            id: "horizontal-object-mutation",
            category: "object_ownership",
            actor: &alice,
            target: Some(&bob),
            operation: "PATCH /objects/{adjacent-owner}",
            oracle: Oracle::MustRejectMutation("object_red_bob"),
        },
        &ownership,
    );
    let adjacent = run.exchange(
        "GET",
        "/objects/red-bob/private",
        Value::Null,
        Some(&alice_token),
        &mut vault,
    )?;
    admit_case(
        &mut cases,
        &mut findings,
        CaseSpec {
            id: "adjacent-private-route",
            category: "adjacent_route_authorization",
            actor: &alice,
            target: Some(&bob),
            operation: "GET /objects/{adjacent-owner}/private",
            oracle: Oracle::MustReject,
        },
        &adjacent,
    );

    let challenge_exchange = login_challenge(&mut run, &mut vault, "admin", &admin_password)?;
    let challenge = secret_field(&challenge_exchange, "challenge", &mut vault)?;
    admit_case(
        &mut cases,
        &mut findings,
        CaseSpec {
            id: "privileged-login-challenge",
            category: "multi_factor_authentication",
            actor: &admin,
            target: None,
            operation: "POST /auth/login",
            oracle: Oracle::Allowed(202),
        },
        &challenge_exchange,
    );
    transitions.push(transition(
        "privileged-login-challenge",
        &admin,
        ModuleIdentitySessionPhase::Anonymous,
        ModuleIdentitySessionPhase::ChallengeIssued,
        "login challenge",
    ));
    vault.request_field();
    vault.request_field();
    let wrong_factor = run.exchange(
        "POST",
        "/auth/mfa",
        json!({"challenge":challenge,"factor":"invalid-factor"}),
        None,
        &mut vault,
    )?;
    admit_case(
        &mut cases,
        &mut findings,
        CaseSpec {
            id: "invalid-mfa-rejected",
            category: "multi_factor_authentication",
            actor: &admin,
            target: None,
            operation: "POST /auth/mfa",
            oracle: Oracle::MustReject,
        },
        &wrong_factor,
    );
    vault.request_field();
    vault.request_field();
    let correct_factor = run.exchange(
        "POST",
        "/auth/mfa",
        json!({"challenge":challenge,"factor":admin_factor}),
        None,
        &mut vault,
    )?;
    let admin_token = secret_field(&correct_factor, "token", &mut vault)?;
    admit_case(
        &mut cases,
        &mut findings,
        CaseSpec {
            id: "valid-mfa-session",
            category: "multi_factor_authentication",
            actor: &admin,
            target: None,
            operation: "POST /auth/mfa",
            oracle: Oracle::Allowed(200),
        },
        &correct_factor,
    );
    transitions.push(transition(
        "valid-mfa-session",
        &admin,
        ModuleIdentitySessionPhase::ChallengeIssued,
        ModuleIdentitySessionPhase::Authenticated,
        "MFA completion",
    ));
    let admin_access =
        run.exchange("GET", "/admin/report", Value::Null, Some(&admin_token), &mut vault)?;
    admit_case(
        &mut cases,
        &mut findings,
        CaseSpec {
            id: "privileged-admin-read",
            category: "vertical_authorization",
            actor: &admin,
            target: Some(&admin),
            operation: "GET /admin/report",
            oracle: Oracle::Allowed(200),
        },
        &admin_access,
    );

    let logout = run.exchange("POST", "/auth/logout", json!({}), Some(&alice_token), &mut vault)?;
    require_status(&logout, 200, "logout")?;
    let logged_out =
        run.exchange("GET", "/auth/me", Value::Null, Some(&alice_token), &mut vault)?;
    admit_case(
        &mut cases,
        &mut findings,
        CaseSpec {
            id: "logout-invalidates-session",
            category: "session_logout",
            actor: &alice,
            target: None,
            operation: "GET /auth/me after logout",
            oracle: Oracle::MustReject,
        },
        &logged_out,
    );
    transitions.push(transition(
        "logout-invalidates-session",
        &alice,
        ModuleIdentitySessionPhase::Authenticated,
        ModuleIdentitySessionPhase::LoggedOut,
        "logout and old-token check",
    ));

    let (_, bob_token) = login(&mut run, &mut vault, "bob", &bob_password)?;
    let rotated = run.exchange("POST", "/auth/rotate", json!({}), Some(&bob_token), &mut vault)?;
    let bob_rotated = secret_field(&rotated, "token", &mut vault)?;
    let old_after_rotate =
        run.exchange("GET", "/auth/me", Value::Null, Some(&bob_token), &mut vault)?;
    admit_case(
        &mut cases,
        &mut findings,
        CaseSpec {
            id: "rotation-invalidates-old-token",
            category: "token_rotation",
            actor: &bob,
            target: None,
            operation: "GET /auth/me with rotated token",
            oracle: Oracle::MustReject,
        },
        &old_after_rotate,
    );
    transitions.push(transition(
        "rotation-invalidates-old-token",
        &bob,
        ModuleIdentitySessionPhase::Authenticated,
        ModuleIdentitySessionPhase::Rotated,
        "rotation and old-token check",
    ));
    let new_after_rotate =
        run.exchange("GET", "/auth/me", Value::Null, Some(&bob_rotated), &mut vault)?;
    admit_case(
        &mut cases,
        &mut findings,
        CaseSpec {
            id: "rotation-preserves-new-session",
            category: "token_rotation",
            actor: &bob,
            target: None,
            operation: "GET /auth/me with replacement token",
            oracle: Oracle::Allowed(200),
        },
        &new_after_rotate,
    );

    let (_, carol_token) = login(&mut run, &mut vault, "carol", &carol_password)?;
    let expired =
        run.exchange("POST", "/auth/expire", json!({}), Some(&carol_token), &mut vault)?;
    require_status(&expired, 200, "expiry")?;
    let expired_check =
        run.exchange("GET", "/auth/me", Value::Null, Some(&carol_token), &mut vault)?;
    admit_case(
        &mut cases,
        &mut findings,
        CaseSpec {
            id: "expired-session-rejected",
            category: "session_expiry",
            actor: &carol,
            target: None,
            operation: "GET /auth/me after expiry",
            oracle: Oracle::MustReject,
        },
        &expired_check,
    );
    transitions.push(transition(
        "expired-session-rejected",
        &carol,
        ModuleIdentitySessionPhase::Authenticated,
        ModuleIdentitySessionPhase::Expired,
        "expiry and old-token check",
    ));

    let (_, alice_revoke_token) = login(&mut run, &mut vault, "alice", &alice_password)?;
    let revoked =
        run.exchange("POST", "/auth/revoke", json!({}), Some(&alice_revoke_token), &mut vault)?;
    require_status(&revoked, 200, "revocation")?;
    let revoked_check =
        run.exchange("GET", "/auth/me", Value::Null, Some(&alice_revoke_token), &mut vault)?;
    admit_case(
        &mut cases,
        &mut findings,
        CaseSpec {
            id: "revoked-session-rejected",
            category: "session_revocation",
            actor: &alice,
            target: None,
            operation: "GET /auth/me after revocation",
            oracle: Oracle::MustReject,
        },
        &revoked_check,
    );
    transitions.push(transition(
        "revoked-session-rejected",
        &alice,
        ModuleIdentitySessionPhase::Authenticated,
        ModuleIdentitySessionPhase::Revoked,
        "revocation and old-token check",
    ));

    let (_, bob_first) = login(&mut run, &mut vault, "bob", &bob_password)?;
    let (_, bob_second) = login(&mut run, &mut vault, "bob", &bob_password)?;
    let revoke_all =
        run.exchange("POST", "/auth/revoke-all", json!({}), Some(&bob_first), &mut vault)?;
    require_status(&revoke_all, 200, "concurrent-session revocation")?;
    let concurrent_check =
        run.exchange("GET", "/auth/me", Value::Null, Some(&bob_second), &mut vault)?;
    admit_case(
        &mut cases,
        &mut findings,
        CaseSpec {
            id: "concurrent-sessions-revoked",
            category: "concurrent_session_revocation",
            actor: &bob,
            target: None,
            operation: "GET /auth/me after revoke-all",
            oracle: Oracle::MustReject,
        },
        &concurrent_check,
    );
    transitions.push(transition(
        "concurrent-sessions-revoked",
        &bob,
        ModuleIdentitySessionPhase::Authenticated,
        ModuleIdentitySessionPhase::Revoked,
        "all-session revocation",
    ));

    let (_, recovery_session) = login(&mut run, &mut vault, "carol", &carol_password)?;
    let recovery =
        run.exchange("POST", "/auth/recover", json!({"username":"carol"}), None, &mut vault)?;
    let recovery_token = secret_field(&recovery, "recovery", &mut vault)?;
    vault.request_field();
    let completed = run.exchange(
        "POST",
        "/auth/recover/complete",
        json!({"recovery":recovery_token}),
        None,
        &mut vault,
    )?;
    require_status(&completed, 200, "account recovery")?;
    let recovery_check =
        run.exchange("GET", "/auth/me", Value::Null, Some(&recovery_session), &mut vault)?;
    admit_case(
        &mut cases,
        &mut findings,
        CaseSpec {
            id: "recovery-invalidates-prior-session",
            category: "account_recovery",
            actor: &carol,
            target: None,
            operation: "GET /auth/me after recovery",
            oracle: Oracle::MustReject,
        },
        &recovery_check,
    );
    transitions.push(transition(
        "recovery-invalidates-prior-session",
        &carol,
        ModuleIdentitySessionPhase::Authenticated,
        ModuleIdentitySessionPhase::Recovered,
        "recovery and prior-token check",
    ));

    let traffic_digest = hex(run.traffic.finalize());
    let mut observation = ModuleIdentityAccessObservation {
        schema: 1,
        laboratory_id: request.laboratory_id.clone(),
        source_snapshot: session.source_snapshot.clone(),
        adapter_version: ADAPTER_VERSION.into(),
        suite_version: SUITE_VERSION.into(),
        identities,
        session_transitions: transitions,
        cases,
        findings,
        redaction: ModuleIdentityRedactionObservation {
            credential_values_checked: u64::try_from(vault.values.len()).unwrap_or(u64::MAX),
            request_fields_redacted: vault.request_fields_redacted,
            response_fields_redacted: vault.response_fields_redacted,
            provider_projection_clean: false,
            projection_digest: String::new(),
        },
        traffic_digest,
        operations_executed: run.operations,
        final_state_digest: run.final_state_digest,
        gaps: vec![
            "The pinned topology uses laboratory-generated identities; external application identity onboarding requires a separately authorized opaque credential import path.".into(),
            "Federated SSO, hardware-backed authenticators, protocol-specific OAuth/OIDC semantics, and application-specific business permissions remain unexamined.".into(),
        ],
    };
    let projection = serde_json::to_vec(&observation).map_err(|error| error.to_string())?;
    if !vault.projection_clean(&projection) {
        return Err("credential bytes reached the module-visible identity projection".into());
    }
    observation.redaction.provider_projection_clean = true;
    observation.redaction.projection_digest = digest(&projection);
    let final_projection = serde_json::to_vec(&observation).map_err(|error| error.to_string())?;
    if !vault.projection_clean(&final_projection) {
        return Err("credential bytes reached the finalized identity projection".into());
    }
    Ok(observation)
}

fn role(
    identity_handle: &str,
    role: &str,
    tenant_handle: &str,
    privileged: bool,
) -> ModuleIdentityRoleObservation {
    ModuleIdentityRoleObservation {
        identity_handle: identity_handle.into(),
        role: role.into(),
        tenant_handle: Some(tenant_handle.into()),
        privileged,
        credential_source: "laboratory_generated".into(),
    }
}

fn transition(
    case_id: &str,
    identity_handle: &str,
    from: ModuleIdentitySessionPhase,
    to: ModuleIdentitySessionPhase,
    operation: &str,
) -> ModuleIdentitySessionTransition {
    ModuleIdentitySessionTransition {
        case_id: case_id.into(),
        identity_handle: identity_handle.into(),
        from,
        to,
        operation: operation.into(),
    }
}

fn login(
    run: &mut Run<'_>,
    vault: &mut Vault,
    username: &str,
    password: &str,
) -> Result<(Exchange, String), String> {
    vault.request_field();
    let exchange = run.exchange(
        "POST",
        "/auth/login",
        json!({"username":username,"password":password}),
        None,
        vault,
    )?;
    let token = secret_field(&exchange, "token", vault)?;
    Ok((exchange, token))
}

fn login_challenge(
    run: &mut Run<'_>,
    vault: &mut Vault,
    username: &str,
    password: &str,
) -> Result<Exchange, String> {
    vault.request_field();
    run.exchange(
        "POST",
        "/auth/login",
        json!({"username":username,"password":password}),
        None,
        vault,
    )
}

fn secret_field(exchange: &Exchange, field: &str, vault: &mut Vault) -> Result<String, String> {
    let body: Value = serde_json::from_str(&exchange.response_body)
        .map_err(|_| format!("identity endpoint did not return JSON for `{field}`"))?;
    let value = body[field]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("identity endpoint omitted `{field}`"))?;
    Ok(vault.response_field(value.into()))
}

fn require_status(exchange: &Exchange, expected: u16, operation: &str) -> Result<(), String> {
    if exchange.response_status == expected {
        Ok(())
    } else {
        Err(format!(
            "{operation} returned status {} instead of {expected}",
            exchange.response_status
        ))
    }
}

fn admit_case(
    cases: &mut Vec<ModuleIdentityAccessCaseObservation>,
    findings: &mut Vec<ModuleIdentityAccessFindingObservation>,
    specification: CaseSpec<'_>,
    exchange: &Exchange,
) {
    let state_change = exchange.state_before_digest != exchange.state_after_digest;
    let (disposition, oracle) = match specification.oracle {
        Oracle::Allowed(status) if exchange.response_status == status => (
            ModuleIdentityAccessDisposition::Passed,
            format!("required legitimate behavior returned {status}"),
        ),
        Oracle::Allowed(status) => (
            ModuleIdentityAccessDisposition::Indeterminate,
            format!("required legitimate behavior expected {status}"),
        ),
        Oracle::MustReject if matches!(exchange.response_status, 401 | 403) => (
            ModuleIdentityAccessDisposition::Rejected,
            "unauthorized or invalid action was rejected".into(),
        ),
        Oracle::MustReject if exchange.response_status == 200 => (
            ModuleIdentityAccessDisposition::Violation,
            "unauthorized or invalid action was accepted".into(),
        ),
        Oracle::MustReject => (
            ModuleIdentityAccessDisposition::Indeterminate,
            "target returned neither a clear rejection nor acceptance".into(),
        ),
        Oracle::MustRejectMutation(_key)
            if matches!(exchange.response_status, 401 | 403) && !state_change =>
        {
            (
                ModuleIdentityAccessDisposition::Rejected,
                "unauthorized mutation was rejected without copied-state change".into(),
            )
        }
        Oracle::MustRejectMutation(key)
            if exchange.response_status == 200
                && exchange.changed_state_keys.iter().any(|changed| changed == key) =>
        {
            (
                ModuleIdentityAccessDisposition::Violation,
                format!("unauthorized mutation changed copied-state key `{key}`"),
            )
        }
        Oracle::MustRejectMutation(_) => (
            ModuleIdentityAccessDisposition::Indeterminate,
            "mutation response and copied-state oracle did not agree".into(),
        ),
    };
    let replay_digest = digest(
        format!(
            "peritus.identity-replay.v1\0{}\0{}\0{}\0{}",
            specification.id,
            specification.actor,
            specification.target.unwrap_or("none"),
            specification.operation,
        )
        .as_bytes(),
    );
    if disposition == ModuleIdentityAccessDisposition::Violation {
        let (severity, standards) = finding_metadata(specification.category);
        findings.push(ModuleIdentityAccessFindingObservation {
            id: format!("identity-{}", &digest(replay_digest.as_bytes())[..24]),
            case_id: specification.id.into(),
            category: specification.category.into(),
            severity,
            message: format!(
                "Host differential and lifecycle oracles confirmed `{}`",
                specification.category
            ),
            evidence_state: "runtime_confirmed".into(),
            standards,
            replay_digest: replay_digest.clone(),
        });
    }
    cases.push(ModuleIdentityAccessCaseObservation {
        id: specification.id.into(),
        category: specification.category.into(),
        disposition,
        actor_identity: specification.actor.into(),
        target_identity: specification.target.map(str::to_owned),
        operation: specification.operation.into(),
        response_status: exchange.response_status,
        state_change_observed: state_change,
        oracle,
        replay_digest,
    });
}

fn finding_metadata(category: &str) -> (ModuleSourceSeverity, Vec<String>) {
    let standards = match category {
        "missing_authentication" => vec!["CWE-306"],
        "vertical_authorization" => vec!["CWE-269", "CWE-863"],
        "tenant_isolation" | "adjacent_route_authorization" => vec!["CWE-863"],
        "object_ownership" => vec!["CWE-639"],
        "multi_factor_authentication" => vec!["CWE-308"],
        "account_recovery" => vec!["CWE-640"],
        _ => vec!["CWE-613"],
    };
    (ModuleSourceSeverity::High, standards.into_iter().map(str::to_owned).collect())
}

fn credential(seed: &[u8], label: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"peritus-phase15-v1\0");
    hasher.update(seed);
    hasher.update(label.as_bytes());
    hex(hasher.finalize())
}

fn opaque(laboratory_id: &str, kind: &str, label: &str) -> String {
    digest(format!("peritus.identity-handle.v1\0{laboratory_id}\0{kind}\0{label}").as_bytes())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if path.is_symlink() {
        return Err("identity observation path is a symbolic link".into());
    }
    fs::write(path, bytes).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
}

fn digest(bytes: &[u8]) -> String {
    hex(Sha256::digest(bytes))
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|byte| format!("{byte:02x}")).collect()
}
