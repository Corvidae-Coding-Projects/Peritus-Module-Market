//! Module-owned real-browser campaign adapter for disposable application laboratories.

use super::runtime_laboratory::{Broker, BrowserLaboratorySession};
use peritus_plugin_sdk::{
    ModuleBrowserArtifact, ModuleBrowserCampaignRequest, ModuleBrowserCaseObservation,
    ModuleBrowserCoverageNode, ModuleBrowserDisposition, ModuleBrowserFindingObservation,
    ModuleBrowserObservation, ModuleSourceSeverity,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

const PROFILE: &str = "peritus.browser-client.standard@1";
const ADAPTER_VERSION: &str = "peritus-browser-client-2026-10-24.1";
const SUITE_VERSION: &str = "peritus-browser-client-suite-2026-10-24.1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRun {
    schema: u16,
    browser_identity: String,
    cases: Vec<RawCase>,
    coverage: Vec<ModuleBrowserCoverageNode>,
    artifacts: Vec<RawArtifact>,
    traffic_digest: String,
    requests_observed: u64,
    actions_executed: u64,
    context_isolation_observed: bool,
    off_scope_requests_blocked: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawCase {
    id: String,
    category: String,
    browser_effect: String,
    request_paths: Vec<String>,
    observed: bool,
    replay_digest: String,
    replayed_after_reset: bool,
    extra: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawArtifact {
    kind: String,
    path: PathBuf,
    digest: String,
    bytes: u64,
    case_id: Option<String>,
}

pub(super) fn execute(
    request: ModuleBrowserCampaignRequest,
    request_key: &str,
    module_id: &str,
    module_digest: &str,
    host_state: &Path,
    laboratory: &Broker,
) -> Result<ModuleBrowserObservation, String> {
    validate_request(&request)?;
    let identity = digest(
        format!(
            "peritus.browser-campaign.v1\0{module_id}\0{module_digest}\0{request_key}\0{}\0{}",
            request.laboratory_id, request.endpoint_handle
        )
        .as_bytes(),
    );
    let root = host_state.join("browser-campaigns-v1");
    fs::create_dir_all(&root).map_err(|error| error.to_string())?;
    let retained = root.join(&identity).join("observation.json");
    if retained.is_file() && !retained.is_symlink() {
        return serde_json::from_slice(&fs::read(retained).map_err(|error| error.to_string())?)
            .map_err(|error| format!("retained browser observation is invalid: {error}"));
    }
    let session = laboratory.browser_session(
        &request.laboratory_id,
        &request.endpoint_handle,
        request.maximum_requests,
    )?;
    let staging = tempfile::Builder::new()
        .prefix("browser-campaign-")
        .tempdir_in(&root)
        .map_err(|error| error.to_string())?;
    let raw: RawRun = serde_json::from_value(crate::runtime_browser::campaign(
        staging.path(),
        &session.target_socket,
        &session.attacker_socket,
        request.maximum_actions,
        request.maximum_requests,
    )?)
    .map_err(|error| format!("browser controller returned an invalid observation: {error}"))?;
    let observation = admit_raw(&request, &session, staging.path(), raw)?;
    laboratory.record_browser_observation(
        &request.laboratory_id,
        &request.endpoint_handle,
        observation.requests_observed,
        &observation.final_state_digest,
    )?;
    let bytes = serde_json::to_vec(&observation).map_err(|error| error.to_string())?;
    write_private(&staging.path().join("observation.json"), &bytes)?;
    let destination = root.join(identity);
    fs::rename(staging.keep(), &destination)
        .map_err(|error| format!("retain browser campaign: {error}"))?;
    Ok(observation)
}

fn validate_request(request: &ModuleBrowserCampaignRequest) -> Result<(), String> {
    if request.schema != 1 || request.profile != PROFILE {
        return Err("browser campaign requires schema 1 and the registered profile".into());
    }
    if request.laboratory_id.len() != 64
        || request.endpoint_handle.len() != 64
        || !request.laboratory_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !request.endpoint_handle.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("browser campaign requires opaque laboratory and endpoint identities".into());
    }
    if !(32..=128).contains(&request.maximum_actions)
        || !(32..=256).contains(&request.maximum_requests)
        || !(1024 * 1024..=32 * 1024 * 1024).contains(&request.maximum_artifact_bytes)
    {
        return Err("browser campaign bounds are outside the registered profile".into());
    }
    Ok(())
}

fn admit_raw(
    request: &ModuleBrowserCampaignRequest,
    session: &BrowserLaboratorySession,
    artifact_root: &Path,
    raw: RawRun,
) -> Result<ModuleBrowserObservation, String> {
    if raw.schema != 1
        || raw.browser_identity.is_empty()
        || raw.traffic_digest.len() != 64
        || raw.actions_executed > u64::from(request.maximum_actions)
        || raw.requests_observed > u64::from(request.maximum_requests)
    {
        return Err("browser controller violated the registered result schema or bounds".into());
    }
    let expected = [
        "baseline-navigation",
        "reflected-script",
        "stored-script",
        "dom-script",
        "csp-inline",
        "cookie-policy",
        "cross-origin-request",
        "csrf-form",
        "server-validation",
        "bounded-crawl",
        "download-correlation",
        "upload-correlation",
        "off-scope-block",
        "reset-replay",
    ];
    let ids = raw.cases.iter().map(|case| case.id.clone()).collect::<BTreeSet<_>>();
    if raw.cases.len() != expected.len() || expected.iter().any(|id| !ids.contains(*id)) {
        return Err("browser controller omitted or duplicated a pinned suite case".into());
    }
    let (state_bytes, state): (Vec<u8>, BTreeMap<String, String>) = {
        let bytes = fs::read(&session.state_path)
            .map_err(|error| format!("read copied browser state: {error}"))?;
        let state = serde_json::from_slice(&bytes)
            .map_err(|error| format!("decode copied browser state: {error}"))?;
        (bytes, state)
    };
    let mut findings = Vec::new();
    let mut cases = Vec::new();
    for case in raw.cases {
        if case.replay_digest.len() != 64
            || case.request_paths.iter().any(|path| !path.starts_with('/'))
        {
            return Err("browser case has an invalid replay identity or request path".into());
        }
        let (disposition, server_effect, severity, standards) = classify(&case, &state);
        if disposition == ModuleBrowserDisposition::Violation {
            let finding_id = format!("browser-{}", &digest(case.replay_digest.as_bytes())[..24]);
            findings.push(ModuleBrowserFindingObservation {
                id: finding_id,
                case_id: case.id.clone(),
                category: case.category.clone(),
                severity,
                message: format!(
                    "Real browser behavior and the copied application state confirmed `{}`",
                    case.category
                ),
                evidence_state: "runtime_confirmed".into(),
                state_change_observed: server_effect.starts_with("copied state"),
                standards,
                replay_digest: case.replay_digest.clone(),
            });
        }
        cases.push(ModuleBrowserCaseObservation {
            id: case.id,
            category: case.category,
            disposition,
            browser_effect: case.browser_effect,
            server_effect,
            request_paths: case.request_paths,
            replay_digest: case.replay_digest,
            replayed_after_reset: case.replayed_after_reset,
        });
    }
    let artifacts =
        validate_artifacts(artifact_root, raw.artifacts, request.maximum_artifact_bytes, &ids)?;
    if !artifacts.iter().any(|item| item.kind == "trace")
        || !artifacts.iter().any(|item| item.kind == "traffic")
        || !artifacts.iter().any(|item| item.kind == "download")
        || !artifacts.iter().any(|item| item.kind == "upload")
        || artifacts.iter().filter(|item| item.kind == "screenshot").count() < 3
    {
        return Err("browser campaign did not retain its required evidence artifacts".into());
    }
    Ok(ModuleBrowserObservation {
        schema: 1,
        laboratory_id: request.laboratory_id.clone(),
        source_snapshot: session.source_snapshot.clone(),
        adapter_version: ADAPTER_VERSION.into(),
        suite_version: SUITE_VERSION.into(),
        browser_identity: raw.browser_identity,
        cases,
        findings,
        coverage: raw.coverage,
        artifacts,
        traffic_digest: raw.traffic_digest,
        requests_observed: raw.requests_observed,
        actions_executed: raw.actions_executed,
        final_state_digest: digest(&state_bytes),
        context_isolation_observed: raw.context_isolation_observed,
        off_scope_requests_blocked: raw.off_scope_requests_blocked,
        gaps: vec![
            "This adapter exercises Chromium through Playwright; additional browser engines remain unexamined.".into(),
            "The pinned client campaign does not replace application-specific authenticated business-logic exploration.".into(),
        ],
    })
}

fn classify(
    case: &RawCase,
    state: &BTreeMap<String, String>,
) -> (ModuleBrowserDisposition, String, ModuleSourceSeverity, Vec<String>) {
    let mapping = match case.id.as_str() {
        "reflected-script" => {
            Some(("signal_reflected", ModuleSourceSeverity::High, vec!["CWE-79"]))
        }
        "stored-script" => Some(("signal_stored", ModuleSourceSeverity::High, vec!["CWE-79"])),
        "dom-script" => Some(("signal_dom", ModuleSourceSeverity::High, vec!["CWE-79"])),
        "csp-inline" => Some(("signal_csp", ModuleSourceSeverity::Medium, vec!["CWE-693"])),
        "cross-origin-request" => {
            Some(("origin_mutations", ModuleSourceSeverity::High, vec!["CWE-346"]))
        }
        "csrf-form" => Some(("csrf_transfers", ModuleSourceSeverity::High, vec!["CWE-352"])),
        "server-validation" => {
            Some(("invalid_submissions", ModuleSourceSeverity::Medium, vec!["CWE-602"]))
        }
        _ => None,
    };
    if let Some((key, severity, standards)) = mapping {
        return if state.contains_key(key) {
            (
                ModuleBrowserDisposition::Violation,
                format!("copied state recorded `{key}`"),
                severity,
                standards.into_iter().map(str::to_owned).collect(),
            )
        } else {
            (
                ModuleBrowserDisposition::Rejected,
                format!("copied state has no `{key}` effect"),
                severity,
                standards.into_iter().map(str::to_owned).collect(),
            )
        };
    }
    if case.id == "cookie-policy" {
        let safe = case.extra["safe_cookie"].as_bool().unwrap_or(false);
        return if safe {
            (
                ModuleBrowserDisposition::Passed,
                "browser observed HttpOnly, Secure and SameSite=Strict".into(),
                ModuleSourceSeverity::Medium,
                vec!["CWE-614".into(), "CWE-1004".into()],
            )
        } else {
            (
                ModuleBrowserDisposition::Violation,
                "browser observed a session cookie without the complete safe flag set".into(),
                ModuleSourceSeverity::Medium,
                vec!["CWE-614".into(), "CWE-1004".into()],
            )
        };
    }
    let observed = if case.id == "upload-correlation" {
        state
            .get("upload_digest")
            .is_some_and(|value| value == case.extra["digest"].as_str().unwrap_or_default())
    } else if case.id == "reset-replay" {
        case.observed && case.extra["fresh_context"].as_bool() == Some(true)
    } else {
        case.observed
    };
    (
        if observed {
            ModuleBrowserDisposition::Passed
        } else {
            ModuleBrowserDisposition::Indeterminate
        },
        if observed {
            "module oracle matched the expected bounded browser effect".into()
        } else {
            "module oracle could not establish the expected browser effect".into()
        },
        ModuleSourceSeverity::Informational,
        Vec::new(),
    )
}

fn validate_artifacts(
    root: &Path,
    artifacts: Vec<RawArtifact>,
    maximum_bytes: u64,
    case_ids: &BTreeSet<String>,
) -> Result<Vec<ModuleBrowserArtifact>, String> {
    let canonical_root = root.canonicalize().map_err(|error| error.to_string())?;
    let mut total = 0_u64;
    let mut admitted = Vec::new();
    for artifact in artifacts {
        let path = artifact.path.canonicalize().map_err(|error| error.to_string())?;
        if !path.starts_with(&canonical_root)
            || artifact
                .case_id
                .as_deref()
                .is_some_and(|id| id != "campaign-final" && !case_ids.contains(id))
        {
            return Err("browser artifact is outside its campaign or names an unknown case".into());
        }
        let bytes = fs::read(&path).map_err(|error| error.to_string())?;
        total = total.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if artifact.bytes != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
            || artifact.digest != digest(&bytes)
            || total > maximum_bytes
        {
            return Err("browser artifact identity or aggregate bound is invalid".into());
        }
        admitted.push(ModuleBrowserArtifact {
            kind: artifact.kind,
            digest: artifact.digest,
            bytes: artifact.bytes,
            case_id: artifact.case_id,
        });
    }
    Ok(admitted)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if path.is_symlink() {
        return Err("browser observation path is a symbolic link".into());
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

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}
