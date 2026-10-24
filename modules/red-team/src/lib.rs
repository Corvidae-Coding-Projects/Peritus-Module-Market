//! Phase 5 Red Team coordinator: bounded discovery, contained probes and skeptical adjudication.

mod investigation;
pub mod records;
mod report;
mod state;

use peritus_plugin_sdk::{
    HOST_CAPABILITY_CHECKPOINT, HOST_CAPABILITY_OWNED_JOBS, HOST_CAPABILITY_PRIVATE_STATE,
    HOST_CAPABILITY_PROFILE, HOST_CAPABILITY_SCOPED_SOURCE, MODULE_HOST_CONTRACT_VERSION,
    ModuleAction, ModuleAttachment, ModuleHostOutcome, ModuleHostProfile, ModuleHostRequest,
    ModuleHostResult, ModuleJobCancelRequest, ModuleJobHandle, ModuleJobLimits, ModuleJobLogPage,
    ModuleJobLogRequest, ModuleJobPhase, ModuleJobRequest, ModuleJobStatus, ModuleJobStatusRequest,
    ModuleJobStream, ModuleMenuAction, ScopedSourceHandle, ScopedSourceManifestPage,
    ScopedSourceManifestRequest, ScopedSourceReadRequest, ScopedSourceReadResult,
    ScopedSourceRequest, ScopedSourceRevocation, ScopedSourceRevokeRequest,
};
use records::{
    CampaignState, EvidenceKind, EvidenceRecord, RECORD_SCHEMA_VERSION, RecordId, RecordKind,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use state::{ObservationState, PendingRequest, SkeletonCheckpoint, SourceObservation, State};

const CHECKPOINT_KEY: &str = "red-team-phase-5-investigation-v1";
const COMPATIBILITY_KEY: &str = "red-team-phase-5-host-profile";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("red-team input: {0}")]
    Invalid(String),
    #[error("red-team storage: {0}")]
    Io(#[from] std::io::Error),
    #[error("red-team JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// Dispatches one host-owned native module operation.
pub fn dispatch(method: &str, parameters: &Value) -> Result<Value, Error> {
    if method == "tool" {
        return investigation::tool(parameters);
    }
    let action = match method {
        "command" => command(parameters)?,
        "checkpoint_ack" => checkpoint_ack(parameters)?,
        "host_result" => host_result(parameters)?,
        "model_result" => investigation::model_result(parameters)?,
        "observe" => reply(
            "Red Team roles have no ambient host tools. Source and execution evidence must pass through module-defined scoped-source and contained-job operations.",
            &profile(parameters),
            base_actions(),
            None,
        ),
        _ => return Err(invalid(format!("unsupported module method: {method}"))),
    };
    Ok(serde_json::to_value(action)?)
}

fn command(parameters: &Value) -> Result<ModuleAction, Error> {
    let command = parameters["text"].as_str().unwrap_or_default().trim();
    let host = profile(parameters);
    if command == "compatibility" {
        return compatibility(host);
    }
    if command == "contract" {
        return contract(&host);
    }
    if command == "checkpoint" {
        return checkpoint(parameters, &host);
    }
    let mut state = state::load(parameters)?;
    if let Some(pending) = state.pending.as_ref() {
        if command == "resume" {
            return resume_pending(pending);
        }
        return Ok(reply(
            "A retained host-service request is unfinished. Use resume to reissue that retained request; no new command was accepted.",
            &host,
            base_actions(),
            None,
        ));
    }
    if command == "start" {
        return investigation::start(parameters, &host, &mut state);
    }
    if command == "pause" {
        return investigation::pause(parameters, &mut state);
    }
    if command == "resume"
        && !matches!(state.investigation.stage, state::InvestigationStage::NotStarted)
    {
        return investigation::resume(parameters, &host, &mut state);
    }
    if let Some(direction) = command.strip_prefix("steer ") {
        return investigation::steer(parameters, &mut state, direction);
    }
    if command.is_empty() || matches!(command, "status" | "resume") {
        return Ok(reply(status(&state), &host, actions(&state), None));
    }
    if command == "coverage" {
        return Ok(reply(coverage(&state), &host, actions(&state), None));
    }
    if command == "report" || command == "report-json" {
        let attachment = report::publish_report(
            &state::private_root(parameters)?,
            &mut state,
            command == "report-json",
        )?;
        state::save(parameters, &state)?;
        return Ok(reply(
            "The current Phase 5 report was published from retained source observations, registered hypotheses, host-authored proof receipts and independent skeptical decisions. Pending work and every unexamined family remain explicit gaps.",
            &host,
            actions(&state),
            Some(attachment),
        ));
    }
    if command == "scope" || command.starts_with("scope exclude ") {
        return scope(parameters, &host, &mut state, command);
    }
    if command == "refresh" {
        return refresh(parameters, &host, &mut state);
    }
    if command == "manifest" || command.starts_with("manifest ") {
        return manifest(parameters, &host, &mut state, command);
    }
    if command.starts_with("observe ") {
        return observe(parameters, &host, &mut state, command);
    }
    if command == "revoke" {
        return revoke(parameters, &host, &mut state);
    }
    if command.starts_with("probe ") {
        return submit_probe(parameters, &host, &mut state, command);
    }
    if command.starts_with("prepare ") {
        return submit_preparation(parameters, &host, &mut state, command);
    }
    if command == "jobs" {
        return Ok(reply(jobs(&state), &host, actions(&state), None));
    }
    if command.starts_with("job ") {
        return poll_job(parameters, &host, &mut state, command);
    }
    if command.starts_with("job-log ") {
        return job_log(parameters, &host, &mut state, command);
    }
    if command.starts_with("job-cancel ") {
        return cancel_job(parameters, &host, &mut state, command);
    }
    Ok(reply(
        "Unknown Red Team Phase 5 command. Use start, status, pause, resume, steer DETAILS, scope, refresh, manifest, observe PATH [offset=N] [bytes=N], prepare HTTPS_URL sha256=DIGEST [bytes=N], probe PATH [input=LITERAL], jobs, job ID, job-log ID STREAM [offset=N] [bytes=N], job-cancel ID, coverage, report, report-json, revoke, compatibility, contract, or checkpoint.",
        &host,
        actions(&state),
        None,
    ))
}

fn submit_preparation(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut State,
    command: &str,
) -> Result<ModuleAction, Error> {
    if !supports_jobs(profile) {
        return Ok(jobs_unavailable(profile));
    }
    let authority = state
        .active_handle()
        .ok_or_else(|| invalid("select source with scope before preparing a dependency"))?;
    let (url, expected_sha256, maximum_bytes) = parse_preparation(command)?;
    let key = format!("red-team-preparation-submit-{}", state.jobs.len() + 1);
    let request = ModuleJobRequest {
        schema: 1,
        source_handle: authority.handle,
        scope_revision: authority.scope_revision,
        operation: "https.dependency-fetch.v1".into(),
        specification: json!({
            "url": url,
            "expected_sha256": expected_sha256,
            "maximum_bytes": maximum_bytes,
        }),
        limits: ModuleJobLimits {
            memory_bytes: 128 * 1024 * 1024,
            storage_bytes: maximum_bytes,
            cpu_millis: 1_000,
            wall_millis: 120_000,
            processes: 1,
        },
    };
    state.pending = Some(PendingRequest::JobSubmit { key: key.clone(), request: request.clone() });
    state::save(parameters, state)?;
    Ok(job_service(key, "submit", serde_json::to_value(request)?))
}

fn submit_probe(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut State,
    command: &str,
) -> Result<ModuleAction, Error> {
    if !supports_jobs(profile) {
        return Ok(jobs_unavailable(profile));
    }
    let authority = state
        .active_handle()
        .ok_or_else(|| invalid("select source with scope before submitting a contained job"))?;
    let (target_path, attacker_input) = parse_probe(command)?;
    let key = format!("red-team-job-submit-{}", state.jobs.len() + 1);
    let request = ModuleJobRequest {
        schema: 1,
        source_handle: authority.handle,
        scope_revision: authority.scope_revision,
        operation: "linux.canary-disclosure.v1".into(),
        specification: json!({
            "target_path": target_path,
            "attacker_input": attacker_input,
        }),
        limits: ModuleJobLimits {
            memory_bytes: 128 * 1024 * 1024,
            storage_bytes: 64 * 1024 * 1024,
            cpu_millis: 30_000,
            wall_millis: 30_000,
            processes: 4,
        },
    };
    state.pending = Some(PendingRequest::JobSubmit { key: key.clone(), request: request.clone() });
    state::save(parameters, state)?;
    Ok(ModuleAction::HostService {
        request: ModuleHostRequest {
            key,
            capability: HOST_CAPABILITY_OWNED_JOBS.into(),
            version: 1,
            operation: "submit".into(),
            input: serde_json::to_value(request)?,
        },
    })
}

fn poll_job(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut State,
    command: &str,
) -> Result<ModuleAction, Error> {
    if !supports_jobs(profile) {
        return Ok(jobs_unavailable(profile));
    }
    let job_id = command
        .strip_prefix("job ")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("job command is missing an exact job identity"))?
        .to_owned();
    let key = format!("red-team-job-poll-{}", &job_id[..job_id.len().min(16)]);
    let request = ModuleJobStatusRequest { schema: 1, job_id, wait_millis: 750 };
    state.pending = Some(PendingRequest::JobPoll { key: key.clone(), request: request.clone() });
    state::save(parameters, state)?;
    Ok(job_service(key, "poll", serde_json::to_value(request)?))
}

fn job_log(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut State,
    command: &str,
) -> Result<ModuleAction, Error> {
    if !supports_jobs(profile) {
        return Ok(jobs_unavailable(profile));
    }
    let (job_id, stream, offset, maximum_bytes) = parse_job_log(command)?;
    let key = format!("red-team-job-log-{}", &job_id[..job_id.len().min(16)]);
    let request = ModuleJobLogRequest { schema: 1, job_id, stream, offset, maximum_bytes };
    state.pending = Some(PendingRequest::JobLog { key: key.clone(), request: request.clone() });
    state::save(parameters, state)?;
    Ok(job_service(key, "log", serde_json::to_value(request)?))
}

fn cancel_job(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut State,
    command: &str,
) -> Result<ModuleAction, Error> {
    if !supports_jobs(profile) {
        return Ok(jobs_unavailable(profile));
    }
    let job_id = command
        .strip_prefix("job-cancel ")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("job-cancel command is missing an exact job identity"))?
        .to_owned();
    let key = format!("red-team-job-cancel-{}", &job_id[..job_id.len().min(16)]);
    let request = ModuleJobCancelRequest {
        schema: 1,
        job_id,
        reason: "explicit Red Team user cancellation".into(),
    };
    state.pending = Some(PendingRequest::JobCancel { key: key.clone(), request: request.clone() });
    state::save(parameters, state)?;
    Ok(job_service(key, "cancel", serde_json::to_value(request)?))
}

fn job_service(key: String, operation: &str, input: Value) -> ModuleAction {
    ModuleAction::HostService {
        request: ModuleHostRequest {
            key,
            capability: HOST_CAPABILITY_OWNED_JOBS.into(),
            version: 1,
            operation: operation.into(),
            input,
        },
    }
}

fn scope(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut State,
    command: &str,
) -> Result<ModuleAction, Error> {
    if !supports_source(profile) {
        return Ok(source_unavailable(profile));
    }
    let exclusions = command
        .strip_prefix("scope exclude ")
        .map(|values| {
            values
                .split_whitespace()
                .flat_map(|value| value.split(','))
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let key = format!("red-team-scope-{}", state.scopes.len() + 1);
    state.pending = Some(PendingRequest::Capture {
        key: key.clone(),
        exclusions: exclusions.clone(),
        refresh: None,
    });
    state::save(parameters, state)?;
    Ok(ModuleAction::HostService {
        request: ModuleHostRequest {
            key,
            capability: HOST_CAPABILITY_SCOPED_SOURCE.into(),
            version: 1,
            operation: "capture".into(),
            input: serde_json::to_value(ScopedSourceRequest {
                schema: 1,
                purpose: "Create an inert immutable Red Team source snapshot of the explicitly opened Peritus workspace.".into(),
                immutable_snapshot: true,
                exclusions,
                refresh: None,
            })?,
        },
    })
}

fn refresh(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut State,
) -> Result<ModuleAction, Error> {
    if !supports_source(profile) {
        return Ok(source_unavailable(profile));
    }
    let authority = state
        .active_handle()
        .ok_or_else(|| invalid("select source with scope before refreshing"))?;
    let exclusions = state.scopes.last().map(|scope| scope.exclusions.clone()).unwrap_or_default();
    let key = format!("red-team-refresh-{}", state.scopes.len() + 1);
    state.pending = Some(PendingRequest::Capture {
        key: key.clone(),
        exclusions: exclusions.clone(),
        refresh: Some(authority.clone()),
    });
    state::save(parameters, state)?;
    Ok(ModuleAction::HostService {
        request: ModuleHostRequest {
            key,
            capability: HOST_CAPABILITY_SCOPED_SOURCE.into(),
            version: 1,
            operation: "capture".into(),
            input: serde_json::to_value(ScopedSourceRequest {
                schema: 1,
                purpose: "Refresh the exact retained Red Team source scope and selectively invalidate dependent evidence.".into(),
                immutable_snapshot: true,
                exclusions,
                refresh: Some(authority),
            })?,
        },
    })
}

fn manifest(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut State,
    command: &str,
) -> Result<ModuleAction, Error> {
    if !supports_source(profile) {
        return Ok(source_unavailable(profile));
    }
    let authority = state
        .active_handle()
        .ok_or_else(|| invalid("select source with scope before reading its manifest"))?;
    let after = command.strip_prefix("manifest ").map(str::trim).filter(|value| !value.is_empty());
    let key = format!("red-team-manifest-{}", state.scopes.len());
    let after = after.map(str::to_owned);
    state.pending = Some(PendingRequest::Manifest {
        key: key.clone(),
        authority: authority.clone(),
        after: after.clone(),
        maximum_entries: 100,
    });
    state::save(parameters, state)?;
    Ok(ModuleAction::HostService {
        request: ModuleHostRequest {
            key,
            capability: HOST_CAPABILITY_SCOPED_SOURCE.into(),
            version: 1,
            operation: "manifest".into(),
            input: serde_json::to_value(ScopedSourceManifestRequest {
                schema: 1,
                authority,
                after,
                maximum_entries: 100,
            })?,
        },
    })
}

fn observe(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut State,
    command: &str,
) -> Result<ModuleAction, Error> {
    if !supports_source(profile) {
        return Ok(source_unavailable(profile));
    }
    let authority = state
        .active_handle()
        .ok_or_else(|| invalid("select source with scope before observing it"))?;
    let (path, offset, maximum_bytes) = parse_observe(command)?;
    let key = format!("red-team-read-{}", state.observations.len() + 1);
    state.pending = Some(PendingRequest::Read {
        key: key.clone(),
        authority: authority.clone(),
        path: path.clone(),
        offset,
        maximum_bytes,
    });
    state::save(parameters, state)?;
    Ok(ModuleAction::HostService {
        request: ModuleHostRequest {
            key,
            capability: HOST_CAPABILITY_SCOPED_SOURCE.into(),
            version: 1,
            operation: "read".into(),
            input: serde_json::to_value(ScopedSourceReadRequest {
                schema: 1,
                authority,
                path,
                offset,
                maximum_bytes,
            })?,
        },
    })
}

fn revoke(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut State,
) -> Result<ModuleAction, Error> {
    if !supports_source(profile) {
        return Ok(source_unavailable(profile));
    }
    let authority = state
        .active_handle()
        .ok_or_else(|| invalid("select source with scope before revoking it"))?;
    let key = format!("red-team-revoke-{}", state.scopes.len());
    state.pending = Some(PendingRequest::Revoke { key: key.clone(), authority: authority.clone() });
    state::save(parameters, state)?;
    Ok(ModuleAction::HostService {
        request: ModuleHostRequest {
            key,
            capability: HOST_CAPABILITY_SCOPED_SOURCE.into(),
            version: 1,
            operation: "revoke".into(),
            input: serde_json::to_value(ScopedSourceRevokeRequest { schema: 1, authority })?,
        },
    })
}

pub(crate) fn resume_pending(pending: &PendingRequest) -> Result<ModuleAction, Error> {
    let (capability, operation, input) = match pending {
        PendingRequest::Capture { exclusions, refresh, .. } => (
            HOST_CAPABILITY_SCOPED_SOURCE,
            "capture",
            serde_json::to_value(ScopedSourceRequest {
                schema: 1,
                purpose: if refresh.is_some() {
                    "Refresh the exact retained Red Team source scope and selectively invalidate dependent evidence."
                } else {
                    "Create an inert immutable Red Team source snapshot of the explicitly opened Peritus workspace."
                }
                .into(),
                immutable_snapshot: true,
                exclusions: exclusions.clone(),
                refresh: refresh.clone(),
            })?,
        ),
        PendingRequest::Manifest { authority, after, maximum_entries, .. } => (
            HOST_CAPABILITY_SCOPED_SOURCE,
            "manifest",
            serde_json::to_value(ScopedSourceManifestRequest {
                schema: 1,
                authority: authority.clone(),
                after: after.clone(),
                maximum_entries: *maximum_entries,
            })?,
        ),
        PendingRequest::Read { authority, path, offset, maximum_bytes, .. } => (
            HOST_CAPABILITY_SCOPED_SOURCE,
            "read",
            serde_json::to_value(ScopedSourceReadRequest {
                schema: 1,
                authority: authority.clone(),
                path: path.clone(),
                offset: *offset,
                maximum_bytes: *maximum_bytes,
            })?,
        ),
        PendingRequest::Revoke { authority, .. } => (
            HOST_CAPABILITY_SCOPED_SOURCE,
            "revoke",
            serde_json::to_value(ScopedSourceRevokeRequest {
                schema: 1,
                authority: authority.clone(),
            })?,
        ),
        PendingRequest::JobSubmit { request, .. } => (
            HOST_CAPABILITY_OWNED_JOBS,
            "submit",
            serde_json::to_value(request)?,
        ),
        PendingRequest::JobPoll { request, .. } => (
            HOST_CAPABILITY_OWNED_JOBS,
            "poll",
            serde_json::to_value(request)?,
        ),
        PendingRequest::JobLog { request, .. } => (
            HOST_CAPABILITY_OWNED_JOBS,
            "log",
            serde_json::to_value(request)?,
        ),
        PendingRequest::JobCancel { request, .. } => (
            HOST_CAPABILITY_OWNED_JOBS,
            "cancel",
            serde_json::to_value(request)?,
        ),
    };
    Ok(ModuleAction::HostService {
        request: ModuleHostRequest {
            key: pending.key().to_owned(),
            capability: capability.into(),
            version: 1,
            operation: operation.into(),
            input,
        },
    })
}

fn host_result(parameters: &Value) -> Result<ModuleAction, Error> {
    let result: ModuleHostResult = serde_json::from_value(
        parameters
            .get("result")
            .cloned()
            .ok_or_else(|| invalid("host_result is missing result"))?,
    )?;
    if result.key == COMPATIBILITY_KEY {
        return compatibility_result(result, &profile(parameters));
    }
    let mut state = state::load(parameters)?;
    let pending = state
        .pending
        .clone()
        .ok_or_else(|| invalid("host_result has no retained pending request"))?;
    let expected_capability = pending_capability(&pending);
    if result.key != pending.key()
        || result.capability != expected_capability
        || result.version != 1
    {
        return Err(invalid("host_result does not match the retained host-service request"));
    }
    let host = profile(parameters);
    let output = match result.outcome {
        ModuleHostOutcome::Success { output } => output,
        ModuleHostOutcome::Unsupported { detail } => {
            state.pending = None;
            if result.key.starts_with("red-team-investigation-") {
                investigation::host_failure(&mut state, &pending, &detail);
                state::save(parameters, &state)?;
                return investigation::next(parameters, &host, &mut state);
            }
            state::save(parameters, &state)?;
            return Ok(reply(
                format!(
                    "Host capability `{expected_capability}` is unavailable: {detail}. No ambient fallback was attempted."
                ),
                &host,
                actions(&state),
                None,
            ));
        }
        ModuleHostOutcome::Rejected { code, detail } => {
            state.pending = None;
            if result.key.starts_with("red-team-investigation-") {
                investigation::host_failure(
                    &mut state,
                    &pending,
                    &format!("host rejection {code}: {detail}"),
                );
                state::save(parameters, &state)?;
                return investigation::next(parameters, &host, &mut state);
            }
            state::save(parameters, &state)?;
            return Ok(reply(
                format!(
                    "Host request `{expected_capability}` was rejected (`{code}`): {detail}. No forbidden operation was performed."
                ),
                &host,
                actions(&state),
                None,
            ));
        }
        ModuleHostOutcome::Failed { code, detail, retryable_with_new_action } => {
            state.pending = None;
            if result.key.starts_with("red-team-investigation-") {
                investigation::host_failure(
                    &mut state,
                    &pending,
                    &format!(
                        "host failure {code}: {detail}; retryable={retryable_with_new_action}"
                    ),
                );
                state::save(parameters, &state)?;
                return investigation::next(parameters, &host, &mut state);
            }
            state::save(parameters, &state)?;
            return Ok(reply(
                format!(
                    "Host request `{expected_capability}` failed (`{code}`): {detail}. Retryable with a new action: {retryable_with_new_action}. No incomplete result was admitted."
                ),
                &host,
                actions(&state),
                None,
            ));
        }
    };
    let text = match pending {
        PendingRequest::Capture { .. } => {
            let handle: ScopedSourceHandle = serde_json::from_value(output)?;
            state.admit_scope(&handle)?;
            format!(
                "# Source scope captured\n\n- Source: `{}`\n- Scope revision: `{}`\n- Snapshot: `{}`\n- Manifest artifact: `{}`\n- Included files: {}\n- Included bytes: {}\n- Reused unchanged files: {} ({} bytes)\n- Changed dependent paths: {}\n- Removed dependent paths: {}\n- Exclusions: {}\n\nThe original workspace was inspected without executing target code. Every security family remains unexamined.",
                handle.display_name,
                handle.scope_revision,
                handle.snapshot_digest,
                handle.manifest_artifact,
                handle.file_count,
                handle.total_bytes,
                handle.reused_files,
                handle.reused_bytes,
                list_or_none(&handle.changed_paths),
                list_or_none(&handle.removed_paths),
                list_or_none(&handle.exclusions),
            )
        }
        PendingRequest::Manifest { .. } => {
            let page: ScopedSourceManifestPage = serde_json::from_value(output)?;
            if result.key.starts_with("red-team-investigation-manifest-") {
                let next_after =
                    investigation::admit_manifest_page(&mut state, page.entries, page.next_after);
                state.pending = None;
                state::save(parameters, &state)?;
                return if let Some(after) = next_after {
                    investigation::request_manifest(parameters, &mut state, Some(after))
                } else {
                    investigation::next(parameters, &host, &mut state)
                };
            }
            let mut text = format!(
                "# Source manifest\n\nSnapshot `{}`; manifest artifact `{}`.\n\n",
                page.snapshot_digest, page.manifest_artifact
            );
            for entry in page.entries {
                text.push_str(&format!(
                    "- `{}` — {} bytes — `{}`{}\n",
                    entry.path,
                    entry.bytes,
                    entry.digest,
                    if entry.executable { " — executable" } else { "" }
                ));
            }
            if let Some(next) = page.next_after {
                text.push_str(&format!(
                    "\nMore entries remain. Use `manifest {next}` for the next page."
                ));
            }
            if !page.exclusions.is_empty() {
                text.push_str(&format!("\n\nExcluded: {}.", page.exclusions.join(", ")));
            }
            text
        }
        PendingRequest::Read { .. } => {
            let text = admit_read(parameters, &mut state, output)?;
            if result.key.starts_with("red-team-investigation-read-") {
                if state.investigation.batch_read_active {
                    state.investigation.feedback.push_str("\n\n");
                    state.investigation.feedback.push_str(&text);
                } else {
                    state.investigation.feedback = text;
                }
                state.pending = None;
                if let Some(action) =
                    investigation::request_next_source_read(parameters, &mut state)?
                {
                    return Ok(action);
                }
                state.investigation.batch_read_active = false;
                state.investigation.feedback.push_str(
                    "\n\nCoordinator directive: these exact source bytes have now been delivered to the active role. Do not request the same unchanged ranges again in this role; use their retained evidence identities and continue toward the current stage's commit function.",
                );
                state::save(parameters, &state)?;
                return investigation::next(parameters, &host, &mut state);
            }
            text
        }
        PendingRequest::Revoke { .. } => {
            let observation: ScopedSourceRevocation = serde_json::from_value(output)?;
            state.campaign.state = CampaignState::Paused;
            format!(
                "Source authority `{}` revision `{}` is revoked (new state change: {}). Further manifest and source reads through it are rejected.",
                observation.handle, observation.scope_revision, observation.newly_revoked
            )
        }
        PendingRequest::JobSubmit { .. } => {
            let handle: ModuleJobHandle = serde_json::from_value(output)?;
            if result.key.starts_with("red-team-investigation-submit-") {
                investigation::job_submitted(&mut state, &handle.job_id);
                state.pending = None;
                let action = investigation::poll_action(&mut state, handle.job_id)?;
                state::save(parameters, &state)?;
                return Ok(action);
            }
            let key = format!("red-team-job-poll-{}", &handle.job_id[..16]);
            let request =
                ModuleJobStatusRequest { schema: 1, job_id: handle.job_id, wait_millis: 750 };
            state.pending =
                Some(PendingRequest::JobPoll { key: key.clone(), request: request.clone() });
            state::save(parameters, &state)?;
            return Ok(job_service(key, "poll", serde_json::to_value(request)?));
        }
        PendingRequest::JobPoll { .. } | PendingRequest::JobCancel { .. } => {
            let status: ModuleJobStatus = serde_json::from_value(output)?;
            admit_job_status(&mut state, &status)?;
            if result.key.starts_with("red-team-investigation-poll-") {
                let terminal = investigation::job_status(&mut state, &status);
                state.pending = None;
                if terminal {
                    state::save(parameters, &state)?;
                    return investigation::next(parameters, &host, &mut state);
                }
                let action = investigation::poll_action(&mut state, status.job_id)?;
                state::save(parameters, &state)?;
                return Ok(action);
            }
            job_status_text(&status)
        }
        PendingRequest::JobLog { .. } => {
            let page: ModuleJobLogPage = serde_json::from_value(output)?;
            let content = match std::str::from_utf8(&page.bytes) {
                Ok(text) => format!("```text\n{}\n```", text.replace("```", "` ` `")),
                Err(_) => format!("{} non-UTF-8 bytes retained.", page.bytes.len()),
            };
            format!(
                "# Contained job log\n\n- Job: `{}`\n- Stream: `{:?}`\n- Range: {}..{} of {} bytes\n\n{}",
                page.job_id,
                page.stream,
                page.range_start,
                page.range_end,
                page.total_bytes,
                content,
            )
        }
    };
    state.pending = None;
    state::save(parameters, &state)?;
    Ok(reply(text, &host, actions(&state), None))
}

fn pending_capability(pending: &PendingRequest) -> &'static str {
    match pending {
        PendingRequest::Capture { .. }
        | PendingRequest::Manifest { .. }
        | PendingRequest::Read { .. }
        | PendingRequest::Revoke { .. } => HOST_CAPABILITY_SCOPED_SOURCE,
        PendingRequest::JobSubmit { .. }
        | PendingRequest::JobPoll { .. }
        | PendingRequest::JobLog { .. }
        | PendingRequest::JobCancel { .. } => HOST_CAPABILITY_OWNED_JOBS,
    }
}

fn admit_job_status(state: &mut State, status: &ModuleJobStatus) -> Result<(), Error> {
    let scope = state
        .scopes
        .last()
        .ok_or_else(|| invalid("contained job status has no active scope"))?
        .id
        .clone();
    let snapshot = state
        .active_snapshot()
        .ok_or_else(|| invalid("contained job status has no active source snapshot"))?
        .id
        .clone();
    let job_state = match status.phase {
        ModuleJobPhase::Queued => records::JobState::Queued,
        ModuleJobPhase::Running => records::JobState::Running,
        ModuleJobPhase::Completed => records::JobState::Completed,
        ModuleJobPhase::Failed => records::JobState::Failed,
        ModuleJobPhase::Cancelled => records::JobState::Cancelled,
        ModuleJobPhase::Indeterminate => records::JobState::Indeterminate,
    };
    let job_id = RecordId::new(
        RecordKind::Job,
        format!("job-{}", &status.job_id[..status.job_id.len().min(24)]),
    )
    .map_err(invalid)?;
    let mut receipt_id = None;
    if let Some(receipt) = &status.receipt {
        if receipt.job_id != status.job_id
            || receipt.request_digest != status.request_digest
            || receipt.operation != status.operation
        {
            return Err(invalid("trusted job receipt does not match its retained job status"));
        }
        let bytes = serde_json::to_vec(receipt)?;
        let receipt_digest = digest(&bytes);
        let preparation = receipt.preparation.is_some();
        let evidence_id = RecordId::new(
            RecordKind::Evidence,
            format!(
                "{}-{}",
                if preparation { "preparation" } else { "execution" },
                &receipt_digest[..24]
            ),
        )
        .map_err(invalid)?;
        if !state.job_evidence.iter().any(|evidence| evidence.id == evidence_id) {
            state.job_evidence.push(EvidenceRecord {
                schema: RECORD_SCHEMA_VERSION,
                id: evidence_id.clone(),
                campaign: state.campaign.id.clone(),
                scope_revision: scope.clone(),
                kind: if preparation { EvidenceKind::Build } else { EvidenceKind::Execution },
                observation: format!(
                    "Host controller classified exact {} job {} as {:?}",
                    if preparation { "dependency preparation" } else { "contained proof" },
                    status.job_id,
                    receipt.verdict
                ),
                artifact_digest: receipt_digest,
                dependencies: vec![snapshot.clone()],
            });
        }
        if let Some(existing) =
            state.job_receipts.iter_mut().find(|existing| existing.job_id == receipt.job_id)
        {
            if existing != receipt {
                return Err(invalid("trusted job receipt changed for an existing job identity"));
            }
        } else {
            state.job_receipts.push(receipt.clone());
        }
        receipt_id = Some(evidence_id);
    }
    let record = records::JobRecord {
        schema: RECORD_SCHEMA_VERSION,
        id: job_id.clone(),
        campaign: state.campaign.id.clone(),
        scope_revision: scope,
        source_snapshot: snapshot,
        host_job_id: status.job_id.clone(),
        operation: status.operation.clone(),
        request_digest: status.request_digest.clone(),
        state: job_state,
        receipt: receipt_id,
    };
    if let Some(existing) = state.jobs.iter_mut().find(|job| job.id == job_id) {
        *existing = record;
    } else {
        state.jobs.push(record);
    }
    Ok(())
}

fn job_status_text(status: &ModuleJobStatus) -> String {
    let mut text = format!(
        "# Contained job\n\n- Job: `{}`\n- Adapter: `{}`\n- State: `{:?}`\n- Request: `{}`\n- Detail: {}",
        status.job_id, status.operation, status.phase, status.request_digest, status.detail
    );
    if let Some(receipt) = &status.receipt {
        text.push_str(&format!(
            "\n- Trusted verdict: `{:?}`\n- Target: `{}`\n- Plan: `{}`\n- Oracle: `{}`\n- Backend: `{}`\n- Terminal: `{}`\n- Network: `{}`\n- Cleanup complete: {}\n- Stdout artifact: `{}`\n- Stderr artifact: `{}`",
            receipt.verdict,
            receipt.target_digest,
            receipt.execution_plan_digest,
            receipt.oracle_digest,
            receipt.backend,
            receipt.terminal_disposition,
            receipt.network_policy,
            receipt.cleanup_complete,
            receipt.stdout_artifact,
            receipt.stderr_artifact,
        ));
        if let Some(preparation) = &receipt.preparation {
            text.push_str(&format!(
                "\n- Declared URL: `{}`\n- Final URL: `{}`\n- Redirects: {}\n- Pinned public addresses: {}\n- Dependency bytes: {}\n- Dependency artifact: `{}`",
                preparation.requested_url,
                preparation.final_url,
                list_or_none(&preparation.redirects),
                list_or_none(&preparation.resolved_addresses),
                preparation.bytes,
                preparation.artifact_digest,
            ));
        }
    } else if matches!(status.phase, ModuleJobPhase::Queued | ModuleJobPhase::Running) {
        text.push_str(&format!("\n\nPoll again with `job {}`.", status.job_id));
    }
    text
}

fn admit_read(parameters: &Value, state: &mut State, output: Value) -> Result<String, Error> {
    let read: ScopedSourceReadResult = serde_json::from_value(output)?;
    let bytes = read.bytes.clone();
    let actual = digest(&bytes);
    if actual != read.range_artifact
        || u64::try_from(bytes.len()).map_err(|_| invalid("source range is too large"))?
            != read.range_end.saturating_sub(read.range_start)
    {
        return Err(invalid("host source range bytes do not match their retained identity"));
    }
    let reused_count;
    let evidence_id;
    if let Some(existing) = state.observations.iter_mut().find(|observation| {
        observation.state == ObservationState::Current
            && observation.snapshot_digest == read.snapshot_digest
            && observation.path == read.path
            && observation.source_digest == read.source_digest
            && observation.range_start == read.range_start
            && observation.range_end == read.range_end
            && observation.record.artifact_digest == read.range_artifact
    }) {
        existing.reuse_count = existing
            .reuse_count
            .checked_add(1)
            .ok_or_else(|| invalid("source observation reuse count overflow"))?;
        reused_count = existing.reuse_count;
        evidence_id = existing.record.id.value.clone();
    } else {
        let snapshot = state
            .active_snapshot()
            .ok_or_else(|| invalid("source observation has no active snapshot"))?;
        let scope =
            state.scopes.last().ok_or_else(|| invalid("source observation has no active scope"))?;
        let identity = digest(
            format!(
                "{}\0{}\0{}\0{}\0{}",
                read.snapshot_digest,
                read.path,
                read.source_digest,
                read.range_start,
                read.range_end
            )
            .as_bytes(),
        );
        let retained_relative = format!("observations/{}.bin", read.range_artifact);
        let retained_path = state::private_root(parameters)?.join(&retained_relative);
        if !retained_path.exists() {
            let parent = retained_path
                .parent()
                .ok_or_else(|| invalid("source observation path has no parent"))?;
            std::fs::create_dir_all(parent)?;
            let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
            use std::io::Write as _;
            temporary.write_all(&bytes)?;
            temporary.as_file().sync_all()?;
            temporary.persist(&retained_path).map_err(|error| error.error)?;
        }
        let record_id = RecordId::new(RecordKind::Evidence, format!("source-{}", &identity[..24]))
            .map_err(invalid)?;
        evidence_id = record_id.value.clone();
        state.observations.push(SourceObservation {
            record: EvidenceRecord {
                schema: RECORD_SCHEMA_VERSION,
                id: record_id,
                campaign: state.campaign.id.clone(),
                scope_revision: scope.id.clone(),
                kind: EvidenceKind::Source,
                observation: format!(
                    "Observed immutable source bytes {}..{} from {}",
                    read.range_start, read.range_end, read.path
                ),
                artifact_digest: read.range_artifact.clone(),
                dependencies: vec![snapshot.id.clone()],
            },
            snapshot_digest: read.snapshot_digest.clone(),
            path: read.path.clone(),
            source_digest: read.source_digest.clone(),
            source_bytes: read.source_bytes,
            range_start: read.range_start,
            range_end: read.range_end,
            retained_path: Some(retained_relative),
            state: ObservationState::Current,
            invalidated_by: None,
            reuse_count: u64::from(read.reused),
        });
        reused_count = u64::from(read.reused);
    }
    let preview = match std::str::from_utf8(&bytes) {
        Ok(text) => format!("```text\n{}\n```", text.replace("```", "` ` `")),
        Err(_) => format!(
            "Binary range retained as artifact `{}`; {} bytes.",
            read.range_artifact,
            bytes.len()
        ),
    };
    Ok(format!(
        "# Retained source observation\n\n- Evidence identity: `{}`\n- Path: `{}`\n- Complete source: {} bytes, `{}`\n- Range: {}..{}\n- Range artifact: `{}`\n- Durable identical-read reuse: {}\n- Observation reuse count: {}\n\n{}\n\nUse the exact evidence identity above in source_evidence fields. This is source evidence, not a security finding.",
        evidence_id,
        read.path,
        read.source_bytes,
        read.source_digest,
        read.range_start,
        read.range_end,
        read.range_artifact,
        read.reused,
        reused_count,
        preview,
    ))
}

fn compatibility(profile: Option<ModuleHostProfile>) -> Result<ModuleAction, Error> {
    let Some(profile) = profile else {
        return Ok(reply(
            "This Peritus host does not advertise the versioned native-module host contract. Update Peritus before selecting source.",
            &None,
            base_actions(),
            None,
        ));
    };
    if !profile.supports(HOST_CAPABILITY_PROFILE, MODULE_HOST_CONTRACT_VERSION) {
        return Ok(reply(
            "This host profile does not support capability discovery version 1. Red Team remains inactive.",
            &Some(profile),
            base_actions(),
            None,
        ));
    }
    Ok(ModuleAction::HostService {
        request: ModuleHostRequest {
            key: COMPATIBILITY_KEY.into(),
            capability: HOST_CAPABILITY_PROFILE.into(),
            version: MODULE_HOST_CONTRACT_VERSION,
            operation: "inspect".into(),
            input: json!({}),
        },
    })
}

fn compatibility_result(
    result: ModuleHostResult,
    current: &Option<ModuleHostProfile>,
) -> Result<ModuleAction, Error> {
    if result.capability != HOST_CAPABILITY_PROFILE
        || result.version != MODULE_HOST_CONTRACT_VERSION
    {
        return Err(invalid("compatibility result has the wrong capability identity"));
    }
    let text = match result.outcome {
        ModuleHostOutcome::Success { output } => {
            let profile: ModuleHostProfile = serde_json::from_value(output)?;
            compatibility_text(&profile)
        }
        ModuleHostOutcome::Unsupported { detail } => {
            format!("Host capability discovery is unavailable: {detail}.")
        }
        ModuleHostOutcome::Rejected { code, detail } => {
            format!("Host capability discovery was rejected (`{code}`): {detail}.")
        }
        ModuleHostOutcome::Failed { code, detail, .. } => {
            format!("Host capability discovery failed (`{code}`): {detail}.")
        }
    };
    Ok(reply(text, current, base_actions(), None))
}

fn checkpoint(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
) -> Result<ModuleAction, Error> {
    let Some(host) = profile else {
        return Ok(reply(
            "Checkpoint support cannot be established on this host.",
            profile,
            base_actions(),
            None,
        ));
    };
    if !host.supports(HOST_CAPABILITY_CHECKPOINT, 1)
        || !host.supports(HOST_CAPABILITY_PRIVATE_STATE, 1)
    {
        return Ok(reply(
            "This host lacks version-one checkpoint or private-state support. No checkpoint was published.",
            profile,
            base_actions(),
            None,
        ));
    }
    let mut state = state::load(parameters)?;
    state.checkpoint = Some(SkeletonCheckpoint {
        key: CHECKPOINT_KEY.into(),
        acknowledged: false,
        host_profile_schema: host.schema,
        observed_capabilities: capability_names(host),
    });
    state::save(parameters, &state)?;
    Ok(ModuleAction::Checkpoint {
        key: CHECKPOINT_KEY.into(),
        text: "Red Team Phase 5 investigation checkpoint was written to private module state. It retains exact source observations, role stage, hypotheses, contained-job receipts, skeptical decisions, reuse measurements, and explicit gaps.".into(),
        actions: actions(&state),
    })
}

fn checkpoint_ack(parameters: &Value) -> Result<ModuleAction, Error> {
    let key = parameters["key"]
        .as_str()
        .ok_or_else(|| invalid("checkpoint acknowledgement is missing key"))?;
    let mut state = state::load(parameters)?;
    let checkpoint =
        state.checkpoint.as_mut().ok_or_else(|| invalid("no Phase 5 checkpoint is pending"))?;
    if key != CHECKPOINT_KEY || checkpoint.key != key {
        return Err(invalid("checkpoint acknowledgement key does not match retained state"));
    }
    checkpoint.acknowledged = true;
    state::save(parameters, &state)?;
    Ok(reply(
        "Red Team Phase 5 checkpoint is durably acknowledged.",
        &profile(parameters),
        actions(&state),
        None,
    ))
}

fn status(state: &State) -> String {
    let checkpoint = match &state.checkpoint {
        None => "not created",
        Some(SkeletonCheckpoint { acknowledged: true, .. }) => "acknowledged",
        Some(_) => "written, awaiting host acknowledgement",
    };
    let scope = state.scopes.last();
    let snapshot = state.snapshots.last();
    let current = state.current_observations().count();
    let invalidated = state.observations.len().saturating_sub(current);
    let active_jobs = state
        .jobs
        .iter()
        .filter(|job| matches!(job.state, records::JobState::Queued | records::JobState::Running))
        .count();
    format!(
        "# Red Team — Phase 5 investigation\n\n- Module: `peritus.red-team` {}\n- Durable schema: v{}\n- Campaign state: `{:?}`\n- Investigation stage: `{:?}`\n- Investigation paused: {}\n- Scope revision: `{}`\n- Source snapshot: `{}`\n- Manifest artifact: `{}`\n- Current source observations: {}\n- Invalidated source observations: {}\n- Retained hypotheses: {}\n- Retained probes: {}\n- Retained host-owned jobs: {}\n- Active host-owned jobs: {}\n- Trusted job receipts: {}\n- Skeptically adjudicated findings: {}\n- Security families unexamined: {}\n- Reused exact source reads: {}\n- Foundation checkpoint: {}\n\nThe source handle is revocable. Every model role receives the canonical skill directly. The Rust coordinator alone admits source observations, contained execution receipts and classifications; unsuccessful attempts do not establish safety.",
        state.module_version,
        state.schema,
        state.campaign.state,
        state.investigation.stage,
        state.investigation.paused,
        scope.map_or("not selected", |record| record.id.value.as_str()),
        snapshot.map_or("not captured", |record| record.snapshot_digest.as_str()),
        snapshot.map_or("not captured", |record| record.manifest_artifact.as_str()),
        current,
        invalidated,
        state.hypotheses.len(),
        state.investigation.probes.len(),
        state.jobs.len(),
        active_jobs,
        state.job_receipts.len(),
        state.findings.len(),
        state
            .coverage
            .iter()
            .filter(|record| matches!(record.state, records::CoverageState::Unexamined))
            .count(),
        state.investigation.reuse.source_reads_reused,
        checkpoint,
    )
}

fn coverage(state: &State) -> String {
    if state.coverage.is_empty() {
        return "# Red Team coverage\n\nNo source scope exists, so no family-by-surface ledger has been created. This is an unexamined campaign, not a clean result.".into();
    }
    let mut text = "# Red Team coverage\n\n`Examined` would mean only that named methods ran; it would not mean secure.\n\n".to_owned();
    for record in &state.coverage {
        text.push_str(&format!(
            "- `{}` / `{}` — `{:?}`: {}\n",
            record.family, record.surface, record.state, record.reason
        ));
    }
    text
}

fn contract(profile: &Option<ModuleHostProfile>) -> Result<ModuleAction, Error> {
    Ok(reply(
        "# Red Team Phase 5 contract\n\nThe host binds source capture to the explicitly opened Peritus workspace, then admits only stable job adapters over an exact source handle and revision. The coordinator performs one bounded inventory, delivers the canonical skill to separately persisted discovery and skeptic contexts, registers hypotheses before execution, and routes all effects through revocable scoped-source or host-owned job services. Dependency preparation accepts only declared HTTPS DNS origins on port 443, pins public DNS answers, independently revalidates bounded redirects, sends no credentials, applies a byte ceiling, and requires an exact SHA-256 before content-addressed publication. The canary-disclosure adapter launches the immutable selected target through the native Linux private-filesystem backend with cleared environment, no secrets, deny-all network, finite CPU/memory/process/storage/wall/output limits and complete process-tree ownership. The host generates and compares the canary; target output cannot manufacture a trusted receipt. A confirmed finding requires that receipt. Refuted, not-reproduced, inconclusive and blocked remain distinct. Phase five never develops or applies a patch.",
        profile,
        base_actions(),
        None,
    ))
}

fn reply(
    text: impl Into<String>,
    profile: &Option<ModuleHostProfile>,
    actions: Vec<ModuleMenuAction>,
    attachment: Option<ModuleAttachment>,
) -> ModuleAction {
    let mut text = text.into();
    if let Some(profile) = profile {
        text.push_str(&format!(
            "\n\nHost profile v{}: {}.",
            profile.schema,
            capability_names(profile).join(", ")
        ));
    }
    ModuleAction::Reply { text, actions, attachment }
}

fn compatibility_text(profile: &ModuleHostProfile) -> String {
    let source =
        if profile.supports(HOST_CAPABILITY_SCOPED_SOURCE, 1) { "available" } else { "missing" };
    let jobs =
        if profile.supports(HOST_CAPABILITY_OWNED_JOBS, 1) { "available" } else { "missing" };
    let required = [
        HOST_CAPABILITY_SCOPED_SOURCE,
        HOST_CAPABILITY_OWNED_JOBS,
        HOST_CAPABILITY_CHECKPOINT,
        HOST_CAPABILITY_PRIVATE_STATE,
    ]
    .into_iter()
    .filter(|name| !profile.supports(name, 1))
    .collect::<Vec<_>>();
    format!(
        "# Red Team host compatibility\n\nScoped source: **{source}**.\n\nContained proof jobs: **{jobs}**.\n\nAvailable v1 capabilities: {}.\n\nMissing Phase 5 runtime capabilities: {}.\n\nSource-build capability is used by the module market before installation, not by a running investigation. Missing capabilities do not cause ambient filesystem, process or network fallback.",
        capability_names(profile).join(", "),
        list_or_none(&required),
    )
}

fn supports_source(profile: &Option<ModuleHostProfile>) -> bool {
    profile.as_ref().is_some_and(|profile| profile.supports(HOST_CAPABILITY_SCOPED_SOURCE, 1))
}

fn supports_jobs(profile: &Option<ModuleHostProfile>) -> bool {
    profile.as_ref().is_some_and(|profile| profile.supports(HOST_CAPABILITY_OWNED_JOBS, 1))
}

fn source_unavailable(profile: &Option<ModuleHostProfile>) -> ModuleAction {
    reply(
        "This Peritus host does not advertise `module.scoped-source@1`. Update the host before selecting source; Red Team will not guess a working directory or read ambient files.",
        profile,
        base_actions(),
        None,
    )
}

fn jobs_unavailable(profile: &Option<ModuleHostProfile>) -> ModuleAction {
    reply(
        "This Peritus host does not advertise `module.owned-jobs@1`. Red Team will not execute the target through a raw command or unrestricted fallback.",
        profile,
        base_actions(),
        None,
    )
}

fn actions(state: &State) -> Vec<ModuleMenuAction> {
    let investigation_started =
        !matches!(state.investigation.stage, state::InvestigationStage::NotStarted);
    let mut result = if !investigation_started {
        vec![action("Status", "status", true)]
    } else {
        investigation::actions(state)
    };
    if state.active_snapshot().is_none() {
        result.push(action("Scope current workspace", "scope", true));
    } else {
        if !investigation_started {
            result.push(action("Start autonomous investigation", "start", true));
        }
        result.extend([
            action("Refresh source", "refresh", true),
            action("View manifest", "manifest", true),
            action("Observe source path", "observe ", false),
            action("Prepare pinned dependency", "prepare ", false),
            action("Run contained proof", "probe ", false),
            action("Revoke source", "revoke", true),
        ]);
        if !investigation_started {
            result.extend([
                action("Contained jobs", "jobs", true),
                action("Coverage gaps", "coverage", true),
                action("Current report", "report", true),
            ]);
        }
    }
    result.extend([
        action("Check compatibility", "compatibility", true),
        action("View contract", "contract", true),
        action("Save investigation checkpoint", "checkpoint", true),
    ]);
    result
}

fn base_actions() -> Vec<ModuleMenuAction> {
    vec![
        action("Status", "status", true),
        action("Scope current workspace", "scope", true),
        action("Check compatibility", "compatibility", true),
        action("View contract", "contract", true),
    ]
}

fn action(label: &str, arguments: &str, submit: bool) -> ModuleMenuAction {
    ModuleMenuAction { label: label.into(), arguments: arguments.into(), submit }
}

fn profile(parameters: &Value) -> Option<ModuleHostProfile> {
    serde_json::from_value(parameters.get("host_profile")?.clone()).ok()
}

fn capability_names(profile: &ModuleHostProfile) -> Vec<String> {
    profile
        .capabilities
        .iter()
        .map(|capability| format!("{}@{}", capability.name, capability.version))
        .collect()
}

fn parse_observe(command: &str) -> Result<(String, u64, u64), Error> {
    let arguments = command
        .strip_prefix("observe ")
        .ok_or_else(|| invalid("observe command is missing a path"))?;
    let mut path = Vec::new();
    let mut offset = 0_u64;
    let mut maximum = 4096_u64;
    for part in arguments.split_whitespace() {
        if let Some(value) = part.strip_prefix("offset=") {
            offset = value.parse().map_err(|_| invalid("observe offset must be an integer"))?;
        } else if let Some(value) = part.strip_prefix("bytes=") {
            maximum = value.parse().map_err(|_| invalid("observe bytes must be an integer"))?;
        } else {
            path.push(part);
        }
    }
    if path.is_empty() {
        return Err(invalid("observe command is missing a source-relative path"));
    }
    Ok((path.join(" "), offset, maximum))
}

fn parse_probe(command: &str) -> Result<(String, String), Error> {
    let arguments = command
        .strip_prefix("probe ")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("probe command is missing a source-relative target"))?;
    let (path, input) = arguments
        .rsplit_once(" input=")
        .map_or((arguments, "forged-success-marker"), |(path, input)| (path.trim(), input));
    if path.is_empty() {
        return Err(invalid("probe command is missing a source-relative target"));
    }
    Ok((path.to_owned(), input.to_owned()))
}

fn parse_preparation(command: &str) -> Result<(String, String, u64), Error> {
    let mut values = command
        .strip_prefix("prepare ")
        .map(str::split_whitespace)
        .ok_or_else(|| invalid("prepare command is malformed"))?;
    let url = values
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("prepare command is missing an HTTPS URL"))?
        .to_owned();
    let mut expected_sha256 = None;
    let mut maximum_bytes = 16 * 1024 * 1024_u64;
    for value in values {
        if let Some(value) = value.strip_prefix("sha256=") {
            expected_sha256 = Some(value.to_owned());
        } else if let Some(value) = value.strip_prefix("bytes=") {
            maximum_bytes =
                value.parse().map_err(|_| invalid("prepare bytes must be an integer"))?;
        } else {
            return Err(invalid("prepare accepts only sha256=DIGEST and bytes=N options"));
        }
    }
    let expected_sha256 =
        expected_sha256.ok_or_else(|| invalid("prepare requires sha256=DIGEST"))?;
    Ok((url, expected_sha256, maximum_bytes))
}

fn parse_job_log(command: &str) -> Result<(String, ModuleJobStream, u64, u64), Error> {
    let mut values = command
        .strip_prefix("job-log ")
        .ok_or_else(|| invalid("job-log command is malformed"))?
        .split_whitespace();
    let job_id = values
        .next()
        .ok_or_else(|| invalid("job-log command is missing a job identity"))?
        .to_owned();
    let stream = match values.next().unwrap_or("stdout") {
        "stdout" => ModuleJobStream::Stdout,
        "stderr" => ModuleJobStream::Stderr,
        "controller" => ModuleJobStream::Controller,
        _ => return Err(invalid("job-log stream must be stdout, stderr, or controller")),
    };
    let mut offset = 0_u64;
    let mut maximum = 4096_u64;
    for value in values {
        if let Some(value) = value.strip_prefix("offset=") {
            offset = value.parse().map_err(|_| invalid("job-log offset must be an integer"))?;
        } else if let Some(value) = value.strip_prefix("bytes=") {
            maximum = value.parse().map_err(|_| invalid("job-log bytes must be an integer"))?;
        } else {
            return Err(invalid("job-log accepts only offset=N and bytes=N options"));
        }
    }
    Ok((job_id, stream, offset, maximum))
}

fn jobs(state: &State) -> String {
    if state.jobs.is_empty() {
        return "# Contained jobs\n\nNo job receipt has been observed. Use `prepare HTTPS_URL sha256=DIGEST [bytes=N]` or `probe SOURCE_PATH [input=LITERAL]` after selecting source.".into();
    }
    let mut text = "# Contained jobs\n\n".to_owned();
    for job in &state.jobs {
        text.push_str(&format!(
            "- `{}` — `{:?}` — `{}` — request `{}`\n",
            job.host_job_id, job.state, job.operation, job.request_digest
        ));
    }
    text
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn list_or_none<T: AsRef<str>>(values: &[T]) -> String {
    if values.is_empty() {
        "none".into()
    } else {
        values.iter().map(AsRef::as_ref).collect::<Vec<_>>().join(", ")
    }
}

pub(crate) fn invalid(message: impl Into<String>) -> Error {
    Error::Invalid(message.into())
}
