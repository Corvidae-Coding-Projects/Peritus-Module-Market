//! Hardened Red Team coordinator: investigation, copy-only repair, replay, and delivery.

mod adapter;
mod application_binding;
mod attack_graph;
mod boundary_authority;
mod browser_client;
mod coverage;
mod diamond_binding;
mod file_fuzz;
mod http_api;
mod identity_access;
mod investigation;
mod journey;
mod laboratory;
pub mod records;
mod repair;
mod report;
mod runtime_application;
mod runtime_attack_graph;
mod runtime_boundary_authority;
mod runtime_browser;
mod runtime_browser_client;
mod runtime_diamond;
mod runtime_file_fuzz;
mod runtime_http_api;
mod runtime_identity_access;
mod runtime_laboratory;
mod runtime_workflow_state;
mod source_analysis;
mod source_analysis_worker;
mod state;
mod worker;
mod workflow_state;

use peritus_plugin_sdk::{
    HOST_CAPABILITY_APPLICATION_LABORATORY, HOST_CAPABILITY_CHECKPOINT,
    HOST_CAPABILITY_PRIVATE_STATE, HOST_CAPABILITY_PROFILE, HOST_CAPABILITY_SCOPED_SOURCE,
    HOST_CAPABILITY_WORKER, MODULE_HOST_CONTRACT_VERSION, ModuleAction, ModuleAttachment,
    ModuleHostOutcome, ModuleHostProfile, ModuleHostRequest, ModuleHostResult, ModuleJobLimits,
    ModuleJobLogPage, ModuleJobPhase, ModuleJobRequest, ModuleJobStatus, ModuleMenuAction,
    ModuleWorkerLimits, ModuleWorkerRequest, ModuleWorkerResult, ScopedSourceHandle,
    ScopedSourceManifestPage, ScopedSourceManifestRequest, ScopedSourceReadRequest,
    ScopedSourceReadResult, ScopedSourceRequest, ScopedSourceRevocation, ScopedSourceRevokeRequest,
    ScopedSourceVerification,
};
use records::{
    CampaignState, EvidenceKind, EvidenceRecord, RECORD_SCHEMA_VERSION, RecordId, RecordKind,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use state::{ObservationState, PendingRequest, SkeletonCheckpoint, SourceObservation, State};

const CHECKPOINT_KEY: &str = "red-team-phase-20-complete-journey-v1";
const COMPATIBILITY_KEY: &str = "red-team-phase-20-host-profile";

/// Executes one module-owned worker in the host-provided disposable source copy.
pub fn run_worker(name: &str, input: Value) -> Result<Value, Error> {
    worker::dispatch(name, input).map_err(invalid)
}

pub(crate) fn job_worker_action(
    state: &State,
    key: String,
    request: ModuleJobRequest,
) -> Result<ModuleAction, Error> {
    let source = state
        .active_handle()
        .ok_or_else(|| invalid("captured source authority is unavailable for proof execution"))?;
    if request.source_handle != source.handle || request.scope_revision != source.scope_revision {
        return Err(invalid("proof request source authority differs from the active scope"));
    }
    let source_snapshot = state
        .active_snapshot()
        .ok_or_else(|| invalid("captured source snapshot is unavailable for proof execution"))?
        .snapshot_digest
        .clone();
    Ok(ModuleAction::HostService {
        request: ModuleHostRequest {
            key,
            capability: HOST_CAPABILITY_WORKER.into(),
            version: 1,
            operation: "execute".into(),
            input: serde_json::to_value(ModuleWorkerRequest {
                schema: 1,
                source,
                worker: "proof-job".into(),
                input: json!({"request": request, "source_snapshot": source_snapshot}),
                runtime_features: Vec::new(),
                limits: ModuleWorkerLimits {
                    wall_millis: 30_000,
                    memory_bytes: 256 * 1024 * 1024,
                    storage_bytes: 64 * 1024 * 1024,
                    processes: 16,
                    open_handles: 64,
                },
            })?,
        },
    })
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("red-team input: {0}")]
    Invalid(String),
    #[error("red-team storage: {0}")]
    Io(#[from] std::io::Error),
    #[error("red-team JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// Dispatches one module-owned native workflow operation.
pub fn dispatch(method: &str, parameters: &Value) -> Result<Value, Error> {
    if method == "tool" {
        return if repair::owns_key(parameters) {
            repair::tool(parameters)
        } else {
            investigation::tool(parameters)
        };
    }
    let action = match method {
        "command" => command(parameters)?,
        "checkpoint_ack" => checkpoint_ack(parameters)?,
        "host_result" => host_result(parameters)?,
        "model_result" => {
            if repair::owns_key(parameters) {
                repair::model_result(parameters)?
            } else {
                investigation::model_result(parameters)?
            }
        }
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
    if journey::handles(command) {
        return journey::command(parameters, &host, &mut state, command);
    }
    if diamond_binding::handles(command) {
        return diamond_binding::command(parameters, &host, &mut state, command);
    }
    if application_binding::handles(command) {
        return application_binding::command(parameters, &host, &mut state, command);
    }
    if command == "pause" {
        return investigation::pause(parameters, &mut state);
    }
    if let Some(direction) = command.strip_prefix("steer ") {
        return investigation::steer(parameters, &mut state, direction);
    }
    if command == "resume" {
        if let Some(pending) = state.pending.clone() {
            return resume_pending(&pending, &state);
        }
        if !matches!(state.investigation.stage, state::InvestigationStage::NotStarted) {
            return investigation::resume(parameters, &host, &mut state);
        }
    }
    if state.pending.is_some() {
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
    if source_analysis::handles(command)
        || http_api::handles(command)
        || browser_client::handles(command)
        || identity_access::handles(command)
        || file_fuzz::handles(command)
        || workflow_state::handles(command)
        || boundary_authority::handles(command)
        || attack_graph::handles(command)
        || application_binding::handles(command)
        || adapter::handles(command)
        || laboratory::handles(command)
    {
        return route_component_command(parameters, &host, &mut state, command);
    }
    if command.is_empty() || matches!(command, "status" | "resume") {
        return Ok(reply(status(&state), &host, actions(&state), None));
    }
    if command == "coverage" {
        return Ok(reply(coverage::coverage_view(&state), &host, actions(&state), None));
    }
    if command == "profiles" {
        return Ok(reply(coverage::profiles_view(&state), &host, actions(&state), None));
    }
    if command == "surfaces" {
        return Ok(reply(coverage::surfaces_view(&state), &host, actions(&state), None));
    }
    if command == "methods" {
        return Ok(reply(coverage::methods_view(&state), &host, actions(&state), None));
    }
    if command == "findings" {
        return Ok(reply(findings(&state), &host, actions(&state), None));
    }
    if command == "patches" {
        return Ok(reply(patches(&state), &host, actions(&state), None));
    }
    if matches!(command, "report" | "report-json" | "sarif" | "bundle") {
        return route_component_command(parameters, &host, &mut state, command);
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
        "Unknown Red Team command. Use campaign-plan, campaign-start, campaign, campaign-next, campaign-pause, campaign-resume, campaign-steer DETAILS, campaign-retry, campaign-skip, campaign-abort, start, status, pause, resume, steer DETAILS, scope, refresh, profiles, surfaces, methods, coverage, analyzers, analyzer-install, analyze, analysis-history, analyzer-status, analyzer-remove, diamond, diamond-install, diamond-run, diamond-status, diamond-remove, api, api-install, api-run, api-history, api-status, api-remove, browser, browser-install, browser-run, browser-history, browser-status, browser-remove, identity, identity-install, identity-run, identity-history, file-fuzz, file-fuzz-install, file-fuzz-run, file-fuzz-history, file-fuzz-status, file-fuzz-remove, workflow, workflow-install, workflow-run, workflow-history, workflow-status, workflow-remove, boundary, boundary-install, boundary-run, boundary-history, boundary-status, boundary-remove, graph, graph-install, graph-run, graph-history, graph-status, graph-remove, laboratories, lab-create source, lab-prepare, lab-launch, lab-run-auto, lab-run RUNTIME ENTRYPOINT [ARGS...], lab-run-json JSON, lab-status, lab-select VALUE, lab-snapshot, lab-reset, lab-stop, lab-teardown, compatibility fixture commands, adapters, adapter-install diagnostic, adapter-stage diagnostic, adapter-complete, adapter-cancel, adapter-status, adapter-run MESSAGE, adapter-remove, manifest, observe PATH [offset=N] [bytes=N], probe PATH [input=LITERAL], jobs, job ID, job-log ID STREAM [offset=N] [bytes=N], job-cancel ID, findings, patches, report, report-json, sarif, bundle, revoke, compatibility, contract, or checkpoint.",
        &host,
        actions(&state),
        None,
    ))
}

fn route_component_command(
    parameters: &Value,
    host: &Option<ModuleHostProfile>,
    state: &mut State,
    command: &str,
) -> Result<ModuleAction, Error> {
    if source_analysis::handles(command) {
        return source_analysis::command(parameters, host, state, command);
    }
    if http_api::handles(command) {
        return http_api::command(parameters, host, state, command);
    }
    if browser_client::handles(command) {
        return browser_client::command(parameters, host, state, command);
    }
    if identity_access::handles(command) {
        return identity_access::command(parameters, host, state, command);
    }
    if file_fuzz::handles(command) {
        return file_fuzz::command(parameters, host, state, command);
    }
    if workflow_state::handles(command) {
        return workflow_state::command(parameters, host, state, command);
    }
    if boundary_authority::handles(command) {
        return boundary_authority::command(parameters, host, state, command);
    }
    if attack_graph::handles(command) {
        return attack_graph::command(parameters, host, state, command);
    }
    if application_binding::handles(command) {
        return application_binding::command(parameters, host, state, command);
    }
    if adapter::handles(command) {
        return adapter::command(parameters, host, state, command);
    }
    if laboratory::handles(command) {
        return laboratory::command(parameters, host, state, command);
    }
    if matches!(command, "report" | "report-json" | "sarif" | "bundle") {
        let attachment = report::publish_report(&state::private_root(parameters)?, state, command)?;
        state::save(parameters, state)?;
        return Ok(reply(
            "The current bounded delivery was published from retained source observations, findings, module-authored original and patched replay receipts, exact diffs, independent reviews, and the original-workspace comparison. Pending work and every unexamined family remain explicit gaps.",
            host,
            actions(state),
            Some(attachment),
        ));
    }
    Err(invalid(format!("campaign step uses unsupported command `{command}`")))
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
    job_worker_action(state, key, request)
}

fn poll_job(
    _parameters: &Value,
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
    let job = state
        .jobs
        .iter()
        .find(|job| job.host_job_id == job_id)
        .ok_or_else(|| invalid("job command names no retained module-worker result"))?;
    Ok(reply(
        format!(
            "# Module worker result\n\n- Job: `{}`\n- State: `{:?}`\n- Operation: `{}`\n- Request: `{}`\n- Receipt: `{}`\n\nModule workers return a terminal result in the same bounded call; there is no host-side job to poll.",
            job.host_job_id,
            job.state,
            job.operation,
            job.request_digest,
            job.receipt.as_ref().map_or("none", |value| value.value.as_str()),
        ),
        profile,
        actions(state),
        None,
    ))
}

fn job_log(
    _parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut State,
    command: &str,
) -> Result<ModuleAction, Error> {
    if !supports_jobs(profile) {
        return Ok(jobs_unavailable(profile));
    }
    let job_id = command
        .strip_prefix("job-log ")
        .and_then(|value| value.split_whitespace().next())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("job-log command is missing a job identity"))?;
    if !state.jobs.iter().any(|job| job.host_job_id == job_id) {
        return Err(invalid("job-log names no retained module-worker result"));
    }
    Ok(reply(
        "Module workers return their bounded stdout and stderr to the module in the same call. Red Team retains the admitted typed receipt, not a separate host-owned log stream.",
        profile,
        actions(state),
        None,
    ))
}

fn cancel_job(
    _parameters: &Value,
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
    if !state.jobs.iter().any(|job| job.host_job_id == job_id) {
        return Err(invalid("job-cancel names no retained module-worker result"));
    }
    Ok(reply(
        "The selected module worker is already terminal. Active worker cancellation is the ordinary Peritus run cancellation control; there is no detached host-owned Red Team job.",
        profile,
        actions(state),
        None,
    ))
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

pub(crate) fn resume_pending(
    pending: &PendingRequest,
    state: &State,
) -> Result<ModuleAction, Error> {
    if matches!(
        pending,
        PendingRequest::AdapterCatalog { .. }
            | PendingRequest::AdapterPrepare { .. }
            | PendingRequest::AdapterComplete { .. }
            | PendingRequest::AdapterCancel { .. }
            | PendingRequest::AdapterStatus { .. }
            | PendingRequest::AdapterRemove { .. }
            | PendingRequest::AdapterExecute { .. }
    ) {
        return adapter::resume_worker(state, pending);
    }
    let (capability, operation, input) = match pending {
        PendingRequest::AdapterCatalog { .. }
        | PendingRequest::AdapterPrepare { .. }
        | PendingRequest::AdapterComplete { .. }
        | PendingRequest::AdapterCancel { .. }
        | PendingRequest::AdapterStatus { .. }
        | PendingRequest::AdapterRemove { .. }
        | PendingRequest::AdapterExecute { .. } => unreachable!("handled above"),
        PendingRequest::LaboratoryCatalog { .. } => (
            HOST_CAPABILITY_APPLICATION_LABORATORY,
            "catalog",
            json!({}),
        ),
        PendingRequest::LaboratoryCreate { request, .. } => (
            HOST_CAPABILITY_APPLICATION_LABORATORY,
            "create",
            serde_json::to_value(request)?,
        ),
        PendingRequest::LaboratorySourceCreate { request, .. } => (
            HOST_CAPABILITY_APPLICATION_LABORATORY,
            "create-source",
            serde_json::to_value(request)?,
        ),
        PendingRequest::LaboratoryLifecycle { operation, request, .. } => (
            HOST_CAPABILITY_APPLICATION_LABORATORY,
            operation.as_str(),
            serde_json::to_value(request)?,
        ),
        PendingRequest::LaboratoryInvoke { request, .. } => (
            HOST_CAPABILITY_APPLICATION_LABORATORY,
            "invoke",
            serde_json::to_value(request)?,
        ),
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
        PendingRequest::JobSubmit { key, request } => {
            return job_worker_action(state, key.clone(), request.clone());
        }
        PendingRequest::JobPoll { .. }
        | PendingRequest::JobLog { .. }
        | PendingRequest::JobCancel { .. } => {
            return Err(invalid(
                "legacy asynchronous Red Team job state cannot be resumed; current module workers return a terminal result in the same bounded call",
            ));
        }
        PendingRequest::SourceVerify { request, .. } => (
            HOST_CAPABILITY_SCOPED_SOURCE,
            "verify",
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
            if expected_capability == HOST_CAPABILITY_WORKER {
                state.adapter_errors.push(format!("unsupported: {detail}"));
            }
            if expected_capability == HOST_CAPABILITY_APPLICATION_LABORATORY {
                state.laboratory_errors.push(format!("unsupported: {detail}"));
            }
            if result.key.starts_with("red-team-repair-") {
                repair::host_failure(&mut state, &detail);
                state::save(parameters, &state)?;
                return repair::next(parameters, &host, &mut state);
            }
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
            if expected_capability == HOST_CAPABILITY_WORKER {
                state.adapter_errors.push(format!("{code}: {detail}"));
            }
            if expected_capability == HOST_CAPABILITY_APPLICATION_LABORATORY {
                state.laboratory_errors.push(format!("{code}: {detail}"));
            }
            if result.key.starts_with("red-team-repair-") {
                repair::host_failure(&mut state, &format!("host rejection {code}: {detail}"));
                state::save(parameters, &state)?;
                return repair::next(parameters, &host, &mut state);
            }
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
            if expected_capability == HOST_CAPABILITY_WORKER {
                state.adapter_errors.push(format!("{code}: {detail}"));
            }
            if expected_capability == HOST_CAPABILITY_APPLICATION_LABORATORY {
                state.laboratory_errors.push(format!("{code}: {detail}"));
            }
            if result.key.starts_with("red-team-repair-") {
                repair::host_failure(
                    &mut state,
                    &format!(
                        "host failure {code}: {detail}; retryable={retryable_with_new_action}"
                    ),
                );
                state::save(parameters, &state)?;
                return repair::next(parameters, &host, &mut state);
            }
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
    if expected_capability == HOST_CAPABILITY_WORKER {
        let worker: ModuleWorkerResult = serde_json::from_value(output)?;
        let expected_worker = if matches!(pending, PendingRequest::JobSubmit { .. }) {
            "proof-job"
        } else {
            "adapter-runtime"
        };
        if worker.schema != 1
            || worker.worker != expected_worker
            || worker.exit_code != Some(0)
            || !worker.cleanup_complete
            || !worker.original_source_unchanged
            || worker.execution_plan_digest.len() != 64
            || !worker.stderr.is_empty()
        {
            let stderr = String::from_utf8_lossy(&worker.stderr);
            let stderr = stderr.chars().take(2_048).collect::<String>();
            return Err(invalid(format!(
                "module worker `{}` failed: exit={:?}, cleanup={}, original_source_unchanged={}, plan_digest_bytes={}, stderr={stderr:?}",
                worker.worker,
                worker.exit_code,
                worker.cleanup_complete,
                worker.original_source_unchanged,
                worker.execution_plan_digest.len(),
            )));
        }
        let output = serde_json::from_slice(&worker.stdout)?;
        if expected_worker == "adapter-runtime" {
            return adapter::admit(parameters, &host, &mut state, pending, output);
        }
        let status: ModuleJobStatus = serde_json::from_value(output)?;
        admit_job_status(&mut state, &status)?;
        if result.key.starts_with("red-team-repair-submit-") {
            repair::job_submitted(&mut state, &status.job_id);
            let _ = repair::job_status(&mut state, &status)?;
            state.pending = None;
            state::save(parameters, &state)?;
            return repair::next(parameters, &host, &mut state);
        }
        if result.key.starts_with("red-team-investigation-submit-") {
            investigation::job_submitted(&mut state, &status.job_id);
            let _ = investigation::job_status(&mut state, &status);
            state.pending = None;
            state::save(parameters, &state)?;
            return investigation::next(parameters, &host, &mut state);
        }
        state.pending = None;
        state::save(parameters, &state)?;
        return Ok(reply(job_status_text(&status), &host, actions(&state), None));
    }
    if expected_capability == HOST_CAPABILITY_APPLICATION_LABORATORY {
        return laboratory::admit(parameters, &host, &mut state, pending, output);
    }
    let text = match pending {
        PendingRequest::AdapterCatalog { .. }
        | PendingRequest::AdapterPrepare { .. }
        | PendingRequest::AdapterComplete { .. }
        | PendingRequest::AdapterCancel { .. }
        | PendingRequest::AdapterStatus { .. }
        | PendingRequest::AdapterRemove { .. }
        | PendingRequest::AdapterExecute { .. } => {
            return Err(invalid("adapter host result was routed through a non-adapter capability"));
        }
        PendingRequest::LaboratoryCatalog { .. }
        | PendingRequest::LaboratoryCreate { .. }
        | PendingRequest::LaboratorySourceCreate { .. }
        | PendingRequest::LaboratoryLifecycle { .. }
        | PendingRequest::LaboratoryInvoke { .. } => {
            return Err(invalid(
                "laboratory host result was routed through a non-laboratory capability",
            ));
        }
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
            return Err(invalid("proof-job result bypassed the generic worker admission path"));
        }
        PendingRequest::JobPoll { .. } | PendingRequest::JobCancel { .. } => {
            let status: ModuleJobStatus = serde_json::from_value(output)?;
            admit_job_status(&mut state, &status)?;
            if result.key.starts_with("red-team-repair-poll-") {
                let terminal = repair::job_status(&mut state, &status)?;
                state.pending = None;
                if terminal {
                    state::save(parameters, &state)?;
                    return repair::next(parameters, &host, &mut state);
                }
                let action = repair::poll_action(&mut state, status.job_id)?;
                state::save(parameters, &state)?;
                return Ok(action);
            }
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
        PendingRequest::SourceVerify { .. } => {
            let verification: ScopedSourceVerification = serde_json::from_value(output)?;
            repair::original_verified(&mut state, verification.clone());
            format!(
                "# Original-workspace byte verification\n\n- Starting snapshot: `{}`\n- Observed manifest: `{}`\n- Unchanged: {}\n- Changed paths: {}\n- Added paths: {}\n- Removed paths: {}",
                verification.snapshot_digest,
                verification.observed_manifest_digest,
                verification.unchanged,
                list_or_none(&verification.changed_paths),
                list_or_none(&verification.added_paths),
                list_or_none(&verification.removed_paths),
            )
        }
    };
    state.pending = None;
    state::save(parameters, &state)?;
    Ok(reply(text, &host, actions(&state), None))
}

fn pending_capability(pending: &PendingRequest) -> &'static str {
    match pending {
        PendingRequest::AdapterCatalog { .. }
        | PendingRequest::AdapterPrepare { .. }
        | PendingRequest::AdapterComplete { .. }
        | PendingRequest::AdapterCancel { .. }
        | PendingRequest::AdapterStatus { .. }
        | PendingRequest::AdapterRemove { .. }
        | PendingRequest::AdapterExecute { .. } => HOST_CAPABILITY_WORKER,
        PendingRequest::LaboratoryCatalog { .. }
        | PendingRequest::LaboratoryCreate { .. }
        | PendingRequest::LaboratorySourceCreate { .. }
        | PendingRequest::LaboratoryLifecycle { .. }
        | PendingRequest::LaboratoryInvoke { .. } => HOST_CAPABILITY_APPLICATION_LABORATORY,
        PendingRequest::Capture { .. }
        | PendingRequest::Manifest { .. }
        | PendingRequest::Read { .. }
        | PendingRequest::Revoke { .. }
        | PendingRequest::SourceVerify { .. } => HOST_CAPABILITY_SCOPED_SOURCE,
        PendingRequest::JobSubmit { .. } => HOST_CAPABILITY_WORKER,
        PendingRequest::JobPoll { .. }
        | PendingRequest::JobLog { .. }
        | PendingRequest::JobCancel { .. } => HOST_CAPABILITY_WORKER,
    }
}

pub(crate) fn admit_job_status(state: &mut State, status: &ModuleJobStatus) -> Result<(), Error> {
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
        text: "Red Team checkpoint was written to private module state. It retains exact source observations, pinned static-analysis leads, module-captured class-specific receipts, cross-adapter graph edges and counterfactuals, laboratory identities/status/receipts, copy-only patches, adapter replay receipts, independent reviews, original-byte proof, reuse measurements, and explicit gaps.".into(),
        actions: actions(&state),
    })
}

fn checkpoint_ack(parameters: &Value) -> Result<ModuleAction, Error> {
    let key = parameters["key"]
        .as_str()
        .ok_or_else(|| invalid("checkpoint acknowledgement is missing key"))?;
    let mut state = state::load(parameters)?;
    let checkpoint =
        state.checkpoint.as_mut().ok_or_else(|| invalid("no Red Team checkpoint is pending"))?;
    if key != CHECKPOINT_KEY || checkpoint.key != key {
        return Err(invalid("checkpoint acknowledgement key does not match retained state"));
    }
    checkpoint.acknowledged = true;
    state::save(parameters, &state)?;
    Ok(reply(
        "Red Team checkpoint is durably acknowledged.",
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
        "# Red Team investigation and repair\n\n- Module: `peritus.red-team` {}\n- Durable schema: v{}\n- Campaign state: `{:?}`\n- Investigation stage: `{:?}`\n- Repair stage: `{:?}`\n- Complete-journey stage: `{:?}`\n- Complete-journey progress: {}/{}\n- Complete-journey gaps/failures: {}\n- Paused: {}\n- Scope revision: `{}`\n- Source snapshot: `{}`\n- Manifest artifact: `{}`\n- Current source observations: {}\n- Invalidated source observations: {}\n- Target profiles: {}\n- Application surfaces: {}\n- Method-backed coverage cells: {}\n- Coverage cells examined: {}\n- Coverage cells blocked: {}\n- Managed adapter lifecycle observations: {}\n- Adapter execution receipts: {}\n- Static-analysis observations: {}\n- Static-analysis source evidence: {}\n- HTTP/API campaigns: {}\n- HTTP/API evidence records: {}\n- Browser campaigns: {}\n- Identity/access campaigns: {}\n- File/parser campaigns: {}\n- Workflow/state campaigns: {}\n- Boundary/authority campaigns: {}\n- Boundary/authority evidence records: {}\n- Attack-graph campaigns: {}\n- Attack-graph evidence records: {}\n- Generic application campaigns: {}\n- Retained adapter errors: {}\n- Laboratory lifecycle observations: {}\n- Laboratory operation receipts: {}\n- Retained laboratory errors: {}\n- Latest laboratory phase: `{}`\n- Retained hypotheses: {}\n- Retained probes: {}\n- Retained module worker operations: {}\n- Active module worker operations: {}\n- Trusted job receipts: {}\n- Skeptically adjudicated findings: {}\n- Patch revisions: {}\n- Patch replay receipts: {}\n- Original workspace unchanged: {}\n- Security families unexamined: {}\n- Reused exact source reads: {}\n- Foundation checkpoint: {}\n\nThe source handle is revocable. Managed adapters require exact registered descriptors, content identities, platforms, operations and module receipt decoders. Static analysis uses immutable source, pinned module rules and redacted source-only leads; it never establishes runtime exploitability. Runtime adapters can reach only ready opaque disposable-laboratory endpoints; the module captures protocol bytes, copied state, private peer effects, and explicit unavailable-platform gaps while denying ambient network, credentials, privilege, and host tools. Cross-adapter graph search admits only receipt-backed edges, preserves broken and rejected paths, and accepts copy-only repair only after exact source, HTTP, and real-browser replay. Application laboratories require copied immutable source, opaque handles, generic host containment and module-owned target execution, real readiness, state readback, reset, process cleanup and original-source proof. The complete journey schedules only one module operation at a time; steering text and target output remain untrusted and cannot widen authority. Every model role receives the canonical skill directly. The Rust coordinator alone admits source observations, module-authored original and patched execution receipts, classifications, coverage transitions, patch states, and before/after proof; unsuccessful attempts do not establish safety.",
        state.module_version,
        state.schema,
        state.campaign.state,
        state.investigation.stage,
        state.repair.stage,
        state.journey.stage,
        state.journey.cursor,
        state.journey.steps.len(),
        state.journey.failures.len(),
        state.investigation.paused,
        scope.map_or("not selected", |record| record.id.value.as_str()),
        snapshot.map_or("not captured", |record| record.snapshot_digest.as_str()),
        snapshot.map_or("not captured", |record| record.manifest_artifact.as_str()),
        current,
        invalidated,
        state.target_profiles.len(),
        state.application_surfaces.len(),
        state.coverage_cells.len(),
        state
            .coverage_cells
            .iter()
            .filter(|cell| cell.state == records::CoverageState::Examined)
            .count(),
        state
            .coverage_cells
            .iter()
            .filter(|cell| cell.state == records::CoverageState::Blocked)
            .count(),
        state.adapter_statuses.len(),
        state.adapter_receipts.len(),
        state.analysis_observations.len(),
        state.analysis_evidence.len(),
        state.api_observations.len(),
        state.api_evidence.len(),
        state.browser_observations.len(),
        state.identity_observations.len(),
        state.file_fuzz_observations.len(),
        state.workflow_observations.len(),
        state.boundary_observations.len(),
        state.boundary_evidence.len(),
        state.attack_graph_observations.len(),
        state.attack_graph_evidence.len(),
        state.application_observations.len(),
        state.adapter_errors.len(),
        state.laboratory_statuses.len(),
        state.laboratory_receipts.len(),
        state.laboratory_errors.len(),
        state
            .laboratory_statuses
            .last()
            .map_or_else(|| "not created".into(), |status| format!("{:?}", status.phase)),
        state.hypotheses.len(),
        state.investigation.probes.len(),
        state.jobs.len(),
        active_jobs,
        state.job_receipts.len(),
        state.findings.len(),
        state.patches.len(),
        state.patch_receipts.len(),
        state.original_verification.as_ref().is_some_and(|proof| proof.unchanged),
        state
            .coverage
            .iter()
            .filter(|record| matches!(record.state, records::CoverageState::Unexamined))
            .count(),
        state.investigation.reuse.source_reads_reused,
        checkpoint,
    )
}

fn findings(state: &State) -> String {
    let mut text = "# Red Team findings\n\nClassifications describe the retained evidence boundary; they are not vulnerability-severity or whole-project safety claims.\n\n".to_owned();
    if state.findings.is_empty() {
        text.push_str("No finding has been independently adjudicated yet.\n");
        return text;
    }
    for finding in &state.findings {
        let hypothesis =
            state.hypotheses.iter().find(|hypothesis| hypothesis.id.value == finding.hypothesis_id);
        text.push_str(&format!(
            "## `{}` — `{:?}`\n\n- Hypothesis: `{}`\n- Entry point: {}\n- Security property: {}\n- Evidence records: {}\n- Independent review: `{}`\n- Supersedes: `{}`\n\n",
            finding.id.value,
            finding.classification,
            finding.hypothesis_id,
            hypothesis.map_or("unavailable", |value| value.entry_point.as_str()),
            hypothesis.map_or("unavailable", |value| value.security_property.as_str()),
            finding.evidence.len(),
            finding.review.as_ref().map_or("none", |value| value.value.as_str()),
            finding.supersedes.as_ref().map_or("none", |value| value.value.as_str()),
        ));
    }
    text
}

fn patches(state: &State) -> String {
    let mut text = "# Red Team copy-only patches and diffs\n\nEvery state below is bounded to its recorded replay matrix. No patch was applied to the selected original workspace.\n\n".to_owned();
    if state.repair.plans.is_empty() {
        text.push_str("No patch plan has been retained yet.\n");
        return text;
    }
    for plan in &state.repair.plans {
        let lifecycle = state
            .patches
            .iter()
            .rev()
            .find(|patch| plan.diff_artifact.as_ref() == Some(&patch.diff_artifact))
            .map(|patch| format!("{:?}", patch.state))
            .unwrap_or_else(|| "Proposed".into());
        text.push_str(&format!(
            "## Finding `{}` · order {}\n\n- State: `{lifecycle}`\n- Target: `{}`\n- Root cause: {}\n- Expected preimage: `{}`\n- Patch identity: `{}`\n- Diff artifact: `{}`\n- Review: `{}`\n\n",
            plan.finding_id,
            plan.order,
            plan.target_path,
            plan.root_cause,
            plan.expected_source_digest,
            plan.patch_digest.as_deref().unwrap_or("not materialized"),
            plan.diff_artifact.as_deref().unwrap_or("not materialized"),
            plan.review_id.as_ref().map_or("none", |value| value.value.as_str()),
        ));
        for case in &plan.cases {
            text.push_str(&format!(
                "- `{}` / `{:?}` — `{:?}` — {}\n",
                case.id, case.category, case.state, case.detail
            ));
        }
        if let Some(diff) = &plan.diff_bytes {
            text.push_str("\n```diff\n");
            text.push_str(&String::from_utf8_lossy(diff).replace("```", "` ` `"));
            text.push_str("```\n\n");
        }
    }
    text
}

fn contract(profile: &Option<ModuleHostProfile>) -> Result<ModuleAction, Error> {
    Ok(reply(
        "# Red Team module boundary\n\nPeritus supplies generic module lifecycle, revocable scoped-source authority, complete disposable source copies, bounded opaque worker execution, persistence, original-source comparison, and common TUI/WebUI transport. It does not know Red Team adapter names, security classes, target recipes, evidence schemas, canaries, or finding rules.\n\nThe Red Team module owns its adapter registry and implementations; deterministic source analysis; target selection and launch inside the disposable worker copy; HTTP, browser, identity, file/parser, workflow, boundary, and attack-graph campaigns; module-private credentials and canaries; response/state oracles; evidence admission; skeptic decisions; copy-only repair replay; and reports. Adapter input and output are opaque JSON to Peritus.\n\nThe generic host still enforces the outer safety boundary: only explicitly scoped source is copied, worker resources and lifetime are bounded, ambient credentials and networking are denied, cleanup is observed, and the selected original workspace is compared after execution. The module cannot edit, commit, push, deploy, or publish the original project. Applying a returned patch is a separate user action.",
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
    let jobs = if profile.supports(HOST_CAPABILITY_WORKER, 1) { "available" } else { "missing" };
    let adapters =
        if profile.supports(HOST_CAPABILITY_WORKER, 1) { "available" } else { "missing" };
    let laboratories = if profile.supports(HOST_CAPABILITY_APPLICATION_LABORATORY, 1) {
        "available"
    } else {
        "missing"
    };
    let required = [
        HOST_CAPABILITY_SCOPED_SOURCE,
        HOST_CAPABILITY_CHECKPOINT,
        HOST_CAPABILITY_PRIVATE_STATE,
        HOST_CAPABILITY_WORKER,
        HOST_CAPABILITY_APPLICATION_LABORATORY,
    ]
    .into_iter()
    .filter(|name| !profile.supports(name, 1))
    .collect::<Vec<_>>();
    format!(
        "# Red Team host compatibility\n\nScoped source: **{source}**.\n\nModule-owned proof and copy-only replay workers: **{jobs}**.\n\nModule-owned adapter runtime: **{adapters}**.\n\nGeneric disposable application laboratory: **{laboratories}**.\n\nAvailable v1 capabilities: {}.\n\nMissing required generic capabilities: {}.\n\nSource-build capability is used by the module market before installation, not by a running investigation. Missing capabilities do not cause ambient filesystem, process, container, endpoint or network fallback.",
        capability_names(profile).join(", "),
        list_or_none(&required),
    )
}

fn supports_source(profile: &Option<ModuleHostProfile>) -> bool {
    profile.as_ref().is_some_and(|profile| profile.supports(HOST_CAPABILITY_SCOPED_SOURCE, 1))
}

fn supports_jobs(profile: &Option<ModuleHostProfile>) -> bool {
    profile.as_ref().is_some_and(|profile| profile.supports(HOST_CAPABILITY_WORKER, 1))
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
        "This Peritus host does not advertise `module.worker@1`. Red Team will not execute the target through a raw command or unrestricted fallback.",
        profile,
        base_actions(),
        None,
    )
}

fn actions(state: &State) -> Vec<ModuleMenuAction> {
    let investigation_started =
        !matches!(state.investigation.stage, state::InvestigationStage::NotStarted);
    let mut result = journey::actions(state);
    let mut investigation_actions = if !investigation_started {
        vec![action("Status", "status", true)]
    } else {
        investigation::actions(state)
    };
    result.append(&mut investigation_actions);
    if state.active_snapshot().is_none() {
        result.push(action("Scope current workspace", "scope", true));
    } else {
        if !investigation_started {
            result.push(action("Start autonomous investigation", "start", true));
        }
        result.extend([
            action("Static analyzer support", "analyzers", true),
            action("Install static analyzers", "analyzer-install", true),
            action("Analyze scoped source", "analyze", true),
            action("Static analysis history", "analysis-history", true),
            action("HTTP/API support", "api", true),
            action("Install HTTP/API adapter", "api-install", true),
            action("Run HTTP/API campaign", "api-run", true),
            action("HTTP/API campaign history", "api-history", true),
            action("Browser-client support", "browser", true),
            action("Install browser-client adapter", "browser-install", true),
            action("Run real-browser campaign", "browser-run", true),
            action("Browser campaign history", "browser-history", true),
            action("Identity/access support", "identity", true),
            action("Install identity/access adapter", "identity-install", true),
            action("Run identity/access campaign", "identity-run", true),
            action("Identity/access history", "identity-history", true),
            action("File/parser fuzz support", "file-fuzz", true),
            action("Install file/parser adapter", "file-fuzz-install", true),
            action("Run file/parser campaign", "file-fuzz-run", true),
            action("File/parser campaign history", "file-fuzz-history", true),
            action("Workflow/state support", "workflow", true),
            action("Install workflow/state adapter", "workflow-install", true),
            action("Run workflow/state campaign", "workflow-run", true),
            action("Workflow/state campaign history", "workflow-history", true),
            action("Boundary/authority support", "boundary", true),
            action("Install boundary/authority adapter", "boundary-install", true),
            action("Run boundary/authority campaign", "boundary-run", true),
            action("Boundary/authority campaign history", "boundary-history", true),
            action("Attack-graph support", "graph", true),
            action("Install attack-graph adapter", "graph-install", true),
            action("Run cross-adapter attack graph", "graph-run", true),
            action("Attack-graph history", "graph-history", true),
            action("Generic application campaign", "application", true),
            action("Install generic application binding", "application-install", true),
            action("Run generic application attacks", "application-run", true),
            action("Refresh source", "refresh", true),
            action("Target profiles", "profiles", true),
            action("Surface graph", "surfaces", true),
            action("Method registry", "methods", true),
            action("Coverage cells", "coverage", true),
            action("View manifest", "manifest", true),
            action("Observe source path", "observe ", false),
            action("Prepare pinned dependency", "prepare ", false),
            action("Run contained proof", "probe ", false),
            action("Revoke source", "revoke", true),
        ]);
        if journey::diamond_source_observed(state) {
            result.extend([
                action("Diamond application binding", "diamond", true),
                action("Install Diamond application binding", "diamond-install", true),
                action("Run complete Diamond campaign", "diamond-run", true),
            ]);
        }
        if !investigation_started {
            result.extend([
                action("Contained jobs", "jobs", true),
                action("Current report", "report", true),
            ]);
        }
    }
    if let Some(laboratory) = state.laboratory_statuses.last() {
        match laboratory.phase {
            peritus_plugin_sdk::ModuleLaboratoryPhase::Created => {
                result.push(action("Prepare laboratory", "lab-prepare", true));
            }
            peritus_plugin_sdk::ModuleLaboratoryPhase::Prepared
            | peritus_plugin_sdk::ModuleLaboratoryPhase::Stopped => {
                result.push(action("Launch laboratory", "lab-launch", true));
                result.push(action("Tear down laboratory", "lab-teardown", true));
            }
            peritus_plugin_sdk::ModuleLaboratoryPhase::Ready => {
                result.extend([
                    action("Use laboratory", "lab-use ", false),
                    action("Run HTTP/API campaign", "api-run", true),
                    action("Run real-browser campaign", "browser-run", true),
                    action("Run identity/access campaign", "identity-run", true),
                    action("Run file/parser campaign", "file-fuzz-run", true),
                    action("Run workflow/state campaign", "workflow-run", true),
                    action("Run boundary/authority campaign", "boundary-run", true),
                    action("Run cross-adapter attack graph", "graph-run", true),
                    action("Run generic application attacks", "application-run", true),
                    action("Snapshot laboratory", "lab-snapshot", true),
                    action("Reset laboratory", "lab-reset", true),
                    action("Stop laboratory", "lab-stop", true),
                ]);
            }
            peritus_plugin_sdk::ModuleLaboratoryPhase::Failed
            | peritus_plugin_sdk::ModuleLaboratoryPhase::Quarantined => {
                result.push(action("Tear down laboratory", "lab-teardown", true));
            }
            peritus_plugin_sdk::ModuleLaboratoryPhase::TornDown => {}
        }
    }
    result.extend([
        action("Static analyzer status", "analyzer-status", true),
        action("HTTP/API adapter status", "api-status", true),
        action("Browser-client adapter status", "browser-status", true),
        action("Identity/access adapter status", "identity-status", true),
        action("File/parser adapter status", "file-fuzz-status", true),
        action("Workflow/state adapter status", "workflow-status", true),
        action("Boundary/authority adapter status", "boundary-status", true),
        action("Attack-graph adapter status", "graph-status", true),
        action("Generic application adapter status", "application-status", true),
        action("Managed adapters", "adapters", true),
        action("Install diagnostic adapter", "adapter-install diagnostic", true),
        action("Adapter status", "adapter-status", true),
        action("Adapter history", "adapter-history", true),
        action("Laboratory recipes", "laboratories", true),
        action("Create fixture laboratory", "lab-create fixture", true),
        action("Create vulnerable HTTP/API laboratory", "lab-create http-vulnerable", true),
        action("Create safe HTTP/API laboratory", "lab-create http-safe", true),
        action("Create vulnerable identity laboratory", "lab-create identity-vulnerable", true),
        action("Create safe identity laboratory", "lab-create identity-safe", true),
        action("Create vulnerable workflow laboratory", "lab-create workflow-vulnerable", true),
        action("Create safe workflow laboratory", "lab-create workflow-safe", true),
        action("Create vulnerable boundary laboratory", "lab-create boundary-vulnerable", true),
        action("Create safe boundary laboratory", "lab-create boundary-safe", true),
        action("Laboratory status", "lab-status", true),
        action("Laboratory history", "laboratory-history", true),
        action("Check compatibility", "compatibility", true),
        action("View contract", "contract", true),
        action("Save investigation checkpoint", "checkpoint", true),
    ]);
    result
}

fn base_actions() -> Vec<ModuleMenuAction> {
    let mut result = vec![
        action("View source-bound campaign plan", "campaign-plan", true),
        action("Start source-bound campaign", "campaign-start", true),
        action("Status", "status", true),
        action("Static analyzer support", "analyzers", true),
        action("Install static analyzers", "analyzer-install", true),
        action("HTTP/API support", "api", true),
        action("Install HTTP/API adapter", "api-install", true),
        action("Browser-client support", "browser", true),
        action("Install browser-client adapter", "browser-install", true),
        action("Identity/access support", "identity", true),
        action("Install identity/access adapter", "identity-install", true),
        action("Boundary/authority support", "boundary", true),
        action("Install boundary/authority adapter", "boundary-install", true),
        action("Attack-graph support", "graph", true),
        action("Install attack-graph adapter", "graph-install", true),
        action("Generic application support", "application", true),
        action("Install generic application binding", "application-install", true),
        action("Managed adapters", "adapters", true),
        action("Install diagnostic adapter", "adapter-install diagnostic", true),
        action("Adapter history", "adapter-history", true),
        action("Laboratory recipes", "laboratories", true),
        action("Create fixture laboratory", "lab-create fixture", true),
        action("Create vulnerable HTTP/API laboratory", "lab-create http-vulnerable", true),
        action("Create safe HTTP/API laboratory", "lab-create http-safe", true),
        action("Create vulnerable identity laboratory", "lab-create identity-vulnerable", true),
        action("Create safe identity laboratory", "lab-create identity-safe", true),
        action("Create vulnerable boundary laboratory", "lab-create boundary-vulnerable", true),
        action("Create safe boundary laboratory", "lab-create boundary-safe", true),
        action("Laboratory history", "laboratory-history", true),
        action("Scope current workspace", "scope", true),
        action("Check compatibility", "compatibility", true),
        action("View contract", "contract", true),
    ];
    result.push(action("Export SARIF", "sarif", true));
    result
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

fn jobs(state: &State) -> String {
    if state.jobs.is_empty() {
        return "# Contained jobs\n\nNo worker receipt has been observed. Use `probe SOURCE_PATH [input=LITERAL]` after selecting source.".into();
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
