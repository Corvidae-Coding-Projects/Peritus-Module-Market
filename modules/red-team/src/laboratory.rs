//! Phase-eleven disposable application laboratory coordinated through the typed host capability.

use crate::{
    Error, invalid, reply, state,
    state::{PendingRequest, RuntimeTarget, RuntimeTargetBinding},
};
use peritus_plugin_sdk::{
    HOST_CAPABILITY_APPLICATION_LABORATORY, ModuleAction, ModuleHostProfile, ModuleHostRequest,
    ModuleLaboratoryCatalog, ModuleLaboratoryInvokeRequest, ModuleLaboratoryLifecycleRequest,
    ModuleLaboratoryProcessInput, ModuleLaboratoryResult, ModuleLaboratorySourceCreateRequest,
};
use serde_json::{Value, json};

const RECIPE: &str = "linux.python-unix-store.v1";
const HTTP_RECIPE: &str = "linux.python-http-api.v1";
const PROCESS_OPERATION: &str = "process.execute.v1";
const FIXTURE_APPLICATION: &str = "modules/red-team/corpus/laboratory-mixed/application.py";
const FIXTURE_SERVICE: &str = "modules/red-team/corpus/laboratory-mixed/service.py";
const HTTP_VULNERABLE_APPLICATION: &str =
    "modules/red-team/corpus/http-api/vulnerable/application.py";
const HTTP_VULNERABLE_SERVICE: &str = "modules/red-team/corpus/http-api/vulnerable/service.py";
const HTTP_SAFE_APPLICATION: &str = "modules/red-team/corpus/http-api/safe/application.py";
const HTTP_SAFE_SERVICE: &str = "modules/red-team/corpus/http-api/safe/service.py";
const IDENTITY_VULNERABLE_APPLICATION: &str =
    "modules/red-team/corpus/identity-access/vulnerable/application.py";
const IDENTITY_VULNERABLE_SERVICE: &str =
    "modules/red-team/corpus/identity-access/vulnerable/service.py";
const IDENTITY_SAFE_APPLICATION: &str =
    "modules/red-team/corpus/identity-access/safe/application.py";
const IDENTITY_SAFE_SERVICE: &str = "modules/red-team/corpus/identity-access/safe/service.py";
const FILE_VULNERABLE_APPLICATION: &str =
    "modules/red-team/corpus/file-parser/vulnerable/application.py";
const FILE_VULNERABLE_SERVICE: &str = "modules/red-team/corpus/file-parser/vulnerable/service.py";
const FILE_SAFE_APPLICATION: &str = "modules/red-team/corpus/file-parser/safe/application.py";
const FILE_SAFE_SERVICE: &str = "modules/red-team/corpus/file-parser/safe/service.py";
const WORKFLOW_VULNERABLE_APPLICATION: &str =
    "modules/red-team/corpus/workflow-state/vulnerable/application.py";
const WORKFLOW_SAFE_APPLICATION: &str =
    "modules/red-team/corpus/workflow-state/safe/application.py";
const WORKFLOW_SERVICE: &str = "modules/red-team/corpus/workflow-state/shared-service.py";
const BOUNDARY_VULNERABLE_APPLICATION: &str =
    "modules/red-team/corpus/boundary-authority/vulnerable/application.py";
const BOUNDARY_SAFE_APPLICATION: &str =
    "modules/red-team/corpus/boundary-authority/safe/application.py";
const BOUNDARY_SERVICE: &str = "modules/red-team/corpus/boundary-authority/shared-service.py";

pub(crate) fn handles(command: &str) -> bool {
    matches!(
        command,
        "laboratories"
            | "laboratory-history"
            | "lab-create source"
            | "lab-create fixture"
            | "lab-create http-vulnerable"
            | "lab-create http-safe"
            | "lab-create identity-vulnerable"
            | "lab-create identity-safe"
            | "lab-create file-vulnerable"
            | "lab-create file-safe"
            | "lab-create workflow-vulnerable"
            | "lab-create workflow-safe"
            | "lab-create boundary-vulnerable"
            | "lab-create boundary-safe"
            | "lab-prepare"
            | "lab-launch"
            | "lab-status"
            | "lab-snapshot"
            | "lab-reset"
            | "lab-run-auto"
            | "lab-stop"
            | "lab-teardown"
            | "lab-probe-wrong-endpoint"
            | "lab-probe-unregistered-operation"
    ) || command.starts_with("lab-create ")
        || command.starts_with("lab-create-http ")
        || command.starts_with("lab-run ")
        || command.starts_with("lab-run-json ")
        || command.starts_with("lab-select ")
        || command.starts_with("lab-use ")
}

pub(crate) fn command(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
    command: &str,
) -> Result<ModuleAction, Error> {
    if !supports(profile) {
        return Ok(reply(
            "This Peritus host does not advertise `module.application-laboratory@1`. Disposable application execution remains blocked; no local process, container, endpoint, or ambient command fallback was attempted.",
            profile,
            super::actions(state),
            None,
        ));
    }
    match command {
        "laboratories" => service(
            parameters,
            state,
            PendingRequest::LaboratoryCatalog { key: next_key(state, "catalog") },
            "catalog",
        ),
        "laboratory-history" => Ok(reply(view(state), profile, super::actions(state), None)),
        "lab-create source" => create_source(parameters, state),
        "lab-create fixture" => {
            create(parameters, state, RECIPE, FIXTURE_APPLICATION.into(), FIXTURE_SERVICE.into())
        }
        "lab-create http-vulnerable" => create(
            parameters,
            state,
            HTTP_RECIPE,
            HTTP_VULNERABLE_APPLICATION.into(),
            HTTP_VULNERABLE_SERVICE.into(),
        ),
        "lab-create http-safe" => create(
            parameters,
            state,
            HTTP_RECIPE,
            HTTP_SAFE_APPLICATION.into(),
            HTTP_SAFE_SERVICE.into(),
        ),
        "lab-create identity-vulnerable" => create(
            parameters,
            state,
            HTTP_RECIPE,
            IDENTITY_VULNERABLE_APPLICATION.into(),
            IDENTITY_VULNERABLE_SERVICE.into(),
        ),
        "lab-create identity-safe" => create(
            parameters,
            state,
            HTTP_RECIPE,
            IDENTITY_SAFE_APPLICATION.into(),
            IDENTITY_SAFE_SERVICE.into(),
        ),
        "lab-create file-vulnerable" => create(
            parameters,
            state,
            HTTP_RECIPE,
            FILE_VULNERABLE_APPLICATION.into(),
            FILE_VULNERABLE_SERVICE.into(),
        ),
        "lab-create file-safe" => create(
            parameters,
            state,
            HTTP_RECIPE,
            FILE_SAFE_APPLICATION.into(),
            FILE_SAFE_SERVICE.into(),
        ),
        "lab-create workflow-vulnerable" => create(
            parameters,
            state,
            HTTP_RECIPE,
            WORKFLOW_VULNERABLE_APPLICATION.into(),
            WORKFLOW_SERVICE.into(),
        ),
        "lab-create workflow-safe" => create(
            parameters,
            state,
            HTTP_RECIPE,
            WORKFLOW_SAFE_APPLICATION.into(),
            WORKFLOW_SERVICE.into(),
        ),
        "lab-create boundary-vulnerable" => create(
            parameters,
            state,
            HTTP_RECIPE,
            BOUNDARY_VULNERABLE_APPLICATION.into(),
            BOUNDARY_SERVICE.into(),
        ),
        "lab-create boundary-safe" => create(
            parameters,
            state,
            HTTP_RECIPE,
            BOUNDARY_SAFE_APPLICATION.into(),
            BOUNDARY_SERVICE.into(),
        ),
        _ if command.starts_with("lab-create-http ") => {
            let paths = command
                .trim_start_matches("lab-create-http ")
                .split_whitespace()
                .collect::<Vec<_>>();
            if paths.len() != 2 {
                return Err(invalid(
                    "lab-create-http requires exactly APPLICATION_PATH SERVICE_PATH",
                ));
            }
            create(parameters, state, HTTP_RECIPE, paths[0].into(), paths[1].into())
        }
        "lab-prepare" | "lab-launch" | "lab-status" | "lab-snapshot" | "lab-reset" | "lab-stop"
        | "lab-teardown" => {
            let operation = command.trim_start_matches("lab-");
            lifecycle(parameters, state, operation)
        }
        "lab-probe-wrong-endpoint" => invoke(
            parameters,
            state,
            "not-the-retained-endpoint".into(),
            "state.round-trip.v1",
            "must-not-write",
        ),
        "lab-probe-unregistered-operation" => {
            let endpoint = current_status(state)?.handle.endpoint_handle.clone();
            invoke(parameters, state, endpoint, "state.not-registered.v1", "must-not-write")
        }
        "lab-run-auto" => {
            let laboratory_id = current_status(state)?.handle.laboratory_id.clone();
            let candidate = state
                .laboratory_receipts
                .iter()
                .rev()
                .find(|receipt| {
                    receipt.laboratory_id == laboratory_id && receipt.operation == "prepare"
                })
                .and_then(|receipt| receipt.observation["launch_candidates"].as_array())
                .and_then(|candidates| candidates.first())
                .ok_or_else(|| {
                    invalid(
                        "the complete source copy has no inferred launch candidate; use lab-run with the repository's actual runtime and entrypoint",
                    )
                })?;
            let runtime = candidate["runtime"]
                .as_str()
                .ok_or_else(|| invalid("host launch candidate has no runtime"))?;
            let entrypoint = candidate["entrypoint"]
                .as_str()
                .ok_or_else(|| invalid("host launch candidate has no entrypoint"))?;
            invoke_process(
                parameters,
                state,
                ModuleLaboratoryProcessInput {
                    schema: 1,
                    runtime: runtime.into(),
                    entrypoint: entrypoint.into(),
                    arguments: Vec::new(),
                    stdin: Vec::new(),
                    environment: std::collections::BTreeMap::new(),
                    wall_millis: 30_000,
                    expected_exit_codes: vec![0],
                    stdout_contains: Vec::new(),
                    stderr_contains: Vec::new(),
                },
            )
        }
        _ if command.starts_with("lab-run-json ") => {
            let encoded = command.trim_start_matches("lab-run-json ").trim();
            let input: ModuleLaboratoryProcessInput = serde_json::from_str(encoded)
                .map_err(|error| invalid(format!("lab-run-json input is invalid: {error}")))?;
            invoke_process(parameters, state, input)
        }
        _ if command.starts_with("lab-run ") => {
            let values = command
                .trim_start_matches("lab-run ")
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if values.len() < 2 {
                return Err(invalid(
                    "lab-run requires RUNTIME ENTRYPOINT followed by optional literal arguments",
                ));
            }
            invoke_process(
                parameters,
                state,
                ModuleLaboratoryProcessInput {
                    schema: 1,
                    runtime: values[0].clone(),
                    entrypoint: values[1].clone(),
                    arguments: values[2..].to_vec(),
                    stdin: Vec::new(),
                    environment: std::collections::BTreeMap::new(),
                    wall_millis: 30_000,
                    expected_exit_codes: vec![0],
                    stdout_contains: Vec::new(),
                    stderr_contains: Vec::new(),
                },
            )
        }
        _ if command.starts_with("lab-select ") => {
            let prefix = command.trim_start_matches("lab-select ").trim();
            if prefix.is_empty() {
                return Err(invalid("lab-select requires a laboratory identity or unique prefix"));
            }
            let mut seen = std::collections::BTreeSet::new();
            let matches = state
                .laboratory_statuses
                .iter()
                .rev()
                .filter(|status| seen.insert(status.handle.laboratory_id.as_str()))
                .filter(|status| status.handle.laboratory_id.starts_with(prefix))
                .cloned()
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                return Err(invalid(if matches.is_empty() {
                    "lab-select matched no retained laboratory"
                } else {
                    "lab-select prefix is ambiguous"
                }));
            }
            let selected = matches[0].clone();
            state.laboratory_statuses.push(selected.clone());
            state::save(parameters, state)?;
            Ok(reply(
                format!("# Laboratory selected\n\n{}", status_text(&selected)),
                profile,
                super::actions(state),
                None,
            ))
        }
        _ if command.starts_with("lab-use ") => {
            let value = command.trim_start_matches("lab-use ").trim();
            if value.is_empty() {
                return Err(invalid("lab-use requires a nonempty value"));
            }
            let endpoint = current_status(state)?.handle.endpoint_handle.clone();
            invoke(parameters, state, endpoint, "state.round-trip.v1", value)
        }
        _ => {
            let paths = command
                .strip_prefix("lab-create ")
                .ok_or_else(|| invalid("unknown laboratory command"))?
                .split_whitespace()
                .collect::<Vec<_>>();
            if paths.len() != 2 {
                return Err(invalid(
                    "lab-create requires exactly APPLICATION_PATH SERVICE_PATH, or `lab-create fixture`",
                ));
            }
            create(parameters, state, RECIPE, paths[0].into(), paths[1].into())
        }
    }
}

pub(crate) fn admit(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
    pending: PendingRequest,
    output: Value,
) -> Result<ModuleAction, Error> {
    let text = match pending {
        PendingRequest::LaboratoryCatalog { .. } => {
            let catalog: ModuleLaboratoryCatalog = serde_json::from_value(output)?;
            if catalog.schema != 1 {
                return Err(invalid("unsupported laboratory catalog schema"));
            }
            state.laboratory_catalog = Some(catalog.clone());
            catalog_text(&catalog)
        }
        PendingRequest::LaboratoryCreate { .. }
        | PendingRequest::LaboratoryLifecycle { .. }
        | PendingRequest::LaboratoryInvoke { .. } => {
            let result: ModuleLaboratoryResult = serde_json::from_value(output)?;
            if result.schema != 1 || result.status.schema != 1 {
                return Err(invalid("unsupported laboratory result schema"));
            }
            state.laboratory_statuses.push(result.status.clone());
            if let Some(receipt) = result.receipt {
                state.laboratory_receipts.push(receipt.clone());
                format!(
                    "{}\n\n## Module-authored receipt\n\n- Operation: `{}`\n- Request: `{}`\n- Application source: `{}`\n- Backing service source: `{}`\n- Isolation: `{}`\n- Network: `{}`\n- Process cleanup: {}\n- Original source unchanged: `{}`\n\n```json\n{}\n```",
                    status_text(&result.status),
                    receipt.operation,
                    receipt.request_digest,
                    receipt.application_digest,
                    receipt.service_digest,
                    receipt.isolation_backend,
                    receipt.network_policy,
                    receipt.process_cleanup_complete,
                    receipt
                        .original_source_unchanged
                        .map_or("not checked".into(), |value| value.to_string()),
                    serde_json::to_string_pretty(&receipt.observation)?,
                )
            } else {
                status_text(&result.status)
            }
        }
        PendingRequest::LaboratorySourceCreate { target, .. } => {
            let result: ModuleLaboratoryResult = serde_json::from_value(output)?;
            if result.schema != 1 || result.status.schema != 1 {
                return Err(invalid("unsupported laboratory result schema"));
            }
            if let Some(target) = target {
                state
                    .runtime_targets
                    .retain(|binding| binding.laboratory_id != result.status.handle.laboratory_id);
                state.runtime_targets.push(RuntimeTargetBinding {
                    laboratory_id: result.status.handle.laboratory_id.clone(),
                    target,
                });
            }
            state.laboratory_statuses.push(result.status.clone());
            if let Some(receipt) = result.receipt {
                state.laboratory_receipts.push(receipt.clone());
                format!(
                    "{}\n\n## Generic host receipt\n\n- Operation: `{}`\n- Request: `{}`\n- Isolation: `{}`\n- Network: `{}`\n- Process cleanup: {}\n- Original source unchanged: `{}`",
                    status_text(&result.status),
                    receipt.operation,
                    receipt.request_digest,
                    receipt.isolation_backend,
                    receipt.network_policy,
                    receipt.process_cleanup_complete,
                    receipt
                        .original_source_unchanged
                        .map_or("not checked".into(), |value| value.to_string()),
                )
            } else {
                status_text(&result.status)
            }
        }
        _ => return Err(invalid("non-laboratory pending request reached laboratory admission")),
    };
    state.pending = None;
    state::save(parameters, state)?;
    Ok(reply(text, profile, super::actions(state), None))
}

pub(crate) fn supports(profile: &Option<ModuleHostProfile>) -> bool {
    profile.as_ref().is_some_and(|value| value.supports(HOST_CAPABILITY_APPLICATION_LABORATORY, 1))
}

pub(crate) fn has_runtime_target(state: &state::State, laboratory_id: &str) -> bool {
    state.runtime_targets.iter().any(|binding| binding.laboratory_id == laboratory_id)
}

pub(crate) fn view(state: &state::State) -> String {
    let catalog = state.laboratory_catalog.as_ref().map(catalog_text).unwrap_or_else(|| {
        "# Disposable application laboratories\n\nCatalog not observed yet. Use `laboratories`."
            .into()
    });
    let latest = state
        .laboratory_statuses
        .last()
        .map(status_text)
        .unwrap_or_else(|| "No laboratory has been created.".into());
    let errors = if state.laboratory_errors.is_empty() {
        "none".into()
    } else {
        state
            .laboratory_errors
            .iter()
            .map(|error| format!("- {error}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    format!(
        "{catalog}\n\n## Latest retained laboratory\n\n{latest}\n\n## Module-authored receipts\n\n{}\n\n## Retained errors\n\n{errors}",
        state.laboratory_receipts.len(),
    )
}

fn create(
    parameters: &Value,
    state: &mut state::State,
    _recipe_id: &str,
    application_path: String,
    service_path: String,
) -> Result<ModuleAction, Error> {
    create_source_target(parameters, state, Some(RuntimeTarget { application_path, service_path }))
}

fn create_source(parameters: &Value, state: &mut state::State) -> Result<ModuleAction, Error> {
    create_source_target(parameters, state, None)
}

fn create_source_target(
    parameters: &Value,
    state: &mut state::State,
    target: Option<RuntimeTarget>,
) -> Result<ModuleAction, Error> {
    let source = state
        .active_handle()
        .ok_or_else(|| invalid("capture source with `scope` before creating a laboratory"))?;
    let request = ModuleLaboratorySourceCreateRequest { schema: 1, source };
    service(
        parameters,
        state,
        PendingRequest::LaboratorySourceCreate {
            key: next_key(state, "create-source"),
            request,
            target,
        },
        "create-source",
    )
}

fn lifecycle(
    parameters: &Value,
    state: &mut state::State,
    operation: &str,
) -> Result<ModuleAction, Error> {
    let laboratory_id = current_status(state)?.handle.laboratory_id.clone();
    let request = ModuleLaboratoryLifecycleRequest { schema: 1, laboratory_id };
    service(
        parameters,
        state,
        PendingRequest::LaboratoryLifecycle {
            key: next_key(state, operation),
            operation: operation.into(),
            request,
        },
        operation,
    )
}

fn invoke(
    parameters: &Value,
    state: &mut state::State,
    endpoint_handle: String,
    operation: &str,
    value: &str,
) -> Result<ModuleAction, Error> {
    let laboratory_id = current_status(state)?.handle.laboratory_id.clone();
    let request = ModuleLaboratoryInvokeRequest {
        schema: 1,
        laboratory_id,
        endpoint_handle,
        operation: operation.into(),
        input: json!({"key":"message","value":value}),
    };
    service(
        parameters,
        state,
        PendingRequest::LaboratoryInvoke { key: next_key(state, "invoke"), request },
        "invoke",
    )
}

fn invoke_process(
    parameters: &Value,
    state: &mut state::State,
    input: ModuleLaboratoryProcessInput,
) -> Result<ModuleAction, Error> {
    let status = current_status(state)?;
    let request = ModuleLaboratoryInvokeRequest {
        schema: 1,
        laboratory_id: status.handle.laboratory_id.clone(),
        endpoint_handle: status.handle.endpoint_handle.clone(),
        operation: PROCESS_OPERATION.into(),
        input: serde_json::to_value(input)?,
    };
    service(
        parameters,
        state,
        PendingRequest::LaboratoryInvoke { key: next_key(state, "process"), request },
        "invoke",
    )
}

fn service(
    parameters: &Value,
    state: &mut state::State,
    pending: PendingRequest,
    operation: &str,
) -> Result<ModuleAction, Error> {
    let input = match &pending {
        PendingRequest::LaboratoryCatalog { .. } => json!({}),
        PendingRequest::LaboratoryCreate { request, .. } => serde_json::to_value(request)?,
        PendingRequest::LaboratorySourceCreate { request, .. } => serde_json::to_value(request)?,
        PendingRequest::LaboratoryLifecycle { request, .. } => serde_json::to_value(request)?,
        PendingRequest::LaboratoryInvoke { request, .. } => serde_json::to_value(request)?,
        _ => return Err(invalid("non-laboratory request reached laboratory service")),
    };
    let key = pending.key().to_owned();
    state.pending = Some(pending);
    state::save(parameters, state)?;
    Ok(ModuleAction::HostService {
        request: ModuleHostRequest {
            key,
            capability: HOST_CAPABILITY_APPLICATION_LABORATORY.into(),
            version: 1,
            operation: operation.into(),
            input,
        },
    })
}

fn current_status(
    state: &state::State,
) -> Result<&peritus_plugin_sdk::ModuleLaboratoryStatus, Error> {
    state
        .laboratory_statuses
        .last()
        .ok_or_else(|| invalid("create a laboratory before using this command"))
}

fn next_key(state: &state::State, operation: &str) -> String {
    format!(
        "red-team-laboratory-{operation}-{}",
        state.laboratory_statuses.len()
            + state.laboratory_receipts.len()
            + state.laboratory_errors.len()
            + 1,
    )
}

fn catalog_text(catalog: &ModuleLaboratoryCatalog) -> String {
    let mut text = "# Red Team laboratory catalog\n\n".to_owned();
    for recipe in &catalog.recipes {
        text.push_str(&format!(
            "- `{}` {} — {}/{} — `{}` — interface `{}` — source roles {}\n",
            recipe.recipe_id,
            recipe.version,
            recipe.platform.os,
            recipe.platform.architecture,
            recipe.isolation_backend,
            recipe.interface,
            recipe.source_roles.join(", "),
        ));
    }
    text
}

fn status_text(status: &peritus_plugin_sdk::ModuleLaboratoryStatus) -> String {
    format!(
        "# Disposable application laboratory\n\n- Laboratory: `{}`\n- Recipe: `{}`\n- Phase: `{:?}`\n- Source snapshot: `{}`\n- Application service: `{}`\n- Backing service: `{}`\n- Endpoint handle: `{}`\n- Identity handle: `{}`\n- Secret handle: `{}`\n- Requests: {}\n- Input/output bytes: {}/{}\n- State digest: `{}`\n- Host loopback blocked: {}\n- Credential output blocked: {}\n- Snapshots: {}\n- Receipts: {}\n- Cleanup complete: {}\n- Detail: {}\n- Retained error: {}",
        status.handle.laboratory_id,
        status.handle.recipe_id,
        status.phase,
        status.handle.source_snapshot,
        status.handle.application_service,
        status.handle.backing_service,
        status.handle.endpoint_handle,
        status.handle.identity_handle,
        status.handle.secret_handle,
        status.telemetry.requests,
        status.telemetry.input_bytes,
        status.telemetry.output_bytes,
        status.telemetry.state_digest,
        status.telemetry.host_loopback_blocked,
        status.telemetry.credential_output_blocked,
        status.snapshots,
        status.receipts,
        status.cleanup_complete,
        status.detail,
        status.retained_error.as_deref().unwrap_or("none"),
    )
}
