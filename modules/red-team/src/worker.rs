//! Module-owned worker registry and execution.
//!
//! Peritus supplies only an isolated disposable source tree and raw process transport. Every
//! adapter identity, operation, implementation, receipt decoder, and observation is owned here.

use crate::{digest, source_analysis_worker};
use peritus_plugin_sdk::{
    ModuleAdapterCancelRequest, ModuleAdapterCatalog, ModuleAdapterCompleteRequest,
    ModuleAdapterDescriptor, ModuleAdapterExecuteRequest, ModuleAdapterExecutionReceipt,
    ModuleAdapterOperation, ModuleAdapterPhase, ModuleAdapterPlatform,
    ModuleAdapterPreparationHandle, ModuleAdapterPrepareRequest, ModuleAdapterProvenanceReceipt,
    ModuleAdapterRemoveRequest, ModuleAdapterRuntimeIdentity, ModuleAdapterStatus,
    ModuleAdapterStatusRequest, ModuleJobLimits, ModuleJobPhase, ModuleJobReceipt,
    ModuleJobRequest, ModuleJobStatus, ModuleJobVerdict, ModulePatchReceipt,
    ModuleSourceAnalysisRequest,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs,
    path::{Component, Path},
    process::Command,
};

const DIAGNOSTIC: &str = "peritus.diagnostic";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterInvocation {
    request_key: String,
    operation: String,
    request: Value,
    source_snapshot: String,
    #[serde(default)]
    targets: Vec<crate::runtime_laboratory::TargetBinding>,
}

pub(crate) fn dispatch(worker: &str, input: Value) -> Result<Value, String> {
    match worker {
        "adapter-runtime" => adapter_runtime(serde_json::from_value(input).map_err(json_error)?),
        "proof-job" => proof_job(input),
        _ => Err(format!("unknown Red Team worker `{worker}`")),
    }
}

fn proof_job(input: Value) -> Result<Value, String> {
    let source_snapshot = input
        .get("source_snapshot")
        .and_then(Value::as_str)
        .ok_or_else(|| "proof worker input has no source snapshot".to_string())?;
    let request: ModuleJobRequest = serde_json::from_value(
        input
            .get("request")
            .cloned()
            .ok_or_else(|| "proof worker input has no request".to_string())?,
    )
    .map_err(json_error)?;
    require_schema(request.schema)?;
    validate_job_limits(&request.limits)?;
    let request_bytes = serde_json::to_vec(&request).map_err(json_error)?;
    let request_digest = digest(&request_bytes);
    let job_id =
        digest(format!("red-team-proof-job-v1\0{source_snapshot}\0{request_digest}").as_bytes());
    let result = execute_proof(&job_id, source_snapshot, &request, &request_digest);
    let status = match result {
        Ok(receipt) => ModuleJobStatus {
            schema: 1,
            job_id,
            phase: ModuleJobPhase::Completed,
            operation: request.operation,
            request_digest,
            limits: request.limits,
            receipt: Some(receipt),
            detail: "Module-owned proof completed in the disposable source copy.".into(),
        },
        Err(detail) => ModuleJobStatus {
            schema: 1,
            job_id,
            phase: ModuleJobPhase::Failed,
            operation: request.operation,
            request_digest,
            limits: request.limits,
            receipt: None,
            detail,
        },
    };
    encode(status)
}

fn execute_proof(
    job_id: &str,
    source_snapshot: &str,
    request: &ModuleJobRequest,
    request_digest: &str,
) -> Result<ModuleJobReceipt, String> {
    let specification = request
        .specification
        .as_object()
        .ok_or_else(|| "proof specification must be an object".to_string())?;
    let target_path = specification
        .get("target_path")
        .and_then(Value::as_str)
        .ok_or_else(|| "proof specification has no target_path".to_string())?;
    validate_relative_path(target_path)?;
    let root = std::env::current_dir().map_err(|error| error.to_string())?;
    let target = fs::canonicalize(root.join(target_path)).map_err(|error| error.to_string())?;
    if !target.starts_with(fs::canonicalize(&root).map_err(|error| error.to_string())?)
        || !target.is_file()
    {
        return Err("proof target is not a regular file in the disposable source copy".into());
    }
    let original = fs::read(&target).map_err(|error| error.to_string())?;
    let original_digest = digest(&original);
    let attacker_input = specification
        .get("attacker_input")
        .and_then(Value::as_str)
        .ok_or_else(|| "proof specification has no attacker_input".to_string())?;
    if attacker_input.len() > 64 * 1024 || attacker_input.contains('\0') {
        return Err("proof attacker input exceeds module bounds".into());
    }
    let mut patch_receipt = None;
    let mut expected_stdout = None;
    if request.operation == "linux.patched-canary-replay.v1" {
        let patch = specification
            .get("patch")
            .and_then(Value::as_object)
            .ok_or_else(|| "patched replay has no patch specification".to_string())?;
        if patch.get("expected_source_digest").and_then(Value::as_str)
            != Some(original_digest.as_str())
        {
            return Err("patched replay source preimage does not match".into());
        }
        let replacement: Vec<u8> = serde_json::from_value(
            patch
                .get("replacement")
                .cloned()
                .ok_or_else(|| "patched replay has no replacement".to_string())?,
        )
        .map_err(json_error)?;
        fs::write(&target, &replacement).map_err(|error| error.to_string())?;
        let patched_digest = digest(&replacement);
        let diff_bytes = unified_diff(target_path, &original, &replacement)?;
        expected_stdout =
            patch.get("expected_stdout_fragment").and_then(Value::as_str).map(ToOwned::to_owned);
        patch_receipt = Some(ModulePatchReceipt {
            patch_digest: digest(
                format!("{original_digest}\0{patched_digest}\0{}", digest(&diff_bytes)).as_bytes(),
            ),
            source_path: target_path.into(),
            original_digest: original_digest.clone(),
            patched_digest,
            diff_artifact: digest(&diff_bytes),
            diff_bytes,
            case_id: required_string(patch, "case_id")?,
            findings: string_array(patch, "findings")?,
            prerequisites: string_array(patch, "prerequisites")?,
            order: patch
                .get("order")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| "patched replay has no valid order".to_string())?,
            dependencies: string_array(patch, "dependencies")?,
        });
    } else if request.operation != "linux.canary-disclosure.v1" {
        return Err("unknown module-owned proof operation".into());
    }
    let private = root.join(".red-team-worker-private").join(job_id);
    fs::create_dir_all(&private).map_err(|error| error.to_string())?;
    let canary = format!("peritus-red-team-canary-{}", &digest(job_id.as_bytes())[..24]);
    let canary_path = private.join("canary");
    fs::write(&canary_path, canary.as_bytes()).map_err(|error| error.to_string())?;
    let output = Command::new(&target)
        .arg(&canary_path)
        .arg(attacker_input)
        .current_dir(&root)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .output()
        .map_err(|error| format!("launch proof target: {error}"))?;
    let disclosed =
        contains(&output.stdout, canary.as_bytes()) || contains(&output.stderr, canary.as_bytes());
    let positive =
        expected_stdout.as_ref().is_none_or(|value| contains(&output.stdout, value.as_bytes()));
    let verdict = if patch_receipt.is_some() {
        if !disclosed && positive && output.status.success() {
            ModuleJobVerdict::PropertyHeldForCase
        } else {
            ModuleJobVerdict::ViolationObserved
        }
    } else if disclosed {
        ModuleJobVerdict::ViolationObserved
    } else {
        ModuleJobVerdict::PropertyHeldForCase
    };
    let exit_code = output.status.code();
    let target_digest = digest(&fs::read(&target).map_err(|error| error.to_string())?);
    let _ = fs::remove_dir_all(&private);
    Ok(ModuleJobReceipt {
        schema: 1,
        job_id: job_id.into(),
        operation: request.operation.clone(),
        request_digest: request_digest.into(),
        module_digest: digest(env!("CARGO_PKG_VERSION").as_bytes()),
        source_handle: request.source_handle.clone(),
        scope_revision: request.scope_revision.clone(),
        snapshot_digest: source_snapshot.into(),
        target_digest,
        backend: "peritus/module-worker@1".into(),
        execution_plan_digest: digest(
            format!("{}\0{}\0{}", request.operation, target_path, request_digest).as_bytes(),
        ),
        oracle_digest: digest(
            format!("canary-nondisclosure-v1\0{}", expected_stdout.as_deref().unwrap_or(""))
                .as_bytes(),
        ),
        verdict,
        terminal_disposition: if output.status.success() { "exited" } else { "failed" }.into(),
        exit_code,
        stdout_artifact: digest(&output.stdout),
        stderr_artifact: digest(&output.stderr),
        limits: request.limits.clone(),
        cleanup_complete: true,
        network_policy: "deny_all".into(),
        preparation: None,
        patch: patch_receipt,
    })
}

fn validate_job_limits(limits: &ModuleJobLimits) -> Result<(), String> {
    if limits.memory_bytes < 16 * 1024 * 1024
        || limits.memory_bytes > 2 * 1024 * 1024 * 1024
        || limits.storage_bytes == 0
        || limits.storage_bytes > 2 * 1024 * 1024 * 1024
        || limits.cpu_millis == 0
        || limits.wall_millis == 0
        || limits.wall_millis > 3_600_000
        || limits.processes == 0
        || limits.processes > 8_192
    {
        return Err("proof resource limits are outside module bounds".into());
    }
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.len() > 4_096
        || path.contains('\0')
        || path.contains('\\')
        || Path::new(path).is_absolute()
        || !Path::new(path).components().all(|component| matches!(component, Component::Normal(_)))
    {
        return Err("proof target path must be canonical and source-relative".into());
    }
    Ok(())
}

fn required_string(object: &serde_json::Map<String, Value>, name: &str) -> Result<String, String> {
    object
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("patched replay has no valid {name}"))
}

fn string_array(
    object: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<Vec<String>, String> {
    object
        .get(name)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("patched replay has no valid {name}"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .ok_or_else(|| format!("patched replay has an invalid {name} entry"))
        })
        .collect()
}

fn unified_diff(path: &str, original: &[u8], replacement: &[u8]) -> Result<Vec<u8>, String> {
    let original = std::str::from_utf8(original).map_err(|_| "patch preimage is not UTF-8")?;
    let replacement =
        std::str::from_utf8(replacement).map_err(|_| "patch replacement is not UTF-8")?;
    let old = original.lines().collect::<Vec<_>>();
    let new = replacement.lines().collect::<Vec<_>>();
    let mut diff = format!("--- a/{path}\n+++ b/{path}\n@@ -1,{} +1,{} @@\n", old.len(), new.len());
    for line in old {
        diff.push('-');
        diff.push_str(line);
        diff.push('\n');
    }
    for line in new {
        diff.push('+');
        diff.push_str(line);
        diff.push('\n');
    }
    Ok(diff.into_bytes())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
}

fn adapter_runtime(input: AdapterInvocation) -> Result<Value, String> {
    match input.operation.as_str() {
        "catalog" => encode(catalog()),
        "prepare" => prepare(serde_json::from_value(input.request).map_err(json_error)?),
        "complete" => complete(serde_json::from_value(input.request).map_err(json_error)?),
        "cancel" => cancel(serde_json::from_value(input.request).map_err(json_error)?),
        "status" => status(serde_json::from_value(input.request).map_err(json_error)?),
        "remove" => remove(serde_json::from_value(input.request).map_err(json_error)?),
        "execute" => {
            execute(serde_json::from_value(input.request.clone()).map_err(json_error)?, &input)
        }
        operation => Err(format!("unknown module-owned adapter operation `{operation}`")),
    }
}

fn catalog() -> ModuleAdapterCatalog {
    ModuleAdapterCatalog {
        schema: 1,
        descriptors: vec![
            descriptor(DIAGNOSTIC, "diagnostic.echo.v1", "peritus.diagnostic.decoder@1"),
            descriptor(
                crate::source_analysis::ADAPTER_ID,
                crate::source_analysis::OPERATION,
                "peritus.source-analysis.decoder@1",
            ),
            descriptor(
                crate::http_api::ADAPTER_ID,
                crate::http_api::OPERATION,
                "peritus.http-api.decoder@1",
            ),
            descriptor(
                crate::browser_client::ADAPTER_ID,
                crate::browser_client::OPERATION,
                "peritus.browser-client.decoder@1",
            ),
            descriptor(
                crate::identity_access::ADAPTER_ID,
                crate::identity_access::OPERATION,
                "peritus.identity-access.decoder@1",
            ),
            descriptor(
                crate::file_fuzz::ADAPTER_ID,
                crate::file_fuzz::OPERATION,
                "peritus.file-parser.decoder@1",
            ),
            descriptor(
                crate::workflow_state::ADAPTER_ID,
                crate::workflow_state::OPERATION,
                "peritus.workflow-state.decoder@1",
            ),
            descriptor(
                crate::boundary_authority::ADAPTER_ID,
                crate::boundary_authority::OPERATION,
                "peritus.boundary-authority.decoder@1",
            ),
            descriptor(
                crate::attack_graph::ADAPTER_ID,
                crate::attack_graph::OPERATION,
                "peritus.attack-graph.decoder@1",
            ),
            descriptor(
                crate::diamond_binding::ADAPTER_ID,
                crate::diamond_binding::OPERATION,
                "peritus.diamond-application.decoder@1",
            ),
        ],
    }
}

fn descriptor(adapter_id: &str, operation: &str, decoder: &str) -> ModuleAdapterDescriptor {
    let artifact = format!("peritus-red-team-module-worker\0{adapter_id}\0{operation}\0v1");
    ModuleAdapterDescriptor {
        schema: 1,
        adapter_id: adapter_id.into(),
        version: env!("CARGO_PKG_VERSION").into(),
        platform: platform(),
        artifact_digest: digest(artifact.as_bytes()),
        artifact_bytes: u64::try_from(artifact.len()).unwrap_or(u64::MAX),
        license: "MIT".into(),
        operations: vec![ModuleAdapterOperation {
            name: operation.into(),
            input_schema: format!("{operation}.request@1"),
            receipt_schema: format!("{operation}.observation@1"),
        }],
        receipt_decoder: decoder.into(),
    }
}

fn prepare(request: ModuleAdapterPrepareRequest) -> Result<Value, String> {
    require_schema(request.schema)?;
    let descriptor = registered(&request.descriptor.adapter_id)?;
    if request.descriptor != descriptor {
        return Err("adapter descriptor differs from the module-owned registry".into());
    }
    encode(ModuleAdapterPreparationHandle {
        schema: 1,
        preparation_id: preparation_id(&descriptor),
        descriptor_digest: descriptor_digest(&descriptor)?,
    })
}

fn complete(request: ModuleAdapterCompleteRequest) -> Result<Value, String> {
    require_schema(request.schema)?;
    let descriptor = catalog()
        .descriptors
        .into_iter()
        .find(|descriptor| preparation_id(descriptor) == request.preparation_id)
        .ok_or_else(|| "unknown module-owned adapter preparation".to_string())?;
    encode(installed_status(&descriptor, Some(request.preparation_id), false)?)
}

fn cancel(request: ModuleAdapterCancelRequest) -> Result<Value, String> {
    require_schema(request.schema)?;
    if request.reason.trim().is_empty() {
        return Err("adapter cancellation reason is empty".into());
    }
    let descriptor = catalog()
        .descriptors
        .into_iter()
        .find(|descriptor| preparation_id(descriptor) == request.preparation_id)
        .ok_or_else(|| "unknown module-owned adapter preparation".to_string())?;
    let mut result = installed_status(&descriptor, Some(request.preparation_id), false)?;
    result.phase = ModuleAdapterPhase::Cancelled;
    result.runtime = None;
    result.detail = "Module-owned preparation was cancelled before execution.".into();
    encode(result)
}

fn status(request: ModuleAdapterStatusRequest) -> Result<Value, String> {
    require_schema(request.schema)?;
    let descriptor = registered(&request.adapter_id)?;
    encode(installed_status(&descriptor, Some(preparation_id(&descriptor)), true)?)
}

fn remove(request: ModuleAdapterRemoveRequest) -> Result<Value, String> {
    require_schema(request.schema)?;
    let descriptor = registered(&request.runtime.adapter_id)?;
    let expected = runtime(&descriptor)?;
    if request.runtime != expected {
        return Err("adapter removal identity differs from the module-owned registry".into());
    }
    let mut result = installed_status(&descriptor, Some(preparation_id(&descriptor)), false)?;
    result.phase = ModuleAdapterPhase::Removed;
    result.detail =
        "Module-owned adapter activation was removed from retained coordinator state.".into();
    encode(result)
}

fn execute(
    request: ModuleAdapterExecuteRequest,
    input: &AdapterInvocation,
) -> Result<Value, String> {
    require_schema(request.schema)?;
    let descriptor = registered(&request.runtime.adapter_id)?;
    if request.runtime != runtime(&descriptor)? {
        return Err("adapter execution identity differs from the module-owned registry".into());
    }
    let registered_operation =
        descriptor.operations.iter().any(|operation| operation.name == request.operation);
    if !registered_operation {
        return Err("adapter operation is not in the module-owned registry".into());
    }
    let observation = match request.operation.as_str() {
        "diagnostic.echo.v1" => json!({
            "schema": 1,
            "message": request.input.get("message").and_then(Value::as_str).unwrap_or_default(),
            "implementation": "peritus-red-team/module-worker",
        }),
        crate::source_analysis::OPERATION => {
            let scan: ModuleSourceAnalysisRequest =
                serde_json::from_value(request.input.clone()).map_err(json_error)?;
            require_schema(scan.schema)?;
            serde_json::to_value(source_analysis_worker::scan_disposable_source(
                input.source_snapshot.clone(),
                &scan.limits,
            )?)
            .map_err(json_error)?
        }
        crate::http_api::OPERATION => {
            let campaign: peritus_plugin_sdk::ModuleHttpApiCampaignRequest =
                serde_json::from_value(request.input.clone()).map_err(json_error)?;
            let laboratory = crate::runtime_laboratory::Broker::new(
                input.source_snapshot.clone(),
                input.targets.clone(),
            );
            let laboratory_id = campaign.laboratory_id.clone();
            let endpoint_handle = campaign.endpoint_handle.clone();
            serde_json::to_value(crate::runtime_http_api::execute(
                campaign,
                input.source_snapshot.clone(),
                |wire| laboratory.http_exchange(&laboratory_id, &endpoint_handle, wire),
            )?)
            .map_err(json_error)?
        }
        crate::browser_client::OPERATION => {
            let campaign: peritus_plugin_sdk::ModuleBrowserCampaignRequest =
                serde_json::from_value(request.input.clone()).map_err(json_error)?;
            let laboratory = laboratory(input);
            serde_json::to_value(crate::runtime_browser_client::execute(
                campaign,
                &input.request_key,
                "peritus.red-team",
                env!("CARGO_PKG_VERSION"),
                &worker_state_root()?,
                &laboratory,
            )?)
            .map_err(json_error)?
        }
        crate::identity_access::OPERATION => {
            let campaign: peritus_plugin_sdk::ModuleIdentityAccessCampaignRequest =
                serde_json::from_value(request.input.clone()).map_err(json_error)?;
            let laboratory = laboratory(input);
            serde_json::to_value(crate::runtime_identity_access::execute(
                campaign,
                &input.request_key,
                "peritus.red-team",
                env!("CARGO_PKG_VERSION"),
                &worker_state_root()?,
                &laboratory,
            )?)
            .map_err(json_error)?
        }
        crate::file_fuzz::OPERATION => {
            let campaign: peritus_plugin_sdk::ModuleFileFuzzCampaignRequest =
                serde_json::from_value(request.input.clone()).map_err(json_error)?;
            let laboratory = laboratory(input);
            serde_json::to_value(crate::runtime_file_fuzz::execute(
                campaign,
                &input.request_key,
                "peritus.red-team",
                env!("CARGO_PKG_VERSION"),
                &worker_state_root()?,
                &laboratory,
            )?)
            .map_err(json_error)?
        }
        crate::workflow_state::OPERATION => {
            let campaign: peritus_plugin_sdk::ModuleWorkflowCampaignRequest =
                serde_json::from_value(request.input.clone()).map_err(json_error)?;
            let laboratory = laboratory(input);
            let session =
                laboratory.workflow_session(&campaign.laboratory_id, &campaign.endpoint_handle)?;
            let laboratory_id = campaign.laboratory_id.clone();
            let endpoint_handle = campaign.endpoint_handle.clone();
            serde_json::to_value(crate::runtime_workflow_state::execute(
                campaign,
                &session,
                |wire| laboratory.http_exchange(&laboratory_id, &endpoint_handle, wire),
            )?)
            .map_err(json_error)?
        }
        crate::boundary_authority::OPERATION => {
            let campaign: peritus_plugin_sdk::ModuleBoundaryCampaignRequest =
                serde_json::from_value(request.input.clone()).map_err(json_error)?;
            let laboratory = laboratory(input);
            serde_json::to_value(crate::runtime_boundary_authority::execute(
                &campaign,
                &input.request_key,
                "peritus.red-team",
                env!("CARGO_PKG_VERSION"),
                &worker_state_root()?,
                &laboratory,
            )?)
            .map_err(json_error)?
        }
        crate::attack_graph::OPERATION => {
            let campaign: peritus_plugin_sdk::ModuleAttackGraphCampaignRequest =
                serde_json::from_value(request.input.clone()).map_err(json_error)?;
            let laboratory = laboratory(input);
            serde_json::to_value(crate::runtime_attack_graph::execute(
                &campaign,
                &input.request_key,
                &worker_state_root()?,
                &laboratory,
            )?)
            .map_err(json_error)?
        }
        crate::diamond_binding::OPERATION => serde_json::to_value(crate::runtime_diamond::execute(
            request.input.clone(),
            input.source_snapshot.clone(),
            &input.request_key,
            &worker_state_root()?,
        )?)
        .map_err(json_error)?,
        operation => return Err(format!("unknown module-owned adapter operation `{operation}`")),
    };
    encode(ModuleAdapterExecutionReceipt {
        schema: 1,
        runtime_digest: request.runtime.runtime_digest,
        operation: request.operation.clone(),
        input_digest: digest(&serde_json::to_vec(&request.input).map_err(json_error)?),
        receipt_decoder: descriptor.receipt_decoder,
        observation,
        executed_by: format!(
            "peritus-red-team/{}@1",
            request
                .runtime
                .adapter_id
                .strip_prefix("peritus.")
                .unwrap_or(&request.runtime.adapter_id)
        ),
    })
}

fn laboratory(input: &AdapterInvocation) -> crate::runtime_laboratory::Broker {
    crate::runtime_laboratory::Broker::new(input.source_snapshot.clone(), input.targets.clone())
}

fn worker_state_root() -> Result<std::path::PathBuf, String> {
    let root = std::env::current_dir()
        .map_err(|error| error.to_string())?
        .join(".red-team-worker-private")
        .join("receipts");
    fs::create_dir_all(&root).map_err(|error| error.to_string())?;
    Ok(root)
}

fn registered(adapter_id: &str) -> Result<ModuleAdapterDescriptor, String> {
    catalog()
        .descriptors
        .into_iter()
        .find(|descriptor| descriptor.adapter_id == adapter_id)
        .ok_or_else(|| format!("unknown module-owned adapter `{adapter_id}`"))
}

fn installed_status(
    descriptor: &ModuleAdapterDescriptor,
    preparation_id: Option<String>,
    reused: bool,
) -> Result<ModuleAdapterStatus, String> {
    let descriptor_digest = descriptor_digest(descriptor)?;
    Ok(ModuleAdapterStatus {
        schema: 1,
        adapter_id: descriptor.adapter_id.clone(),
        preparation_id,
        phase: ModuleAdapterPhase::Installed,
        runtime: Some(runtime(descriptor)?),
        provenance: Some(ModuleAdapterProvenanceReceipt {
            schema: 1,
            descriptor_digest,
            artifact_digest: descriptor.artifact_digest.clone(),
            artifact_bytes: descriptor.artifact_bytes,
            source: "peritus-red-team/module-worker-registry".into(),
            license: descriptor.license.clone(),
        }),
        reused,
        detail: "Adapter implementation is compiled into this exact Red Team module package."
            .into(),
        retained_error: None,
    })
}

fn runtime(descriptor: &ModuleAdapterDescriptor) -> Result<ModuleAdapterRuntimeIdentity, String> {
    let descriptor_digest = descriptor_digest(descriptor)?;
    let runtime_digest = digest(
        format!(
            "red-team-runtime-v1\0{}\0{}\0{}",
            descriptor.adapter_id, descriptor.version, descriptor_digest
        )
        .as_bytes(),
    );
    Ok(ModuleAdapterRuntimeIdentity {
        schema: 1,
        adapter_id: descriptor.adapter_id.clone(),
        version: descriptor.version.clone(),
        descriptor_digest,
        artifact_digest: descriptor.artifact_digest.clone(),
        platform: descriptor.platform.clone(),
        runtime_digest,
    })
}

fn descriptor_digest(descriptor: &ModuleAdapterDescriptor) -> Result<String, String> {
    Ok(digest(&serde_json::to_vec(descriptor).map_err(json_error)?))
}

fn preparation_id(descriptor: &ModuleAdapterDescriptor) -> String {
    digest(
        format!(
            "red-team-preparation-v1\0{}\0{}",
            descriptor.adapter_id, descriptor.artifact_digest
        )
        .as_bytes(),
    )
}

fn platform() -> ModuleAdapterPlatform {
    ModuleAdapterPlatform {
        os: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
    }
}

fn require_schema(schema: u16) -> Result<(), String> {
    if schema == 1 { Ok(()) } else { Err("unsupported Red Team worker schema".into()) }
}

fn encode<T: serde::Serialize>(value: T) -> Result<Value, String> {
    serde_json::to_value(value).map_err(json_error)
}

fn json_error(error: serde_json::Error) -> String {
    error.to_string()
}
