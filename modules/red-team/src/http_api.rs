//! Phase-thirteen real HTTP, OpenAPI, GraphQL, WebSocket and JSON-RPC campaign coordinator.

use crate::{
    Error, adapter, digest, invalid,
    records::{EvidenceKind, EvidenceRecord, RECORD_SCHEMA_VERSION, RecordId, RecordKind},
    reply, state,
};
use peritus_plugin_sdk::{
    ModuleAction, ModuleAdapterExecuteRequest, ModuleAdapterExecutionReceipt, ModuleHostProfile,
    ModuleHttpApiCampaignRequest, ModuleHttpApiDisposition, ModuleHttpApiObservation,
    ModuleLaboratoryPhase,
};
use serde_json::Value;
use std::collections::BTreeSet;

pub(crate) const ADAPTER_ID: &str = "peritus.http-api";
pub(crate) const OPERATION: &str = "http.campaign.v1";
const RECEIPT_DECODER: &str = "peritus.http-api.decoder@1";
const PROFILE: &str = "peritus.http-api.standard@1";

pub(crate) fn handles(command: &str) -> bool {
    matches!(
        command,
        "api"
            | "api-install"
            | "api-run"
            | "api-history"
            | "api-status"
            | "api-remove"
            | "api-probe-wrong-endpoint"
            | "api-probe-small-budget"
    )
}

pub(crate) fn command(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
    command: &str,
) -> Result<ModuleAction, Error> {
    if !adapter::supports(profile) {
        return Ok(reply(
            "This Peritus host does not advertise `module.adapter-runtime@1`. HTTP/API testing remains blocked; no ambient endpoint or network fallback was attempted.",
            profile,
            super::actions(state),
            None,
        ));
    }
    match command {
        "api" => Ok(reply(view(state), profile, super::actions(state), None)),
        "api-install" => adapter::install(parameters, state, ADAPTER_ID),
        "api-status" => adapter::status_for(parameters, state, ADAPTER_ID),
        "api-remove" => adapter::remove_for(parameters, state, ADAPTER_ID),
        "api-history" => Ok(reply(history(state), profile, super::actions(state), None)),
        "api-run" | "api-probe-wrong-endpoint" | "api-probe-small-budget" => {
            let runtime = adapter::installed_runtime(state, ADAPTER_ID).ok_or_else(|| {
                invalid("install the registered HTTP/API adapter before running `api-run`")
            })?;
            let laboratory = state
                .laboratory_statuses
                .last()
                .filter(|status| status.phase == ModuleLaboratoryPhase::Ready)
                .ok_or_else(|| invalid("launch a ready HTTP/API laboratory before `api-run`"))?;
            if laboratory.handle.recipe_id != "linux.python-http-api.v1" {
                return Err(invalid(
                    "the current laboratory does not expose the registered HTTP/API interface",
                ));
            }
            let mut input = ModuleHttpApiCampaignRequest {
                schema: 1,
                laboratory_id: laboratory.handle.laboratory_id.clone(),
                endpoint_handle: laboratory.handle.endpoint_handle.clone(),
                profile: PROFILE.into(),
                maximum_requests: 64,
                maximum_request_bytes: 128 * 1024,
                maximum_response_bytes: 1024 * 1024,
            };
            if command == "api-probe-wrong-endpoint" {
                input.endpoint_handle = "0".repeat(64);
            } else if command == "api-probe-small-budget" {
                input.maximum_requests = 20;
            }
            adapter::execute(
                parameters,
                state,
                ModuleAdapterExecuteRequest {
                    schema: 1,
                    runtime,
                    operation: OPERATION.into(),
                    input: serde_json::to_value(input)?,
                },
            )
        }
        _ => Err(invalid("unknown HTTP/API command")),
    }
}

pub(crate) fn admit(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
    receipt: ModuleAdapterExecutionReceipt,
) -> Result<ModuleAction, Error> {
    if receipt.operation != OPERATION
        || receipt.receipt_decoder != RECEIPT_DECODER
        || receipt.executed_by != "peritus-host/http-api-v1"
    {
        return Err(invalid("HTTP/API receipt has an unregistered host identity"));
    }
    let observation: ModuleHttpApiObservation = serde_json::from_value(receipt.observation)?;
    validate_observation(state, &observation)?;
    let scope = state.scopes.last().ok_or_else(|| invalid("HTTP/API evidence has no scope"))?;
    let snapshot = state
        .active_snapshot()
        .ok_or_else(|| invalid("HTTP/API evidence has no source snapshot"))?;
    let evidence_id = RecordId::new(
        RecordKind::Evidence,
        format!("http-api-{}", &digest(observation.traffic_digest.as_bytes())[..24]),
    )
    .map_err(invalid)?;
    let evidence = EvidenceRecord {
        schema: RECORD_SCHEMA_VERSION,
        id: evidence_id.clone(),
        campaign: state.campaign.id.clone(),
        scope_revision: scope.id.clone(),
        kind: EvidenceKind::HttpApi,
        observation: format!(
            "Host HTTP/API adapter executed {} real exchanges and confirmed {} violations",
            observation.requests_executed,
            observation.findings.len()
        ),
        artifact_digest: observation.traffic_digest.clone(),
        dependencies: vec![snapshot.id.clone()],
    };
    if !state.api_evidence.iter().any(|existing| existing.id == evidence_id) {
        state.api_evidence.push(evidence);
    }
    if let Some(existing) = state
        .api_observations
        .iter_mut()
        .find(|existing| existing.traffic_digest == observation.traffic_digest)
    {
        *existing = observation.clone();
    } else {
        state.api_observations.push(observation.clone());
    }
    let advanced = crate::coverage::record_http_method(state, &evidence_id);
    state.pending = None;
    state::save(parameters, state)?;
    Ok(reply(render(&observation, &evidence_id, advanced), profile, super::actions(state), None))
}

fn validate_observation(
    state: &state::State,
    observation: &ModuleHttpApiObservation,
) -> Result<(), Error> {
    if observation.schema != 1
        || observation.adapter_version != "peritus-http-api-2026-10-24.1"
        || observation.suite_version != "peritus-http-api-suite-2026-10-24.1"
        || observation.traffic_digest.len() != 64
        || observation.requests_executed
            != u64::try_from(observation.cases.len()).unwrap_or(u64::MAX)
    {
        return Err(invalid("HTTP/API observation has an invalid schema or pinned identity"));
    }
    let laboratory = state
        .laboratory_statuses
        .iter()
        .rev()
        .find(|status| status.handle.laboratory_id == observation.laboratory_id)
        .ok_or_else(|| invalid("HTTP/API observation belongs to an unknown laboratory"))?;
    if laboratory.handle.source_snapshot != observation.source_snapshot {
        return Err(invalid("HTTP/API observation belongs to a different source snapshot"));
    }
    let mut case_ids = BTreeSet::new();
    for case in &observation.cases {
        if !case_ids.insert(case.id.as_str())
            || case.request.digest.len() != 64
            || case.response.digest.len() != 64
        {
            return Err(invalid(
                "HTTP/API cases are duplicated or have invalid receipt identities",
            ));
        }
    }
    let mut finding_ids = BTreeSet::new();
    for finding in &observation.findings {
        let Some(case) = observation.cases.iter().find(|case| case.id == finding.case_id) else {
            return Err(invalid("HTTP/API finding has no retained executed case"));
        };
        if finding.evidence_state != "runtime_confirmed"
            || case.disposition != ModuleHttpApiDisposition::Violation
            || finding.replay_request_digest != case.request.digest
            || !case.minimized
            || !finding_ids.insert(finding.id.as_str())
        {
            return Err(invalid(
                "HTTP/API finding is not uniquely bound to a minimized host-confirmed violation",
            ));
        }
    }
    Ok(())
}

fn render(observation: &ModuleHttpApiObservation, evidence: &RecordId, advanced: usize) -> String {
    let rejected = observation
        .cases
        .iter()
        .filter(|case| case.disposition == ModuleHttpApiDisposition::Rejected)
        .count();
    let unreachable = observation
        .cases
        .iter()
        .filter(|case| case.disposition == ModuleHttpApiDisposition::Unreachable)
        .count();
    let passed = observation
        .cases
        .iter()
        .filter(|case| case.disposition == ModuleHttpApiDisposition::Passed)
        .count();
    let mut text = format!(
        "# HTTP/API campaign\n\n- Evidence: `{}`\n- Laboratory: `{}`\n- Source snapshot: `{}`\n- Adapter: `{}`\n- Suite: `{}`\n- Imported OpenAPI: `{}`\n- Routes discovered: {}\n- Real exchanges: {}\n- Passed / rejected / unreachable / violations: {passed} / {rejected} / {unreachable} / {}\n- Request / response bytes: {} / {}\n- Coverage cells advanced: {advanced}\n- Traffic digest: `{}`\n- Final copied-state digest: `{}`\n\n",
        evidence.value,
        observation.laboratory_id,
        observation.source_snapshot,
        observation.adapter_version,
        observation.suite_version,
        observation.imported_schema_digest.as_deref().unwrap_or("not imported"),
        observation.routes.len(),
        observation.requests_executed,
        observation.findings.len(),
        observation.request_bytes,
        observation.response_bytes,
        observation.traffic_digest,
        observation.final_state_digest,
    );
    text.push_str("## Runtime-confirmed findings\n\n");
    if observation.findings.is_empty() {
        text.push_str("None in this pinned campaign. This is not a universal safety claim.\n");
    }
    for finding in &observation.findings {
        text.push_str(&format!(
            "- `{}` · `{:?}` · case `{}` · replay `{}` — {}\n",
            finding.category,
            finding.severity,
            finding.case_id,
            finding.replay_request_digest,
            finding.message,
        ));
    }
    text.push_str("\n## Case ledger\n\n");
    for case in &observation.cases {
        text.push_str(&format!(
            "- `{}` · `{:?}` · `{:?}` · `{} {}` → {} — {}\n",
            case.id,
            case.protocol,
            case.disposition,
            case.request.method,
            case.request.target,
            case.response.status,
            case.oracle,
        ));
    }
    text.push_str("\n## Explicit gaps\n\n");
    for gap in &observation.gaps {
        text.push_str(&format!("- {gap}\n"));
    }
    text
}

fn view(state: &state::State) -> String {
    format!(
        "# HTTP/API adapter family\n\n- Registered adapter: `{ADAPTER_ID}`\n- Operation: `{OPERATION}`\n- Installed: {}\n- Retained campaigns: {}\n\nThe initial pinned suite captures real HTTP/1.1 traffic, imports live OpenAPI routes and parameters, and exercises REST, GraphQL, WebSocket and JSON-RPC behavior. It checks injection, parsing, method, content-type, error, redirect, header and request-sequence dimensions against host-owned response and copied-state oracles. Only observed violations become runtime-confirmed findings.",
        adapter::installed_runtime(state, ADAPTER_ID).is_some(),
        state.api_observations.len(),
    )
}

fn history(state: &state::State) -> String {
    let mut text = "# HTTP/API campaign history\n\n".to_owned();
    if state.api_observations.is_empty() {
        text.push_str("No HTTP/API campaign receipt has been admitted.\n");
    }
    for observation in state.api_observations.iter().rev() {
        text.push_str(&format!(
            "- laboratory `{}` — {} exchanges, {} routes, {} violations, traffic `{}`\n",
            observation.laboratory_id,
            observation.requests_executed,
            observation.routes.len(),
            observation.findings.len(),
            observation.traffic_digest,
        ));
    }
    text
}
