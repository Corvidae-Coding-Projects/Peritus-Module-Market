//! Phase-fourteen real-browser client-security campaign coordinator.

use crate::{
    Error, adapter, digest, invalid,
    records::{EvidenceKind, EvidenceRecord, RECORD_SCHEMA_VERSION, RecordId, RecordKind},
    reply, state,
};
use peritus_plugin_sdk::{
    ModuleAction, ModuleAdapterExecuteRequest, ModuleAdapterExecutionReceipt,
    ModuleBrowserCampaignRequest, ModuleBrowserDisposition, ModuleBrowserObservation,
    ModuleHostProfile, ModuleLaboratoryPhase,
};
use serde_json::Value;
use std::collections::BTreeSet;

pub(crate) const ADAPTER_ID: &str = "peritus.browser-client";
pub(crate) const OPERATION: &str = "browser.campaign.v1";
const RECEIPT_DECODER: &str = "peritus.browser-client.decoder@1";
const PROFILE: &str = "peritus.browser-client.standard@1";

pub(crate) fn handles(command: &str) -> bool {
    matches!(
        command,
        "browser"
            | "browser-install"
            | "browser-run"
            | "browser-history"
            | "browser-status"
            | "browser-remove"
            | "browser-probe-wrong-endpoint"
            | "browser-probe-small-budget"
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
            "This Peritus host does not advertise generic isolated module workers. Real-browser testing remains blocked; no ambient browser, endpoint, or network fallback was attempted.",
            profile,
            super::actions(state),
            None,
        ));
    }
    match command {
        "browser" => Ok(reply(view(state), profile, super::actions(state), None)),
        "browser-install" => adapter::install(parameters, state, ADAPTER_ID),
        "browser-status" => adapter::status_for(parameters, state, ADAPTER_ID),
        "browser-remove" => adapter::remove_for(parameters, state, ADAPTER_ID),
        "browser-history" => Ok(reply(history(state), profile, super::actions(state), None)),
        "browser-run" | "browser-probe-wrong-endpoint" | "browser-probe-small-budget" => {
            let runtime = adapter::installed_runtime(state, ADAPTER_ID).ok_or_else(|| {
                invalid("install the registered browser adapter before running `browser-run`")
            })?;
            let laboratory = state
                .laboratory_statuses
                .last()
                .filter(|status| status.phase == ModuleLaboratoryPhase::Ready)
                .ok_or_else(|| invalid("launch a ready browser laboratory before `browser-run`"))?;
            if !crate::laboratory::has_runtime_target(state, &laboratory.handle.laboratory_id) {
                return Err(invalid(
                    "the current laboratory does not expose the registered browser interface",
                ));
            }
            let mut input = ModuleBrowserCampaignRequest {
                schema: 1,
                laboratory_id: laboratory.handle.laboratory_id.clone(),
                endpoint_handle: laboratory.handle.endpoint_handle.clone(),
                profile: PROFILE.into(),
                maximum_actions: 64,
                maximum_requests: 128,
                maximum_artifact_bytes: 16 * 1024 * 1024,
            };
            if command == "browser-probe-wrong-endpoint" {
                input.endpoint_handle = "0".repeat(64);
            } else if command == "browser-probe-small-budget" {
                input.maximum_actions = 8;
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
        _ => Err(invalid("unknown browser command")),
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
        || receipt.executed_by != "peritus-red-team/browser-client@1"
    {
        return Err(invalid("browser receipt has an unregistered module runtime identity"));
    }
    let observation: ModuleBrowserObservation = serde_json::from_value(receipt.observation)?;
    validate_observation(state, &observation)?;
    let scope = state.scopes.last().ok_or_else(|| invalid("browser evidence has no scope"))?;
    let snapshot = state
        .active_snapshot()
        .ok_or_else(|| invalid("browser evidence has no source snapshot"))?;
    let evidence_id = RecordId::new(
        RecordKind::Evidence,
        format!("browser-{}", &digest(observation.traffic_digest.as_bytes())[..24]),
    )
    .map_err(invalid)?;
    let evidence = EvidenceRecord {
        schema: RECORD_SCHEMA_VERSION,
        id: evidence_id.clone(),
        campaign: state.campaign.id.clone(),
        scope_revision: scope.id.clone(),
        kind: EvidenceKind::BrowserClient,
        observation: format!(
            "Module-owned browser adapter executed {} real actions and confirmed {} violations",
            observation.actions_executed,
            observation.findings.len()
        ),
        artifact_digest: observation.traffic_digest.clone(),
        dependencies: vec![snapshot.id.clone()],
    };
    if !state.browser_evidence.iter().any(|existing| existing.id == evidence_id) {
        state.browser_evidence.push(evidence);
    }
    if let Some(existing) = state
        .browser_observations
        .iter_mut()
        .find(|existing| existing.traffic_digest == observation.traffic_digest)
    {
        *existing = observation.clone();
    } else {
        state.browser_observations.push(observation.clone());
    }
    let advanced = crate::coverage::record_browser_method(state, &evidence_id);
    state.pending = None;
    crate::capability_projection::reconcile(state);
    state::save(parameters, state)?;
    Ok(reply(render(&observation, &evidence_id, advanced), profile, super::actions(state), None))
}

pub(crate) fn validate_observation(
    state: &state::State,
    observation: &ModuleBrowserObservation,
) -> Result<(), Error> {
    if observation.schema != 1
        || observation.adapter_version != "peritus-browser-client-2026-10-24.1"
        || !matches!(
            observation.suite_version.as_str(),
            "peritus-browser-client-suite-2026-10-24.1"
                | "peritus-browser-client-diamond-2026-10-25.1"
        )
        || observation.traffic_digest.len() != 64
        || !observation.context_isolation_observed
        || observation.off_scope_requests_blocked == 0
    {
        return Err(invalid(
            "browser observation has an invalid schema, identity, or isolation receipt",
        ));
    }
    let laboratory = state
        .laboratory_statuses
        .iter()
        .rev()
        .find(|status| status.handle.laboratory_id == observation.laboratory_id)
        .ok_or_else(|| invalid("browser observation belongs to an unknown laboratory"))?;
    if laboratory.handle.source_snapshot != observation.source_snapshot {
        return Err(invalid("browser observation belongs to a different source snapshot"));
    }
    let mut case_ids = BTreeSet::new();
    for case in &observation.cases {
        if !case_ids.insert(case.id.as_str()) || case.replay_digest.len() != 64 {
            return Err(invalid("browser cases are duplicated or have invalid replay identities"));
        }
    }
    for finding in &observation.findings {
        let Some(case) = observation.cases.iter().find(|case| case.id == finding.case_id) else {
            return Err(invalid("browser finding has no retained executed case"));
        };
        if finding.evidence_state != "runtime_confirmed"
            || case.disposition != ModuleBrowserDisposition::Violation
            || finding.replay_digest != case.replay_digest
        {
            return Err(invalid("browser finding is not bound to a host-confirmed violation"));
        }
    }
    Ok(())
}

fn render(observation: &ModuleBrowserObservation, evidence: &RecordId, advanced: usize) -> String {
    let mut text = format!(
        "# Real-browser client campaign\n\n- Evidence: `{}`\n- Laboratory: `{}`\n- Source snapshot: `{}`\n- Browser: `{}`\n- Adapter / suite: `{}` / `{}`\n- Actions / requests: {} / {}\n- Runtime-confirmed violations: {}\n- Coverage nodes: {}\n- Retained artifacts: {}\n- Fresh-context isolation: {}\n- Off-scope requests blocked: {}\n- Coverage cells advanced: {}\n- Traffic digest: `{}`\n- Final copied-state digest: `{}`\n\n## Runtime-confirmed findings\n\n",
        evidence.value,
        observation.laboratory_id,
        observation.source_snapshot,
        observation.browser_identity,
        observation.adapter_version,
        observation.suite_version,
        observation.actions_executed,
        observation.requests_observed,
        observation.findings.len(),
        observation.coverage.len(),
        observation.artifacts.len(),
        observation.context_isolation_observed,
        observation.off_scope_requests_blocked,
        advanced,
        observation.traffic_digest,
        observation.final_state_digest,
    );
    if observation.findings.is_empty() {
        text.push_str(
            "None in this pinned campaign. This is not a universal browser-safety claim.\n",
        );
    }
    for finding in &observation.findings {
        text.push_str(&format!(
            "- `{:?}` · `{}` · case `{}` · replay `{}` — {}\n",
            finding.severity,
            finding.category,
            finding.case_id,
            finding.replay_digest,
            finding.message
        ));
    }
    text.push_str("\n## Executed cases\n\n");
    for case in &observation.cases {
        text.push_str(&format!(
            "- `{}` · `{:?}` · `{}` — {}; {}\n",
            case.id, case.disposition, case.replay_digest, case.browser_effect, case.server_effect
        ));
    }
    text.push_str("\n## Explicit gaps\n\n");
    for gap in &observation.gaps {
        text.push_str(&format!("- {gap}\n"));
    }
    text
}

fn view(state: &state::State) -> String {
    state.browser_observations.last().map_or_else(
        || "# Real-browser client testing\n\nNo browser campaign receipt has been admitted. Install the adapter, launch a vulnerable or safe HTTP laboratory, then use `browser-run`.".into(),
        |observation| render(observation, state.browser_evidence.last().map(|item| &item.id).unwrap_or(&state.campaign.id), 0),
    )
}

fn history(state: &state::State) -> String {
    let mut text = format!(
        "# Browser campaign history\n\n{} retained observations.\n",
        state.browser_observations.len()
    );
    for observation in &state.browser_observations {
        text.push_str(&format!(
            "- `{}` — {} actions, {} requests, {} findings, traffic `{}`\n",
            observation.laboratory_id,
            observation.actions_executed,
            observation.requests_observed,
            observation.findings.len(),
            observation.traffic_digest,
        ));
    }
    text
}
