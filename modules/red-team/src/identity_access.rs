//! Phase-fifteen authentication, session, authorization, and tenancy campaign coordinator.

use crate::{
    Error, adapter, digest, invalid,
    records::{EvidenceKind, EvidenceRecord, RECORD_SCHEMA_VERSION, RecordId, RecordKind},
    reply, state,
};
use peritus_plugin_sdk::{
    ModuleAction, ModuleAdapterExecuteRequest, ModuleAdapterExecutionReceipt, ModuleHostProfile,
    ModuleIdentityAccessCampaignRequest, ModuleIdentityAccessDisposition,
    ModuleIdentityAccessObservation, ModuleLaboratoryPhase,
};
use serde_json::Value;
use std::collections::BTreeSet;

pub(crate) const ADAPTER_ID: &str = "peritus.identity-access";
pub(crate) const OPERATION: &str = "identity.campaign.v1";
const RECEIPT_DECODER: &str = "peritus.identity-access.decoder@1";
const PROFILE: &str = "peritus.identity-access.standard@1";
const IDENTITY_PROFILE: &str = "peritus.identity-topology.multitenant@1";

pub(crate) fn handles(command: &str) -> bool {
    matches!(
        command,
        "identity"
            | "identity-install"
            | "identity-run"
            | "identity-history"
            | "identity-status"
            | "identity-remove"
            | "identity-probe-wrong-endpoint"
            | "identity-probe-small-budget"
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
            "This Peritus host does not advertise generic isolated module workers. Identity and access-control testing remains blocked; no ambient credentials, endpoint, or network fallback was attempted.",
            profile,
            super::actions(state),
            None,
        ));
    }
    match command {
        "identity" => Ok(reply(view(state), profile, super::actions(state), None)),
        "identity-install" => adapter::install(parameters, state, ADAPTER_ID),
        "identity-status" => adapter::status_for(parameters, state, ADAPTER_ID),
        "identity-remove" => adapter::remove_for(parameters, state, ADAPTER_ID),
        "identity-history" => Ok(reply(history(state), profile, super::actions(state), None)),
        "identity-run" | "identity-probe-wrong-endpoint" | "identity-probe-small-budget" => {
            let runtime = adapter::installed_runtime(state, ADAPTER_ID).ok_or_else(|| {
                invalid("install the registered identity adapter before running `identity-run`")
            })?;
            let laboratory = state
                .laboratory_statuses
                .last()
                .filter(|status| status.phase == ModuleLaboratoryPhase::Ready)
                .ok_or_else(|| {
                    invalid("launch a ready identity laboratory before `identity-run`")
                })?;
            if !crate::laboratory::has_runtime_target(state, &laboratory.handle.laboratory_id) {
                return Err(invalid(
                    "the current laboratory does not expose the registered identity interface",
                ));
            }
            let mut input = ModuleIdentityAccessCampaignRequest {
                schema: 1,
                laboratory_id: laboratory.handle.laboratory_id.clone(),
                endpoint_handle: laboratory.handle.endpoint_handle.clone(),
                profile: PROFILE.into(),
                identity_profile: IDENTITY_PROFILE.into(),
                maximum_operations: 64,
                maximum_response_bytes: 256 * 1024,
            };
            if command == "identity-probe-wrong-endpoint" {
                input.endpoint_handle = "0".repeat(64);
            } else if command == "identity-probe-small-budget" {
                input.maximum_operations = 8;
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
        _ => Err(invalid("unknown identity/access command")),
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
        || receipt.executed_by != "peritus-red-team/identity-access@1"
    {
        return Err(invalid("identity receipt has an unregistered module runtime identity"));
    }
    let observation: ModuleIdentityAccessObservation = serde_json::from_value(receipt.observation)?;
    validate_observation(state, &observation)?;
    let scope = state.scopes.last().ok_or_else(|| invalid("identity evidence has no scope"))?;
    let snapshot = state
        .active_snapshot()
        .ok_or_else(|| invalid("identity evidence has no source snapshot"))?;
    let evidence_id = RecordId::new(
        RecordKind::Evidence,
        format!("identity-{}", &digest(observation.traffic_digest.as_bytes())[..24]),
    )
    .map_err(invalid)?;
    let evidence = EvidenceRecord {
        schema: RECORD_SCHEMA_VERSION,
        id: evidence_id.clone(),
        campaign: state.campaign.id.clone(),
        scope_revision: scope.id.clone(),
        kind: EvidenceKind::IdentityAccess,
        observation: format!(
            "Module-owned identity adapter executed {} real operations and confirmed {} violations without projecting credential bytes",
            observation.operations_executed,
            observation.findings.len()
        ),
        artifact_digest: observation.traffic_digest.clone(),
        dependencies: vec![snapshot.id.clone()],
    };
    if !state.identity_evidence.iter().any(|existing| existing.id == evidence_id) {
        state.identity_evidence.push(evidence);
    }
    if let Some(existing) = state
        .identity_observations
        .iter_mut()
        .find(|existing| existing.traffic_digest == observation.traffic_digest)
    {
        *existing = observation.clone();
    } else {
        state.identity_observations.push(observation.clone());
    }
    let advanced = crate::coverage::record_identity_method(state, &evidence_id);
    state.pending = None;
    state::save(parameters, state)?;
    Ok(reply(render(&observation, &evidence_id, advanced), profile, super::actions(state), None))
}

fn validate_observation(
    state: &state::State,
    observation: &ModuleIdentityAccessObservation,
) -> Result<(), Error> {
    if observation.schema != 1
        || observation.adapter_version != "peritus-identity-access-2026-10-24.1"
        || !matches!(
            observation.suite_version.as_str(),
            "peritus-identity-access-suite-2026-10-24.1"
                | "peritus-identity-access-diamond-2026-10-25.1"
        )
        || observation.traffic_digest.len() != 64
        || observation.redaction.projection_digest.len() != 64
        || !observation.redaction.provider_projection_clean
        || observation.redaction.credential_values_checked == 0
    {
        return Err(invalid(
            "identity observation has an invalid schema, identity, or redaction record",
        ));
    }
    let laboratory = state
        .laboratory_statuses
        .iter()
        .rev()
        .find(|status| status.handle.laboratory_id == observation.laboratory_id)
        .ok_or_else(|| invalid("identity observation belongs to an unknown laboratory"))?;
    if laboratory.handle.source_snapshot != observation.source_snapshot {
        return Err(invalid("identity observation belongs to a different source snapshot"));
    }
    let identities = observation
        .identities
        .iter()
        .map(|identity| identity.identity_handle.as_str())
        .collect::<BTreeSet<_>>();
    if identities.len() != observation.identities.len()
        || observation.identities.iter().any(|identity| identity.identity_handle.len() != 64)
    {
        return Err(invalid("identity topology contains duplicate or invalid opaque handles"));
    }
    let mut cases = BTreeSet::new();
    for case in &observation.cases {
        if !cases.insert(case.id.as_str())
            || case.replay_digest.len() != 64
            || !identities.contains(case.actor_identity.as_str())
            || case.target_identity.as_deref().is_some_and(|target| !identities.contains(target))
        {
            return Err(invalid(
                "identity cases are duplicated or reference invalid opaque identities",
            ));
        }
    }
    for transition in &observation.session_transitions {
        if !cases.contains(transition.case_id.as_str())
            || !identities.contains(transition.identity_handle.as_str())
        {
            return Err(invalid("session graph is not bound to retained cases and identities"));
        }
    }
    let mut findings = BTreeSet::new();
    for finding in &observation.findings {
        let Some(case) = observation.cases.iter().find(|case| case.id == finding.case_id) else {
            return Err(invalid("identity finding has no retained executed case"));
        };
        if finding.evidence_state != "runtime_confirmed"
            || case.disposition != ModuleIdentityAccessDisposition::Violation
            || finding.replay_digest != case.replay_digest
            || !findings.insert(finding.id.as_str())
        {
            return Err(invalid(
                "identity finding is not uniquely bound to a host-confirmed violation",
            ));
        }
    }
    Ok(())
}

fn render(
    observation: &ModuleIdentityAccessObservation,
    evidence: &RecordId,
    advanced: usize,
) -> String {
    let passed = count(observation, ModuleIdentityAccessDisposition::Passed);
    let rejected = count(observation, ModuleIdentityAccessDisposition::Rejected);
    let indeterminate = count(observation, ModuleIdentityAccessDisposition::Indeterminate);
    let mut text = format!(
        "# Identity and access-control campaign\n\n- Evidence: `{}`\n- Laboratory: `{}`\n- Source snapshot: `{}`\n- Adapter: `{}`\n- Suite: `{}`\n- Opaque identities / session transitions: {} / {}\n- Real operations / retained cases: {} / {}\n- Passed / rejected / violations / indeterminate: {passed} / {rejected} / {} / {indeterminate}\n- Coverage cells advanced: {advanced}\n- Traffic digest: `{}`\n- Final copied-state digest: `{}`\n- Credential values checked: {}\n- Request / response credential fields withheld: {} / {}\n- Provider projection clean: {}\n- Projection digest: `{}`\n\n",
        evidence.value,
        observation.laboratory_id,
        observation.source_snapshot,
        observation.adapter_version,
        observation.suite_version,
        observation.identities.len(),
        observation.session_transitions.len(),
        observation.operations_executed,
        observation.cases.len(),
        observation.findings.len(),
        observation.traffic_digest,
        observation.final_state_digest,
        observation.redaction.credential_values_checked,
        observation.redaction.request_fields_redacted,
        observation.redaction.response_fields_redacted,
        observation.redaction.provider_projection_clean,
        observation.redaction.projection_digest,
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
            finding.replay_digest,
            finding.message,
        ));
    }
    text.push_str("\n## Differential case ledger\n\n");
    for case in &observation.cases {
        text.push_str(&format!(
            "- `{}` · `{:?}` · `{}` → {} — {}\n",
            case.id, case.disposition, case.operation, case.response_status, case.oracle,
        ));
    }
    text.push_str("\n## Explicit gaps\n\n");
    for gap in &observation.gaps {
        text.push_str(&format!("- {gap}\n"));
    }
    text
}

fn count(
    observation: &ModuleIdentityAccessObservation,
    disposition: ModuleIdentityAccessDisposition,
) -> usize {
    observation.cases.iter().filter(|case| case.disposition == disposition).count()
}

fn view(state: &state::State) -> String {
    format!(
        "# Identity and access-control adapter family\n\n- Registered adapter: `{ADAPTER_ID}`\n- Operation: `{OPERATION}`\n- Installed: {}\n- Retained campaigns: {}\n\nThe pinned laboratory topology creates anonymous, ordinary, privileged, same-tenant, and cross-tenant opaque identities. The module alone handles login credentials, MFA factors, recovery values, and session tokens while it exercises lifecycle, differential authorization, object ownership, adjacent-route, and tenant-isolation oracles.",
        adapter::installed_runtime(state, ADAPTER_ID).is_some(),
        state.identity_observations.len(),
    )
}

fn history(state: &state::State) -> String {
    let mut text = "# Identity and access-control campaign history\n\n".to_owned();
    if state.identity_observations.is_empty() {
        text.push_str("No identity/access campaign receipt has been admitted.\n");
    }
    for observation in state.identity_observations.iter().rev() {
        text.push_str(&format!(
            "- laboratory `{}` — {} operations, {} cases, {} violations, projection clean {}, traffic `{}`\n",
            observation.laboratory_id,
            observation.operations_executed,
            observation.cases.len(),
            observation.findings.len(),
            observation.redaction.provider_projection_clean,
            observation.traffic_digest,
        ));
    }
    text
}
