//! Phase-eighteen private-network, TLS, local-policy, and delegated-authority coordinator.

use crate::{
    Error, adapter, digest, invalid,
    records::{EvidenceKind, EvidenceRecord, RECORD_SCHEMA_VERSION, RecordId, RecordKind},
    reply, state,
};
use peritus_plugin_sdk::{
    ModuleAction, ModuleAdapterExecuteRequest, ModuleAdapterExecutionReceipt,
    ModuleBoundaryCampaignRequest, ModuleBoundaryDisposition, ModuleBoundaryObservation,
    ModuleHostProfile, ModuleLaboratoryPhase,
};
use serde_json::Value;
use std::collections::BTreeSet;

pub(crate) const ADAPTER_ID: &str = "peritus.boundary-authority";
pub(crate) const OPERATION: &str = "boundary-authority.campaign.v1";
const RECEIPT_DECODER: &str = "peritus.boundary-authority.decoder@1";
const PROFILE: &str = "peritus.boundary-authority.standard@1";

pub(crate) fn handles(command: &str) -> bool {
    matches!(
        command,
        "boundary"
            | "boundary-install"
            | "boundary-run"
            | "boundary-history"
            | "boundary-status"
            | "boundary-remove"
            | "boundary-probe-wrong-endpoint"
            | "boundary-probe-small-budget"
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
            "This Peritus host does not advertise generic isolated module workers. Boundary testing remains blocked; no ambient network, TLS, cloud, privilege, or tool fallback was attempted.",
            profile,
            super::actions(state),
            None,
        ));
    }
    match command {
        "boundary" => Ok(reply(view(state), profile, super::actions(state), None)),
        "boundary-install" => adapter::install(parameters, state, ADAPTER_ID),
        "boundary-status" => adapter::status_for(parameters, state, ADAPTER_ID),
        "boundary-remove" => adapter::remove_for(parameters, state, ADAPTER_ID),
        "boundary-history" => Ok(reply(history(state), profile, super::actions(state), None)),
        "boundary-run" | "boundary-probe-wrong-endpoint" | "boundary-probe-small-budget" => {
            let runtime = adapter::installed_runtime(state, ADAPTER_ID).ok_or_else(|| {
                invalid("install the registered boundary adapter before `boundary-run`")
            })?;
            let laboratory = state
                .laboratory_statuses
                .last()
                .filter(|status| status.phase == ModuleLaboratoryPhase::Ready)
                .ok_or_else(|| invalid("launch a ready boundary laboratory first"))?;
            if !crate::laboratory::has_runtime_target(state, &laboratory.handle.laboratory_id) {
                return Err(invalid(
                    "the current laboratory does not expose the registered boundary interface",
                ));
            }
            let mut input = ModuleBoundaryCampaignRequest {
                schema: 1,
                laboratory_id: laboratory.handle.laboratory_id.clone(),
                endpoint_handle: laboratory.handle.endpoint_handle.clone(),
                profile: PROFILE.into(),
                maximum_operations: 32,
                maximum_response_bytes: 256 * 1024,
            };
            if command == "boundary-probe-wrong-endpoint" {
                input.endpoint_handle = "0".repeat(64);
            } else if command == "boundary-probe-small-budget" {
                input.maximum_operations = 4;
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
        _ => Err(invalid("unknown boundary-authority campaign command")),
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
        || receipt.executed_by != "peritus-red-team/boundary-authority@1"
    {
        return Err(invalid("boundary receipt has an unregistered module runtime identity"));
    }
    let observation: ModuleBoundaryObservation = serde_json::from_value(receipt.observation)?;
    validate_observation(state, &observation)?;
    let scope = state.scopes.last().ok_or_else(|| invalid("boundary evidence has no scope"))?;
    let snapshot = state
        .active_snapshot()
        .ok_or_else(|| invalid("boundary evidence has no source snapshot"))?;
    let evidence_id = RecordId::new(
        RecordKind::Evidence,
        format!("boundary-{}", &digest(observation.campaign_digest.as_bytes())[..24]),
    )
    .map_err(invalid)?;
    let evidence = EvidenceRecord {
        schema: RECORD_SCHEMA_VERSION,
        id: evidence_id.clone(),
        campaign: state.campaign.id.clone(),
        scope_revision: scope.id.clone(),
        kind: EvidenceKind::BoundaryAuthority,
        observation: format!(
            "Module-owned boundary adapter executed {} real target operations, retained {} cases including explicit platform blocks, and confirmed {} documented violations without public/LAN/host-loopback or host-privilege effects",
            observation.operations_executed,
            observation.cases.len(),
            observation.findings.len(),
        ),
        artifact_digest: observation.campaign_digest.clone(),
        dependencies: vec![snapshot.id.clone()],
    };
    if !state.boundary_evidence.iter().any(|existing| existing.id == evidence_id) {
        state.boundary_evidence.push(evidence);
    }
    if let Some(existing) = state
        .boundary_observations
        .iter_mut()
        .find(|existing| existing.campaign_digest == observation.campaign_digest)
    {
        *existing = observation.clone();
    } else {
        state.boundary_observations.push(observation.clone());
    }
    let advanced = crate::coverage::record_boundary_authority_method(state, &evidence_id);
    state.pending = None;
    crate::capability_projection::reconcile(state);
    state::save(parameters, state)?;
    Ok(reply(render(&observation, &evidence_id, advanced), profile, super::actions(state), None))
}

pub(crate) fn validate_observation(
    state: &state::State,
    observation: &ModuleBoundaryObservation,
) -> Result<(), Error> {
    if observation.schema != 1
        || observation.adapter_version != "peritus-boundary-authority-2026-10-24.5"
        || !matches!(
            observation.suite_version.as_str(),
            "peritus-boundary-authority-suite-2026-10-24.1"
                | "peritus-boundary-authority-diamond-2026-10-25.1"
        )
        || observation.campaign_digest.len() != 64
        || observation.final_state_digest.len() != 64
        || observation.operations_executed == 0
        || observation.network.peer_receipt_digest.len() != 64
        || observation.tls.certificate_set_digest.len() != 64
    {
        return Err(invalid("boundary observation has an invalid identity or aggregate record"));
    }
    let laboratory = state
        .laboratory_statuses
        .iter()
        .rev()
        .find(|status| status.handle.laboratory_id == observation.laboratory_id)
        .ok_or_else(|| invalid("boundary observation belongs to an unknown laboratory"))?;
    if laboratory.handle.source_snapshot != observation.source_snapshot {
        return Err(invalid("boundary observation belongs to a different source snapshot"));
    }
    if observation.network.host_loopback_effects != 0
        || observation.network.lan_effects != 0
        || observation.network.external_effects != 0
        || observation.policy.host_privilege_effects != 0
        || !observation.policy.containment_held
        || !observation.authority.host_authority_unchanged
    {
        return Err(invalid("boundary receipt claims an effect outside the contained laboratory"));
    }
    let mut cases = BTreeSet::new();
    for case in &observation.cases {
        if !cases.insert(case.id.as_str())
            || case.request_digest.len() != 64
            || case.state_before_digest.len() != 64
            || case.state_after_digest.len() != 64
            || case.replay_digest.len() != 64
            || case.oracle.is_empty()
        {
            return Err(invalid("boundary case identity or replay data is invalid"));
        }
    }
    let mut findings = BTreeSet::new();
    for finding in &observation.findings {
        let Some(case) = observation.cases.iter().find(|case| case.id == finding.case_id) else {
            return Err(invalid("boundary finding has no retained case"));
        };
        if finding.evidence_state != "runtime_confirmed"
            || case.disposition != ModuleBoundaryDisposition::Violation
            || finding.replay_digest != case.replay_digest
            || !findings.insert(finding.id.as_str())
        {
            return Err(invalid(
                "boundary finding is not uniquely bound to a host-observed violation",
            ));
        }
    }
    if !observation.cases.iter().any(|case| {
        case.id == "live-cloud-provider" && case.disposition == ModuleBoundaryDisposition::Blocked
    }) || !observation.cases.iter().any(|case| {
        case.id == "host-privileged-runtime"
            && case.disposition == ModuleBoundaryDisposition::Blocked
    }) {
        return Err(invalid("boundary observation omitted mandatory unavailable-platform records"));
    }
    Ok(())
}

fn render(observation: &ModuleBoundaryObservation, evidence: &RecordId, advanced: usize) -> String {
    let passed = count(observation, ModuleBoundaryDisposition::Passed);
    let violations = count(observation, ModuleBoundaryDisposition::Violation);
    let blocked = count(observation, ModuleBoundaryDisposition::Blocked);
    let harness = count(observation, ModuleBoundaryDisposition::HarnessFailure);
    let mut text = format!(
        "# Private-network, TLS, policy, and authority campaign\n\n- Evidence: `{}`\n- Laboratory: `{}`\n- Source snapshot: `{}`\n- Adapter / suite: `{}` / `{}`\n- Real operations / retained cases: {} / {}\n- Passed / violations / blocked / harness failures: {passed} / {violations} / {blocked} / {harness}\n- Findings: {}\n- Private DNS / callbacks / redirects / proxies: {} / {} / {} / {}\n- Forbidden blind-effect attempts: {}\n- Host-loopback / LAN / external effects: {} / {} / {}\n- TLS handshakes / connection reuse: {} / {}\n- Privilege attempts / host effects: {} / {}\n- Untrusted directives / privileged copied effects: {} / {}\n- Coverage cells advanced: {advanced}\n- Campaign digest: `{}`\n- Final copied-state digest: `{}`\n\n",
        evidence.value,
        observation.laboratory_id,
        observation.source_snapshot,
        observation.adapter_version,
        observation.suite_version,
        observation.operations_executed,
        observation.cases.len(),
        observation.findings.len(),
        observation.network.private_dns_queries,
        observation.network.private_callbacks,
        observation.network.redirect_hops,
        observation.network.proxy_requests,
        observation.network.forbidden_destination_attempts,
        observation.network.host_loopback_effects,
        observation.network.lan_effects,
        observation.network.external_effects,
        observation.tls.handshakes,
        format_args!("{:?}", observation.tls.connection_reuse),
        observation.policy.privilege_attempts,
        observation.policy.host_privilege_effects,
        observation.authority.untrusted_directives,
        observation.authority.privileged_effects,
        observation.campaign_digest,
        observation.final_state_digest,
    );
    text.push_str("## Runtime-confirmed documented violations\n\n");
    if observation.findings.is_empty() {
        text.push_str("None in this pinned campaign.\n");
    }
    for finding in &observation.findings {
        text.push_str(&format!(
            "- `{:?}` · case `{}` · replay `{}` — {}\n",
            finding.severity, finding.case_id, finding.replay_digest, finding.message
        ));
    }
    text.push_str("\n## Exact case ledger\n\n");
    for case in &observation.cases {
        text.push_str(&format!(
            "- `{}` · `{:?}` / `{:?}` · status `{}` · oracle `{}` · replay `{}` — {}\n",
            case.id,
            case.class,
            case.disposition,
            case.response_status.map_or_else(|| "none".into(), |value| value.to_string()),
            case.oracle,
            case.replay_digest,
            case.detail
        ));
    }
    text.push_str("\n## Explicit gaps\n\n");
    for gap in &observation.gaps {
        text.push_str(&format!("- {gap}\n"));
    }
    text
}

fn count(observation: &ModuleBoundaryObservation, disposition: ModuleBoundaryDisposition) -> usize {
    observation.cases.iter().filter(|case| case.disposition == disposition).count()
}

fn view(state: &state::State) -> String {
    format!(
        "# Boundary-authority adapter family\n\n- Registered adapter: `{ADAPTER_ID}`\n- Operation: `{OPERATION}`\n- Installed: {}\n- Retained campaigns: {}\n\nThe module owns private DNS/HTTP/TLS peers, callback receipts, forbidden-destination and certificate oracles, contained privilege attempts, and copied-application authority observations. Public/LAN/host-loopback routing, host privilege, and general model tools are never granted.",
        adapter::installed_runtime(state, ADAPTER_ID).is_some(),
        state.boundary_observations.len(),
    )
}

fn history(state: &state::State) -> String {
    let mut text = "# Boundary-authority campaign history\n\n".to_owned();
    if state.boundary_observations.is_empty() {
        text.push_str("No boundary-authority campaign receipt has been admitted.\n");
    }
    for observation in state.boundary_observations.iter().rev() {
        text.push_str(&format!("- laboratory `{}` — {} operations, {} cases, {} findings, {} forbidden callbacks, {} host-network effects, campaign `{}`\n", observation.laboratory_id, observation.operations_executed, observation.cases.len(), observation.findings.len(), observation.network.forbidden_destination_attempts, observation.network.host_loopback_effects + observation.network.lan_effects + observation.network.external_effects, observation.campaign_digest));
    }
    text
}
