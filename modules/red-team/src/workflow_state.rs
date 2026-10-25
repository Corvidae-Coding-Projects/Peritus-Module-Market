//! Phase-seventeen state, concurrency, and business-workflow campaign coordinator.

use crate::{
    Error, adapter, digest, invalid,
    records::{EvidenceKind, EvidenceRecord, RECORD_SCHEMA_VERSION, RecordId, RecordKind},
    reply, state,
};
use peritus_plugin_sdk::{
    ModuleAction, ModuleAdapterExecuteRequest, ModuleAdapterExecutionReceipt, ModuleHostProfile,
    ModuleLaboratoryPhase, ModuleWorkflowCampaignRequest, ModuleWorkflowInvariantDisposition,
    ModuleWorkflowInvariantOrigin, ModuleWorkflowObservation, ModuleWorkflowSequenceDisposition,
};
use serde_json::Value;
use std::collections::BTreeSet;

pub(crate) const ADAPTER_ID: &str = "peritus.workflow-state";
pub(crate) const OPERATION: &str = "workflow-state.campaign.v1";
const RECEIPT_DECODER: &str = "peritus.workflow-state.decoder@1";
const PROFILE: &str = "peritus.workflow-state.standard@1";

pub(crate) fn handles(command: &str) -> bool {
    matches!(
        command,
        "workflow"
            | "workflow-install"
            | "workflow-run"
            | "workflow-history"
            | "workflow-status"
            | "workflow-remove"
            | "workflow-probe-wrong-endpoint"
            | "workflow-probe-small-budget"
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
            "This Peritus host does not advertise generic isolated module workers. Stateful workflow and concurrency testing remains blocked; no raw command fallback was attempted.",
            profile,
            super::actions(state),
            None,
        ));
    }
    match command {
        "workflow" => Ok(reply(view(state), profile, super::actions(state), None)),
        "workflow-install" => adapter::install(parameters, state, ADAPTER_ID),
        "workflow-status" => adapter::status_for(parameters, state, ADAPTER_ID),
        "workflow-remove" => adapter::remove_for(parameters, state, ADAPTER_ID),
        "workflow-history" => Ok(reply(history(state), profile, super::actions(state), None)),
        "workflow-run" | "workflow-probe-wrong-endpoint" | "workflow-probe-small-budget" => {
            let runtime = adapter::installed_runtime(state, ADAPTER_ID).ok_or_else(|| {
                invalid("install the registered workflow/state adapter before `workflow-run`")
            })?;
            let laboratory = state
                .laboratory_statuses
                .last()
                .filter(|status| status.phase == ModuleLaboratoryPhase::Ready)
                .ok_or_else(|| invalid("launch a ready workflow laboratory first"))?;
            if !crate::laboratory::has_runtime_target(state, &laboratory.handle.laboratory_id) {
                return Err(invalid(
                    "the current laboratory does not expose the registered workflow interface",
                ));
            }
            let mut input = ModuleWorkflowCampaignRequest {
                schema: 1,
                laboratory_id: laboratory.handle.laboratory_id.clone(),
                endpoint_handle: laboratory.handle.endpoint_handle.clone(),
                profile: PROFILE.into(),
                seed: 0x5048_3137,
                maximum_sequences: 16,
                maximum_actions: 96,
                maximum_response_bytes: 256 * 1024,
            };
            if command == "workflow-probe-wrong-endpoint" {
                input.endpoint_handle = "0".repeat(64);
            } else if command == "workflow-probe-small-budget" {
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
        _ => Err(invalid("unknown workflow/state campaign command")),
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
        || receipt.executed_by != "peritus-red-team/workflow-state@1"
    {
        return Err(invalid("workflow/state receipt has an unregistered module runtime identity"));
    }
    let observation: ModuleWorkflowObservation = serde_json::from_value(receipt.observation)?;
    validate_observation(state, &observation)?;
    let scope = state.scopes.last().ok_or_else(|| invalid("workflow evidence has no scope"))?;
    let snapshot = state
        .active_snapshot()
        .ok_or_else(|| invalid("workflow evidence has no source snapshot"))?;
    let evidence_id = RecordId::new(
        RecordKind::Evidence,
        format!("workflow-{}", &digest(observation.campaign_digest.as_bytes())[..24]),
    )
    .map_err(invalid)?;
    let evidence = EvidenceRecord {
        schema: RECORD_SCHEMA_VERSION,
        id: evidence_id.clone(),
        campaign: state.campaign.id.clone(),
        scope_revision: scope.id.clone(),
        kind: EvidenceKind::WorkflowState,
        observation: format!(
            "Module-owned workflow adapter executed {} real actions across {} retained sequences, evaluated {} provenance-labelled invariants, and confirmed {} documented violations",
            observation.actions_executed,
            observation.sequences.len(),
            observation.invariants.len(),
            observation.findings.len(),
        ),
        artifact_digest: observation.campaign_digest.clone(),
        dependencies: vec![snapshot.id.clone()],
    };
    if !state.workflow_evidence.iter().any(|existing| existing.id == evidence_id) {
        state.workflow_evidence.push(evidence);
    }
    if let Some(existing) = state
        .workflow_observations
        .iter_mut()
        .find(|existing| existing.campaign_digest == observation.campaign_digest)
    {
        *existing = observation.clone();
    } else {
        state.workflow_observations.push(observation.clone());
    }
    let advanced = crate::coverage::record_workflow_state_method(state, &evidence_id);
    state.pending = None;
    state::save(parameters, state)?;
    Ok(reply(render(&observation, &evidence_id, advanced), profile, super::actions(state), None))
}

fn validate_observation(
    state: &state::State,
    observation: &ModuleWorkflowObservation,
) -> Result<(), Error> {
    if observation.schema != 1
        || observation.adapter_version != "peritus-workflow-state-2026-10-24.1"
        || observation.suite_version != "peritus-workflow-state-suite-2026-10-24.1"
        || observation.campaign_digest.len() != 64
        || observation.final_state_digest.len() != 64
        || observation.actions_executed
            < u64::try_from(observation.sequences.len()).unwrap_or(u64::MAX)
    {
        return Err(invalid("workflow observation has an invalid identity or action record"));
    }
    let laboratory = state
        .laboratory_statuses
        .iter()
        .rev()
        .find(|status| status.handle.laboratory_id == observation.laboratory_id)
        .ok_or_else(|| invalid("workflow observation belongs to an unknown laboratory"))?;
    if laboratory.handle.source_snapshot != observation.source_snapshot {
        return Err(invalid("workflow observation belongs to a different source snapshot"));
    }
    let mut invariant_ids = BTreeSet::new();
    for invariant in &observation.invariants {
        if !invariant_ids.insert(invariant.id.as_str())
            || invariant.oracle.is_empty()
            || invariant.statement.is_empty()
            || (invariant.origin == ModuleWorkflowInvariantOrigin::ModelProposed
                && invariant.disposition == ModuleWorkflowInvariantDisposition::Violated)
        {
            return Err(invalid("workflow invariant provenance or status is invalid"));
        }
    }
    let mut sequence_ids = BTreeSet::new();
    for sequence in &observation.sequences {
        if !sequence_ids.insert(sequence.id.as_str())
            || sequence.starting_snapshot_digest.len() != 64
            || sequence.final_state_digest.len() != 64
            || sequence.replay_digest.len() != 64
            || sequence.invariant_ids.iter().any(|id| !invariant_ids.contains(id.as_str()))
        {
            return Err(invalid("workflow sequence identity or replay data is invalid"));
        }
        for (position, action) in sequence.actions.iter().enumerate() {
            if action.position != u32::try_from(position).unwrap_or(u32::MAX)
                || action.request_digest.len() != 64
                || action.state_before_digest.len() != 64
                || action.state_after_digest.len() != 64
                || action.id.is_empty()
                || action.actor.is_empty()
                || action.operation.is_empty()
            {
                return Err(invalid("workflow action order or state receipt is invalid"));
            }
        }
    }
    let documented = observation
        .invariants
        .iter()
        .filter(|invariant| invariant.origin == ModuleWorkflowInvariantOrigin::Documented)
        .map(|invariant| invariant.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut findings = BTreeSet::new();
    for finding in &observation.findings {
        let Some(sequence) =
            observation.sequences.iter().find(|sequence| sequence.id == finding.sequence_id)
        else {
            return Err(invalid("workflow finding has no retained sequence"));
        };
        if finding.evidence_state != "runtime_confirmed"
            || sequence.disposition != ModuleWorkflowSequenceDisposition::Violation
            || !documented.contains(finding.invariant_id.as_str())
            || !sequence.invariant_ids.contains(&finding.invariant_id)
            || finding.replay_digest != sequence.replay_digest
            || !findings.insert(finding.id.as_str())
        {
            return Err(invalid(
                "workflow finding is not uniquely bound to a documented host-observed violation",
            ));
        }
    }
    for schedule in &observation.nondeterminism.schedules {
        if schedule.id.is_empty()
            || schedule.steps.is_empty()
            || schedule.replay_count == 0
            || schedule.matching_replays > schedule.replay_count
            || schedule.schedule_digest.len() != 64
        {
            return Err(invalid("workflow schedule replay record is invalid"));
        }
    }
    Ok(())
}

fn render(observation: &ModuleWorkflowObservation, evidence: &RecordId, advanced: usize) -> String {
    let passed = count(observation, ModuleWorkflowSequenceDisposition::Passed);
    let violations = count(observation, ModuleWorkflowSequenceDisposition::Violation);
    let harness = count(observation, ModuleWorkflowSequenceDisposition::HarnessFailure);
    let documented = observation
        .invariants
        .iter()
        .filter(|invariant| invariant.origin == ModuleWorkflowInvariantOrigin::Documented)
        .count();
    let proposed = observation.invariants.len().saturating_sub(documented);
    let mut text = format!(
        "# Stateful workflow and concurrency campaign\n\n- Evidence: `{}`\n- Laboratory: `{}`\n- Source snapshot: `{}`\n- Adapter / suite: `{}` / `{}`\n- Seed: `{}`\n- Documented / proposed invariants: {documented} / {proposed}\n- Retained sequences / real actions: {} / {}\n- Passed / violations / excluded harness failures: {passed} / {violations} / {harness}\n- Findings: {}\n- Schedule replays / matching / divergent: {} / {} / {}\n- Coverage cells advanced: {advanced}\n- Campaign digest: `{}`\n- Final copied-state digest: `{}`\n\n",
        evidence.value,
        observation.laboratory_id,
        observation.source_snapshot,
        observation.adapter_version,
        observation.suite_version,
        observation.seed,
        observation.sequences.len(),
        observation.actions_executed,
        observation.findings.len(),
        observation.nondeterminism.replays,
        observation
            .nondeterminism
            .schedules
            .iter()
            .map(|schedule| u64::from(schedule.matching_replays))
            .sum::<u64>(),
        observation.nondeterminism.divergent_replays,
        observation.campaign_digest,
        observation.final_state_digest,
    );
    text.push_str("## Invariants\n\n");
    for invariant in &observation.invariants {
        text.push_str(&format!(
            "- `{}` · `{:?}` · `{:?}` · oracle `{}` · sequences {} — {}\n",
            invariant.id,
            invariant.origin,
            invariant.disposition,
            invariant.oracle,
            invariant.sequence_ids.join(", "),
            invariant.statement,
        ));
    }
    text.push_str("\n## Runtime-confirmed documented violations\n\n");
    if observation.findings.is_empty() {
        text.push_str(
            "None in this pinned campaign. Proposed invariants cannot create findings.\n",
        );
    }
    for finding in &observation.findings {
        text.push_str(&format!(
            "- `{:?}` · invariant `{}` · sequence `{}` · replay `{}` — {}\n",
            finding.severity,
            finding.invariant_id,
            finding.sequence_id,
            finding.replay_digest,
            finding.message,
        ));
    }
    text.push_str("\n## Exact sequence ledger\n\n");
    for sequence in &observation.sequences {
        text.push_str(&format!(
            "- `{}` · `{:?}` · `{}` · identities `{}` · actions {} · start `{}` · final `{}` · schedule `{}` · replay `{}` — {}\n",
            sequence.id,
            sequence.disposition,
            sequence.category,
            sequence.identities.join(","),
            sequence.actions.len(),
            sequence.starting_snapshot_digest,
            sequence.final_state_digest,
            sequence.schedule_id.as_deref().unwrap_or("none"),
            sequence.replay_digest,
            sequence.oracle,
        ));
    }
    text.push_str("\n## Nondeterminism and explicit gaps\n\n");
    for note in &observation.nondeterminism.notes {
        text.push_str(&format!("- {note}\n"));
    }
    for gap in &observation.gaps {
        text.push_str(&format!("- {gap}\n"));
    }
    text
}

fn count(
    observation: &ModuleWorkflowObservation,
    disposition: ModuleWorkflowSequenceDisposition,
) -> usize {
    observation.sequences.iter().filter(|sequence| sequence.disposition == disposition).count()
}

fn view(state: &state::State) -> String {
    format!(
        "# Stateful workflow and concurrency adapter family\n\n- Registered adapter: `{ADAPTER_ID}`\n- Operation: `{OPERATION}`\n- Installed: {}\n- Retained campaigns: {}\n\nThe module owns documented and proposed invariant provenance, real action order, copied-state reads, duplicate/retry/cancellation/crash-recovery cases, quota/accounting oracles, a deterministic two-worker schedule, and nondeterminism receipts. Proposed invariants and unrelated controller failures cannot create findings.",
        adapter::installed_runtime(state, ADAPTER_ID).is_some(),
        state.workflow_observations.len(),
    )
}

fn history(state: &state::State) -> String {
    let mut text = "# Workflow/state campaign history\n\n".to_owned();
    if state.workflow_observations.is_empty() {
        text.push_str("No workflow/state campaign receipt has been admitted.\n");
    }
    for observation in state.workflow_observations.iter().rev() {
        text.push_str(&format!(
            "- laboratory `{}` — {} actions, {} sequences, {} invariants, {} findings, {} schedule replays, {} divergent, campaign `{}`\n",
            observation.laboratory_id,
            observation.actions_executed,
            observation.sequences.len(),
            observation.invariants.len(),
            observation.findings.len(),
            observation.nondeterminism.replays,
            observation.nondeterminism.divergent_replays,
            observation.campaign_digest,
        ));
    }
    text
}
