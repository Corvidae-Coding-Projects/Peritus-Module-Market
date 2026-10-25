//! Phase-nineteen cross-adapter attack graph, counterfactual, and repair replay.

use crate::{
    Error, adapter, digest, invalid,
    records::{EvidenceKind, EvidenceRecord, RECORD_SCHEMA_VERSION, RecordId, RecordKind},
    reply, state,
};
use peritus_plugin_sdk::{
    ModuleAction, ModuleAdapterExecuteRequest, ModuleAdapterExecutionReceipt,
    ModuleAttackGraphCampaignRequest, ModuleAttackGraphDisposition, ModuleAttackGraphObservation,
    ModuleHostProfile, ModuleLaboratoryPhase,
};
use serde_json::Value;
use std::collections::BTreeSet;

pub(crate) const ADAPTER_ID: &str = "peritus.attack-graph";
pub(crate) const OPERATION: &str = "attack-graph.campaign.v1";
const RECEIPT_DECODER: &str = "peritus.attack-graph.decoder@1";
const PROFILE: &str = "peritus.attack-graph.standard@1";

pub(crate) fn handles(command: &str) -> bool {
    matches!(
        command,
        "graph"
            | "graph-install"
            | "graph-run"
            | "graph-history"
            | "graph-status"
            | "graph-remove"
            | "graph-probe-single-lab"
            | "graph-probe-small-budget"
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
            "This Peritus host does not advertise generic isolated module workers. Cross-adapter graph search remains blocked; no model-invented edge or ambient execution fallback was attempted.",
            profile,
            super::actions(state),
            None,
        ));
    }
    match command {
        "graph" => Ok(reply(view(state), profile, super::actions(state), None)),
        "graph-install" => adapter::install(parameters, state, ADAPTER_ID),
        "graph-status" => adapter::status_for(parameters, state, ADAPTER_ID),
        "graph-remove" => adapter::remove_for(parameters, state, ADAPTER_ID),
        "graph-history" => Ok(reply(history(state), profile, super::actions(state), None)),
        "graph-run" | "graph-probe-single-lab" | "graph-probe-small-budget" => {
            let runtime = adapter::installed_runtime(state, ADAPTER_ID).ok_or_else(|| {
                invalid("install the registered attack-graph adapter before `graph-run`")
            })?;
            let (vulnerable, repaired) = ready_twins(state)?;
            let source = state
                .active_handle()
                .ok_or_else(|| invalid("select source before running an attack graph"))?;
            let mut input = ModuleAttackGraphCampaignRequest {
                schema: 1,
                source,
                vulnerable_laboratory_id: vulnerable.handle.laboratory_id.clone(),
                vulnerable_endpoint_handle: vulnerable.handle.endpoint_handle.clone(),
                repaired_laboratory_id: repaired.handle.laboratory_id.clone(),
                repaired_endpoint_handle: repaired.handle.endpoint_handle.clone(),
                profile: PROFILE.into(),
                maximum_browser_actions: 12,
                maximum_requests: 24,
                maximum_artifact_bytes: 4 * 1024 * 1024,
            };
            if command == "graph-probe-single-lab" {
                input.repaired_laboratory_id = input.vulnerable_laboratory_id.clone();
                input.repaired_endpoint_handle = input.vulnerable_endpoint_handle.clone();
            } else if command == "graph-probe-small-budget" {
                input.maximum_browser_actions = 2;
                input.maximum_requests = 4;
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
        _ => Err(invalid("unknown attack-graph command")),
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
        || receipt.executed_by != "peritus-red-team/attack-graph@1"
    {
        return Err(invalid("attack-graph receipt has an unregistered module runtime identity"));
    }
    let observation: ModuleAttackGraphObservation = serde_json::from_value(receipt.observation)?;
    validate_observation(state, &observation)?;
    let scope = state.scopes.last().ok_or_else(|| invalid("attack-graph evidence has no scope"))?;
    let snapshot = state
        .active_snapshot()
        .ok_or_else(|| invalid("attack-graph evidence has no source snapshot"))?;
    let evidence_id = RecordId::new(
        RecordKind::Evidence,
        format!("attack-graph-{}", &digest(observation.campaign_digest.as_bytes())[..24]),
    )
    .map_err(invalid)?;
    let evidence = EvidenceRecord {
        schema: RECORD_SCHEMA_VERSION,
        id: evidence_id.clone(),
        campaign: state.campaign.id.clone(),
        scope_revision: scope.id.clone(),
        kind: EvidenceKind::AttackGraph,
        observation: if observation
            .chains
            .iter()
            .any(|chain| chain.disposition == ModuleAttackGraphDisposition::Confirmed)
        {
            format!(
                "Module-owned attack-graph adapter retained {} nodes, {} edges, {} searched chains, a counterfactual, and {} accepted repair replays across exact source, private HTTP, and a real isolated browser",
                observation.nodes.len(),
                observation.edges.len(),
                observation.chains.len(),
                observation.repair.replays.len(),
            )
        } else {
            format!(
                "Module-owned attack-graph adapter retained {} nodes, {} edges, and {} searched chains; no fully supported impact chain was confirmed, so no repair was fabricated",
                observation.nodes.len(),
                observation.edges.len(),
                observation.chains.len(),
            )
        },
        artifact_digest: observation.campaign_digest.clone(),
        dependencies: vec![snapshot.id.clone()],
    };
    if !state.attack_graph_evidence.iter().any(|existing| existing.id == evidence_id) {
        state.attack_graph_evidence.push(evidence);
    }
    if let Some(existing) = state
        .attack_graph_observations
        .iter_mut()
        .find(|existing| existing.campaign_digest == observation.campaign_digest)
    {
        *existing = observation.clone();
    } else {
        state.attack_graph_observations.push(observation.clone());
    }
    let advanced = crate::coverage::record_attack_graph_method(state, &evidence_id);
    state.pending = None;
    state::save(parameters, state)?;
    Ok(reply(render(&observation, &evidence_id, advanced), profile, super::actions(state), None))
}

fn ready_twins(
    state: &state::State,
) -> Result<
    (&peritus_plugin_sdk::ModuleLaboratoryStatus, &peritus_plugin_sdk::ModuleLaboratoryStatus),
    Error,
> {
    let mut seen = BTreeSet::new();
    let ready = state
        .laboratory_statuses
        .iter()
        .rev()
        .filter(|status| seen.insert(status.handle.laboratory_id.as_str()))
        .filter(|status| status.phase == ModuleLaboratoryPhase::Ready)
        .take(2)
        .collect::<Vec<_>>();
    if ready.len() != 2 {
        return Err(invalid(
            "launch distinct vulnerable and repaired HTTP laboratories before `graph-run`",
        ));
    }
    let repaired = ready[0];
    let vulnerable = ready[1];
    if vulnerable.handle.source_snapshot != repaired.handle.source_snapshot
        || !crate::laboratory::has_runtime_target(state, &vulnerable.handle.laboratory_id)
        || !crate::laboratory::has_runtime_target(state, &repaired.handle.laboratory_id)
    {
        return Err(invalid(
            "attack-graph laboratories must be ready HTTP twins from one source snapshot",
        ));
    }
    Ok((vulnerable, repaired))
}

fn validate_observation(
    state: &state::State,
    observation: &ModuleAttackGraphObservation,
) -> Result<(), Error> {
    if observation.schema != 1
        || observation.adapter_version != "peritus-attack-graph-2026-10-24.1"
        || !matches!(
            observation.suite_version.as_str(),
            "peritus-attack-graph-suite-2026-10-24.1" | "peritus-attack-graph-diamond-2026-10-25.1"
        )
        || observation.campaign_digest.len() != 64
        || observation.operations_executed == 0
    {
        return Err(invalid("attack-graph observation has an invalid identity or aggregate"));
    }
    let snapshot = state
        .active_snapshot()
        .ok_or_else(|| invalid("attack-graph observation has no active source snapshot"))?;
    if snapshot.snapshot_digest != observation.source_snapshot {
        return Err(invalid("attack-graph observation belongs to another source snapshot"));
    }
    for id in [&observation.vulnerable_laboratory_id, &observation.repaired_laboratory_id] {
        let latest = state
            .laboratory_statuses
            .iter()
            .rev()
            .find(|status| &status.handle.laboratory_id == id)
            .ok_or_else(|| invalid("attack-graph observation names an unknown laboratory"))?;
        if latest.phase != ModuleLaboratoryPhase::Ready
            || latest.handle.source_snapshot != observation.source_snapshot
        {
            return Err(invalid("attack-graph observation names a non-ready or stale laboratory"));
        }
    }
    let nodes = observation.nodes.iter().map(|node| node.id.as_str()).collect::<BTreeSet<_>>();
    let edges = observation.edges.iter().map(|edge| edge.id.as_str()).collect::<BTreeSet<_>>();
    if nodes.len() != observation.nodes.len() || edges.len() != observation.edges.len() {
        return Err(invalid("attack-graph node or edge identities are duplicated"));
    }
    if observation.nodes.iter().any(|node| node.evidence_digest.len() != 64)
        || observation.edges.iter().any(|edge| {
            edge.evidence_digest.len() != 64
                || !nodes.contains(edge.from.as_str())
                || !nodes.contains(edge.to.as_str())
        })
    {
        return Err(invalid("attack-graph node or edge evidence is malformed"));
    }
    for chain in &observation.chains {
        if chain.replay_digest.len() != 64
            || chain.nodes.iter().any(|node| !nodes.contains(node.as_str()))
            || chain.edges.iter().any(|edge| !edges.contains(edge.as_str()))
        {
            return Err(invalid("attack-graph chain references unknown or malformed evidence"));
        }
        let unsupported = chain
            .edges
            .iter()
            .any(|id| observation.edges.iter().any(|edge| edge.id == *id && !edge.supported));
        if (chain.disposition == ModuleAttackGraphDisposition::Confirmed && unsupported)
            || (chain.disposition == ModuleAttackGraphDisposition::Broken
                && chain.removed_prerequisite.is_none())
            || (chain.disposition == ModuleAttackGraphDisposition::Rejected && !unsupported)
        {
            return Err(invalid("attack-graph chain disposition contradicts its evidence"));
        }
    }
    let confirmed = observation
        .chains
        .iter()
        .find(|chain| chain.disposition == ModuleAttackGraphDisposition::Confirmed);
    if confirmed
        .is_some_and(|chain| chain.adapter_families.iter().collect::<BTreeSet<_>>().len() < 3)
        || !observation
            .chains
            .iter()
            .any(|chain| chain.disposition == ModuleAttackGraphDisposition::Broken)
        || !observation
            .chains
            .iter()
            .any(|chain| chain.disposition == ModuleAttackGraphDisposition::Rejected)
    {
        return Err(invalid(
            "attack graph omitted its three-family confirmed-chain proof, counterfactual, or rejection record",
        ));
    }
    if confirmed.is_some()
        && observation.vulnerable_laboratory_id == observation.repaired_laboratory_id
    {
        return Err(invalid("confirmed attack graph reused one laboratory as both twins"));
    }
    let supported_evidence = observation
        .nodes
        .iter()
        .map(|node| node.evidence_digest.as_str())
        .chain(
            observation
                .edges
                .iter()
                .filter(|edge| edge.supported)
                .map(|edge| edge.evidence_digest.as_str()),
        )
        .chain(
            observation
                .chains
                .iter()
                .filter(|chain| chain.disposition != ModuleAttackGraphDisposition::Rejected)
                .map(|chain| chain.replay_digest.as_str()),
        )
        .collect::<BTreeSet<_>>();
    if !observation.skeptic.accepted
        || observation
            .skeptic
            .inspected_evidence
            .iter()
            .any(|digest| digest.len() != 64 || !supported_evidence.contains(digest.as_str()))
        || observation
            .skeptic
            .rejected_edges
            .iter()
            .any(|id| !observation.edges.iter().any(|edge| edge.id == *id && !edge.supported))
    {
        return Err(invalid("attack-graph skeptic did not independently bind its decision"));
    }
    let repair = &observation.repair;
    if confirmed.is_none() {
        if !repair.target_path.is_empty()
            || !repair.diff_bytes.is_empty()
            || !repair.addressed_chains.is_empty()
            || !repair.replays.is_empty()
            || repair.review_accepted
        {
            return Err(invalid("attack graph without a confirmed chain fabricated a repair"));
        }
        return Ok(());
    }
    let replay_adapters =
        repair.replays.iter().map(|replay| replay.adapter_id.as_str()).collect::<BTreeSet<_>>();
    if repair.target_path.is_empty()
        || repair.original_digest.len() != 64
        || repair.patched_digest.len() != 64
        || repair.diff_artifact.len() != 64
        || repair.diff_bytes.is_empty()
        || !repair.review_accepted
        || !repair.legitimate_behavior_preserved
        || repair.replays.iter().any(|replay| !replay.passed || replay.evidence_digest.len() != 64)
        || !["peritus.source-analysis", "peritus.http-api", "peritus.browser-client"]
            .iter()
            .all(|adapter| replay_adapters.contains(adapter))
    {
        return Err(invalid(
            "attack-graph repair lacks an accepted exact diff or required replays",
        ));
    }
    Ok(())
}

fn render(
    observation: &ModuleAttackGraphObservation,
    evidence: &RecordId,
    advanced: usize,
) -> String {
    let mut text = format!(
        "# Cross-adapter attack graph\n\n- Evidence: `{}`\n- Source snapshot: `{}`\n- Vulnerable / repaired laboratories: `{}` / `{}`\n- Nodes / edges / chains: {} / {} / {}\n- Real operations: {}\n- Skeptic accepted: {}\n- Repair reviewer accepted: {}\n- Legitimate behavior preserved: {}\n- Adapter replays passed: {}/{}\n- Coverage cells advanced: {}\n- Campaign digest: `{}`\n- Exact diff artifact: `{}`\n\n## Searched chains\n\n",
        evidence.value,
        observation.source_snapshot,
        observation.vulnerable_laboratory_id,
        observation.repaired_laboratory_id,
        observation.nodes.len(),
        observation.edges.len(),
        observation.chains.len(),
        observation.operations_executed,
        observation.skeptic.accepted,
        observation.repair.review_accepted,
        observation.repair.legitimate_behavior_preserved,
        observation.repair.replays.iter().filter(|replay| replay.passed).count(),
        observation.repair.replays.len(),
        advanced,
        observation.campaign_digest,
        observation.repair.diff_artifact,
    );
    for chain in &observation.chains {
        text.push_str(&format!(
            "- `{}` · `{:?}` · {} families · replay `{}` — {}\n",
            chain.id,
            chain.disposition,
            chain.adapter_families.len(),
            chain.replay_digest,
            chain.detail,
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
        "# Cross-adapter attack graph\n\n- Registered adapter: `{ADAPTER_ID}`\n- Operation: `{OPERATION}`\n- Installed: {}\n- Retained campaigns: {}\n\nThe module searches only receipt-supported edges across exact source, private HTTP, and isolated-browser evidence. It retains counterfactual and rejected paths and groups root causes without erasing distinct entry points or impacts. It hands back an exact copy-only patch plus adapter-specific replays only when a supported impact chain is confirmed; otherwise it records the bounded negative result without fabricating a repair.",
        adapter::installed_runtime(state, ADAPTER_ID).is_some(),
        state.attack_graph_observations.len(),
    )
}

fn history(state: &state::State) -> String {
    let mut text = "# Attack-graph campaign history\n\n".to_owned();
    if state.attack_graph_observations.is_empty() {
        text.push_str("No attack-graph campaign receipt has been admitted.\n");
    }
    for observation in state.attack_graph_observations.iter().rev() {
        text.push_str(&format!(
            "- campaign `{}` — {} nodes, {} edges, {} chains, skeptic {}, repair review {}, {} replay(s) passed\n",
            observation.campaign_digest,
            observation.nodes.len(),
            observation.edges.len(),
            observation.chains.len(),
            observation.skeptic.accepted,
            observation.repair.review_accepted,
            observation.repair.replays.iter().filter(|replay| replay.passed).count(),
        ));
    }
    text
}
