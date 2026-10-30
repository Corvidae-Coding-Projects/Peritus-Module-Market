//! Stage 6 confirmed-chain root-cause repair, regression, review, and source verification.

use crate::{Error, adapter, digest, invalid, reply, state, state::PendingRequest};
use peritus_plugin_sdk::{
    HOST_CAPABILITY_SCOPED_SOURCE, MODULE_RESEARCH_CONTRACT_VERSION, ModuleAction,
    ModuleAdapterExecuteRequest, ModuleAdapterExecutionReceipt, ModuleHostProfile,
    ModuleHostRequest, ModuleResearchArtifactClassification, ModuleResearchArtifactIdentity,
    ModuleResearchChainDisposition, ModuleResearchIdentity, ModuleResearchIdentityKind,
    ModuleResearchPocState, ModuleResearchRegressionCategory, ModuleResearchRepairBundle,
    ModuleResearchRepairObservation, ModuleResearchRepairRequest, ModuleResearchRepairState,
    ScopedSourceVerification, ScopedSourceVerifyRequest,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
};

const RECEIPT_DECODER: &str = "peritus.attack-graph.decoder@1";
const EXECUTED_BY: &str = "peritus-red-team/attack-graph@1";

pub(crate) fn handles(command: &str) -> bool {
    matches!(command, "repair" | "repair-plan" | "repair-history" | "repair-cancel")
        || command == "repair-start"
        || command.starts_with("repair-start ")
}

pub(crate) fn command(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
    command: &str,
) -> Result<ModuleAction, Error> {
    match command {
        "repair" | "repair-plan" => Ok(reply(plan(state), profile, super::actions(state), None)),
        "repair-history" => Ok(reply(history(state), profile, super::actions(state), None)),
        "repair-cancel" => cancel(parameters, profile, state),
        _ => {
            let bundle = command.strip_prefix("repair-start").unwrap_or_default().trim();
            start(parameters, profile, state, (!bundle.is_empty()).then_some(bundle))
        }
    }
}

fn start(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
    selected_bundle: Option<&str>,
) -> Result<ModuleAction, Error> {
    if !adapter::supports(profile) {
        return Ok(reply(
            "This Peritus host does not advertise generic isolated module workers. Stage 6 remains blocked; no ambient patch, browser, network, or process fallback was attempted.",
            profile,
            super::actions(state),
            None,
        ));
    }
    if state.pending.is_some() {
        return Err(invalid("settle or cancel the retained host request before starting Stage 6"));
    }
    let runtime =
        adapter::installed_runtime(state, crate::attack_graph::ADAPTER_ID).ok_or_else(|| {
            invalid("install the registered attack-graph adapter before `repair-start`")
        })?;
    let poc = if let Some(id) = selected_bundle {
        state
            .research_poc_bundles
            .iter()
            .find(|bundle| bundle.id == id && bundle.state == ModuleResearchPocState::Verified)
            .ok_or_else(|| invalid("repair-start names no verified Stage 5 PoC bundle"))?
    } else {
        state
            .research_poc_bundles
            .iter()
            .rev()
            .find(|bundle| bundle.state == ModuleResearchPocState::Verified)
            .ok_or_else(|| invalid("Stage 6 requires one verified Stage 5 PoC bundle"))?
    };
    if state.research_repair_bundles.iter().any(|repair| {
        repair.poc_bundle_id == poc.id
            && matches!(
                repair.state,
                ModuleResearchRepairState::Planned
                    | ModuleResearchRepairState::Replayed
                    | ModuleResearchRepairState::Verified
            )
    }) {
        return Err(invalid(
            "this PoC already has an active or verified repair bundle; inspect `repair-history`",
        ));
    }
    let graph = state
        .research_graphs
        .iter()
        .rev()
        .find(|graph| {
            graph.chains.iter().any(|chain| {
                chain.id == poc.chain_id
                    && chain.disposition == ModuleResearchChainDisposition::Confirmed
                    && chain.replay.is_some()
            })
        })
        .ok_or_else(|| invalid("Stage 6 PoC has no immutable confirmed graph-v2 chain"))?;
    let (vulnerable, _safe) = crate::chain_confirmation::ready_twins(state)?;
    let source_snapshot = state
        .active_snapshot()
        .ok_or_else(|| invalid("Stage 6 has no immutable source snapshot"))?
        .snapshot_digest
        .clone();
    let source = state
        .active_handle()
        .ok_or_else(|| invalid("Stage 6 has no active scoped-source authority"))?;
    if vulnerable.handle.source_snapshot != source_snapshot || poc.replay.is_none() {
        return Err(invalid(
            "Stage 6 PoC or vulnerable laboratory differs from the active source snapshot",
        ));
    }
    let repair_bundle_id = format!(
        "repair-{}",
        digest(
            format!(
                "stage6-repair-bundle-v2\0{}\0{}\0{}\0{}\0{}",
                graph.id,
                poc.chain_id,
                poc.id,
                source_snapshot,
                state.research_repair_bundles.len(),
            )
            .as_bytes(),
        )
    );
    let request = ModuleResearchRepairRequest {
        schema: MODULE_RESEARCH_CONTRACT_VERSION,
        graph_id: graph.id.clone(),
        chain_id: poc.chain_id.clone(),
        poc_bundle_id: poc.id.clone(),
        repair_bundle_id: repair_bundle_id.clone(),
        source_snapshot: source_snapshot.clone(),
        source,
        vulnerable_laboratory_id: vulnerable.handle.laboratory_id.clone(),
        vulnerable_endpoint_handle: vulnerable.handle.endpoint_handle.clone(),
        profile: crate::runtime_chain_repair::PROFILE.into(),
        destination: crate::runtime_chain_confirmation::DESTINATION.into(),
        synthetic_identity: crate::runtime_chain_confirmation::SYNTHETIC_IDENTITY.into(),
        maximum_browser_actions: 30,
        maximum_requests: 60,
        maximum_mutations: 8,
        maximum_artifact_bytes: 8 * 1024 * 1024,
    };
    state.research_repair_bundles.push(ModuleResearchRepairBundle {
        schema: MODULE_RESEARCH_CONTRACT_VERSION,
        id: repair_bundle_id.clone(),
        chain_id: poc.chain_id.clone(),
        poc_bundle_id: poc.id.clone(),
        source_snapshot,
        state: ModuleResearchRepairState::Planned,
        patch: None,
        artifacts: Vec::new(),
        replay: None,
        review: None,
        original_verification: None,
        limitations: vec![
            "Exact-preimage copy-only repair, patched-twin replay, mutation, independent review, and original-workspace verification are pending.".into(),
        ],
    });
    adapter::execute_chain_repair(
        parameters,
        state,
        &repair_bundle_id,
        ModuleAdapterExecuteRequest {
            schema: 1,
            runtime,
            operation: crate::runtime_chain_repair::OPERATION.into(),
            input: serde_json::to_value(request)?,
        },
    )
}

pub(crate) fn admit(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
    request: &ModuleAdapterExecuteRequest,
    receipt: ModuleAdapterExecutionReceipt,
) -> Result<ModuleAction, Error> {
    let result = admit_inner(parameters, state, request, receipt);
    match result {
        Ok(repair_id) => request_original_verification(parameters, state, &repair_id),
        Err(error) => {
            block_request(state, request, &format!("receipt admission failed closed: {error}"));
            state.pending = None;
            state::save(parameters, state)?;
            Ok(reply(
                format!(
                    "Stage 6 repair evidence was rejected and no repair was accepted.\n\n{error}"
                ),
                profile,
                super::actions(state),
                None,
            ))
        }
    }
}

fn admit_inner(
    parameters: &Value,
    state: &mut state::State,
    request: &ModuleAdapterExecuteRequest,
    receipt: ModuleAdapterExecutionReceipt,
) -> Result<String, Error> {
    if request.operation != crate::runtime_chain_repair::OPERATION
        || receipt.operation != request.operation
        || receipt.receipt_decoder != RECEIPT_DECODER
        || receipt.executed_by != EXECUTED_BY
        || receipt.input_digest != digest(&serde_json::to_vec(&request.input)?)
    {
        return Err(invalid("Stage 6 receipt has an unregistered or mismatched runtime identity"));
    }
    let input: ModuleResearchRepairRequest = serde_json::from_value(request.input.clone())?;
    let observation: ModuleResearchRepairObservation =
        serde_json::from_value(receipt.observation.clone())?;
    validate_observation(state, &input, &observation)?;
    let index = state
        .research_repair_bundles
        .iter()
        .position(|bundle| {
            bundle.id == input.repair_bundle_id
                && bundle.state == ModuleResearchRepairState::Planned
                && bundle.poc_bundle_id == input.poc_bundle_id
        })
        .ok_or_else(|| invalid("Stage 6 receipt does not match one planned repair bundle"))?;
    let artifacts = write_bundle(parameters, &input, &observation)?;
    let replay = crate::chain_confirmation::identity(
        ModuleResearchIdentityKind::Receipt,
        &format!(
            "{}:{}:{}",
            crate::runtime_chain_repair::OPERATION,
            receipt.input_digest,
            observation.verification_digest,
        ),
    );
    state.adapter_receipts.push(receipt);
    for artifact in &artifacts {
        if !state
            .research_artifacts
            .iter()
            .any(|retained| retained.relative_private_path == artifact.relative_private_path)
        {
            state.research_artifacts.push(artifact.clone());
        }
    }
    let bundle = &mut state.research_repair_bundles[index];
    bundle.state = ModuleResearchRepairState::Replayed;
    bundle.patch = Some(observation.patch.clone());
    bundle.artifacts = artifacts;
    bundle.replay = Some(replay);
    bundle.review = Some(observation.review.clone());
    bundle.limitations = observation.limitations.clone();
    state.pending = None;
    state::save(parameters, state)?;
    Ok(input.repair_bundle_id)
}

fn validate_observation(
    state: &state::State,
    input: &ModuleResearchRepairRequest,
    observation: &ModuleResearchRepairObservation,
) -> Result<(), Error> {
    let active_source = state
        .active_handle()
        .ok_or_else(|| invalid("Stage 6 observation has no active scoped-source authority"))?;
    if observation.schema != MODULE_RESEARCH_CONTRACT_VERSION
        || observation.graph_id != input.graph_id
        || observation.chain_id != input.chain_id
        || observation.poc_bundle_id != input.poc_bundle_id
        || observation.repair_bundle_id != input.repair_bundle_id
        || observation.source_snapshot != input.source_snapshot
        || observation.profile != crate::runtime_chain_repair::PROFILE
        || observation.patched_laboratory_id.len() != 64
        || observation.regression_script_digest
            != digest(crate::runtime_browser::REPAIR_REGRESSION.as_bytes())
        || observation.limitations.is_empty()
        || !observation.cleanup_complete
        || !observation.original_source_unchanged
        || input.source != active_source
    {
        return Err(invalid("Stage 6 observation identity, policy, or cleanup proof is invalid"));
    }
    if !state.research_poc_bundles.iter().any(|bundle| {
        bundle.id == input.poc_bundle_id
            && bundle.chain_id == input.chain_id
            && bundle.state == ModuleResearchPocState::Verified
            && bundle.replay.is_some()
    }) {
        return Err(invalid("Stage 6 observation is not bound to a verified Stage 5 PoC"));
    }
    crate::attack_graph::validate_ephemeral_repair_observation(
        state,
        &observation.full_replay,
        &observation.patched_laboratory_id,
    )?;
    if observation.full_replay.vulnerable_laboratory_id != input.vulnerable_laboratory_id
        || observation.full_replay.repaired_laboratory_id != observation.patched_laboratory_id
        || !observation.full_replay.repair.review_accepted
        || !observation.full_replay.repair.legitimate_behavior_preserved
        || observation.full_replay.repair.target_path != observation.patch.target_path
        || observation.full_replay.repair.original_digest != observation.patch.original_digest
        || observation.full_replay.repair.patched_digest != observation.patch.patched_digest
        || observation.full_replay.repair.diff_bytes != observation.diff_bytes
        || observation.patch.diff_digest != digest(&observation.diff_bytes)
        || observation.patch.root_cause_group != crate::runtime_chain_repair::ROOT_CAUSE_GROUP
        || observation.patch.earliest_prerequisite
            != crate::runtime_chain_repair::EARLIEST_PREREQUISITE
        || !diff_only_changes_root_flag(&observation.diff_bytes)
    {
        return Err(invalid("Stage 6 patch is not the exact earliest root-cause preimage change"));
    }
    let poc = &observation.patched_poc;
    if poc.schema != MODULE_RESEARCH_CONTRACT_VERSION
        || poc.expected_signal
        || poc.observed_signal
        || poc.browser_identity.is_empty()
        || poc.traffic_digest.len() != 64
        || poc.result_digest.len() != 64
        || poc.requests_observed == 0
        || poc.actions_executed == 0
        || !poc.cleanup_complete
        || !poc.original_source_unchanged
        || poc.target.service_digest != observation.patch.patched_digest
    {
        return Err(invalid("Stage 6 minimized PoC was not blocked by the patched twin"));
    }
    validate_matrix(input, observation)?;
    let review = &observation.review;
    let strategies = review
        .rejected_strategies
        .iter()
        .map(|item| item.strategy.as_str())
        .collect::<BTreeSet<_>>();
    let required_strategies = BTreeSet::from([
        "disable-stored-content-feature",
        "suppress-signal-or-error",
        "replace-target-with-safe-fixture",
        "patch-later-symptom-only",
    ]);
    if review.reviewer != crate::runtime_chain_repair::REVIEWER
        || !review.accepted
        || !review.exact_preimage
        || !review.root_cause_repaired
        || !review.legitimate_behavior_preserved
        || !review.oracle_preserved
        || !review.target_preserved
        || !review.complete_matrix
        || !required_strategies.is_subset(&strategies)
        || review.rejected_strategies.iter().any(|item| !item.rejected || item.reason.is_empty())
    {
        return Err(invalid("independent Stage 6 patch review is incomplete or rejected"));
    }
    let expected_verification = digest(&serde_json::to_vec(&json!({
        "schema": 2,
        "repair": input.repair_bundle_id,
        "patch": observation.patch,
        "full_replay": observation.full_replay.campaign_digest,
        "poc": observation.patched_poc.result_digest,
        "regression": observation.regression.result_digest,
        "matrix": observation.matrix,
        "review": observation.review,
        "cleanup": observation.cleanup_complete,
        "source_unchanged": observation.original_source_unchanged,
    }))?);
    if observation.verification_digest != expected_verification
        || serde_json::to_vec(observation)?.len()
            > usize::try_from(input.maximum_artifact_bytes).unwrap_or(usize::MAX)
    {
        return Err(invalid("Stage 6 verification digest or artifact bound is invalid"));
    }
    Ok(())
}

fn validate_matrix(
    input: &ModuleResearchRepairRequest,
    observation: &ModuleResearchRepairObservation,
) -> Result<(), Error> {
    let categories = observation.matrix.iter().map(|case| case.category).collect::<BTreeSet<_>>();
    let required_categories = BTreeSet::from([
        ModuleResearchRegressionCategory::MinimizedPoc,
        ModuleResearchRegressionCategory::FullChain,
        ModuleResearchRegressionCategory::Counterfactual,
        ModuleResearchRegressionCategory::SupportingAdapter,
        ModuleResearchRegressionCategory::Legitimate,
        ModuleResearchRegressionCategory::Malformed,
        ModuleResearchRegressionCategory::Adjacent,
        ModuleResearchRegressionCategory::Mutation,
        ModuleResearchRegressionCategory::SafetyControl,
    ]);
    let dimensions =
        observation.matrix.iter().map(|case| case.dimension.as_str()).collect::<BTreeSet<_>>();
    let required_dimensions = BTreeSet::from([
        "encoding",
        "ordering",
        "transport",
        "identity",
        "state",
        "timing",
        "alternate_entry",
        "equivalent_adapter_path",
    ]);
    let mutation_count = observation
        .matrix
        .iter()
        .filter(|case| case.category == ModuleResearchRegressionCategory::Mutation)
        .count();
    if !required_categories.is_subset(&categories)
        || !required_dimensions.is_subset(&dimensions)
        || mutation_count > input.maximum_mutations as usize
        || observation.matrix.iter().any(|case| {
            case.id.is_empty()
                || case.dimension.is_empty()
                || case.expected.is_empty()
                || case.observed.is_empty()
                || !case.passed
                || case.evidence_digest.len() != 64
        })
        || observation.regression.schema != MODULE_RESEARCH_CONTRACT_VERSION
        || observation.regression.browser_identity.is_empty()
        || observation.regression.cases.is_empty()
        || observation.regression.cases.iter().any(|case| !case.passed)
        || observation.regression.actions_executed > u64::from(input.maximum_browser_actions)
        || observation.regression.requests_observed
            > u64::from(input.maximum_requests.saturating_mul(2))
        || !observation.regression.browser_cleanup_complete
        || observation.regression.traffic_digest.len() != 64
        || observation.regression.result_digest.len() != 64
    {
        return Err(invalid("Stage 6 replay and bounded mutation matrix is incomplete"));
    }
    Ok(())
}

fn diff_only_changes_root_flag(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let removed = text
        .lines()
        .filter(|line| line.starts_with('-') && !line.starts_with("---"))
        .map(|line| &line[1..])
        .collect::<Vec<_>>();
    let added = text
        .lines()
        .filter(|line| line.starts_with('+') && !line.starts_with("+++"))
        .map(|line| &line[1..])
        .collect::<Vec<_>>();
    if removed.len() != added.len() {
        return false;
    }
    let changes =
        removed.iter().zip(&added).filter(|(before, after)| before != after).collect::<Vec<_>>();
    changes.len() == 1
        && *changes[0].0 == "VULNERABLE = True"
        && *changes[0].1 == "VULNERABLE = False"
}

fn request_original_verification(
    parameters: &Value,
    state: &mut state::State,
    repair_id: &str,
) -> Result<ModuleAction, Error> {
    let authority = state
        .active_handle()
        .ok_or_else(|| invalid("source authority is unavailable for Stage 6 byte verification"))?;
    let request = ScopedSourceVerifyRequest { schema: 1, authority };
    let suffix = repair_id.strip_prefix("repair-").unwrap_or(repair_id);
    let key = format!("red-team-chain-repair-verify-{}", &suffix[..suffix.len().min(32)]);
    state.pending =
        Some(PendingRequest::SourceVerify { key: key.clone(), request: request.clone() });
    state::save(parameters, state)?;
    Ok(ModuleAction::HostService {
        request: ModuleHostRequest {
            key,
            capability: HOST_CAPABILITY_SCOPED_SOURCE.into(),
            version: 1,
            operation: "verify".into(),
            input: serde_json::to_value(request)?,
        },
    })
}

pub(crate) fn original_verified(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
    result: ScopedSourceVerification,
) -> Result<ModuleAction, Error> {
    let expected = state
        .active_snapshot()
        .ok_or_else(|| invalid("Stage 6 source verification has no active snapshot"))?
        .snapshot_digest
        .clone();
    let index = state
        .research_repair_bundles
        .iter()
        .rposition(|bundle| {
            bundle.state == ModuleResearchRepairState::Replayed
                && bundle.source_snapshot == expected
        })
        .ok_or_else(|| invalid("Stage 6 source verification has no replayed repair bundle"))?;
    let bundle = &mut state.research_repair_bundles[index];
    bundle.original_verification = Some(result.clone());
    if result.unchanged
        && result.snapshot_digest == expected
        && result.changed_paths.is_empty()
        && result.added_paths.is_empty()
        && result.removed_paths.is_empty()
    {
        bundle.state = ModuleResearchRepairState::Verified;
        bundle.limitations.push(
            "The host re-read the exact selected workspace after repair qualification and observed no changed, added, or removed bytes.".into(),
        );
    } else {
        bundle.state = ModuleResearchRepairState::Rejected;
        bundle.limitations.push(
            "The final original-workspace comparison failed; retained copy-only evidence is not an accepted Stage 6 repair.".into(),
        );
    }
    let verified = bundle.state == ModuleResearchRepairState::Verified;
    let id = bundle.id.clone();
    let patch =
        bundle.patch.as_ref().map_or("none", |patch| patch.patch_digest.as_str()).to_owned();
    let artifacts = bundle.artifacts.len();
    state.pending = None;
    state::save(parameters, state)?;
    Ok(reply(
        format!(
            "# Stage 6 {}\n\n- Repair bundle: `{id}`\n- Patch: `{patch}`\n- Patched PoC: blocked\n- Original full chain: blocked on patched twin\n- Counterfactual and adapter obligations: passed\n- Bounded mutations: blocked\n- Legitimate and malformed behavior: passed\n- Independent patch review: accepted\n- Original workspace unchanged: {}\n- Owner-only artifacts: {artifacts}\n\nNo patch was applied to the selected source and no external system was contacted.",
            if verified { "repair verified" } else { "repair rejected" },
            result.unchanged,
        ),
        profile,
        super::actions(state),
        None,
    ))
}

pub(crate) fn host_failure(state: &mut state::State, pending: &PendingRequest, detail: &str) {
    match pending {
        PendingRequest::AdapterExecute { request, .. }
            if request.operation == crate::runtime_chain_repair::OPERATION =>
        {
            block_request(state, request, detail);
        }
        PendingRequest::SourceVerify { key, .. }
            if key.starts_with("red-team-chain-repair-verify-") =>
        {
            if let Some(bundle) = state
                .research_repair_bundles
                .iter_mut()
                .rev()
                .find(|bundle| bundle.state == ModuleResearchRepairState::Replayed)
            {
                bundle.state = ModuleResearchRepairState::Rejected;
                bundle.limitations.push(format!(
                    "Final original-workspace verification failed safely: {}",
                    detail.chars().take(2048).collect::<String>()
                ));
            }
        }
        _ => {}
    }
}

pub(crate) fn receipt_failure(
    parameters: &Value,
    state: &mut state::State,
    request: &ModuleAdapterExecuteRequest,
    detail: &str,
) -> Result<(), Error> {
    block_request(state, request, detail);
    state.pending = None;
    state::save(parameters, state)
}

fn block_request(state: &mut state::State, request: &ModuleAdapterExecuteRequest, detail: &str) {
    if request.operation != crate::runtime_chain_repair::OPERATION {
        return;
    }
    let Ok(input) = serde_json::from_value::<ModuleResearchRepairRequest>(request.input.clone())
    else {
        return;
    };
    if let Some(bundle) = state.research_repair_bundles.iter_mut().find(|bundle| {
        bundle.id == input.repair_bundle_id && bundle.state == ModuleResearchRepairState::Planned
    }) {
        bundle.state = ModuleResearchRepairState::Blocked;
        bundle.patch = None;
        bundle.replay = None;
        bundle.review = None;
        bundle.artifacts.clear();
        bundle.original_verification = None;
        bundle.limitations = vec![format!(
            "Stage 6 admitted no patch because copy-only replay or review failed safely: {}",
            detail.chars().take(2048).collect::<String>()
        )];
    }
}

fn cancel(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
) -> Result<ModuleAction, Error> {
    let pending = state.pending.clone();
    let Some(pending) = pending.as_ref() else {
        return Err(invalid("no retained Stage 6 repair is available to cancel"));
    };
    let owned = matches!(pending, PendingRequest::AdapterExecute { request, .. } if request.operation == crate::runtime_chain_repair::OPERATION)
        || matches!(pending, PendingRequest::SourceVerify { key, .. } if key.starts_with("red-team-chain-repair-verify-"));
    if !owned {
        return Err(invalid("the retained host request is not a Stage 6 repair"));
    }
    host_failure(
        state,
        pending,
        "cancelled before final admission; owned worker cleanup remains a host obligation",
    );
    state.pending = None;
    state::save(parameters, state)?;
    Ok(reply(
        "Stage 6 was cancelled. No repair was accepted; completed private evidence, if any, remains explicitly rejected and the selected source was not modified.",
        profile,
        super::actions(state),
        None,
    ))
}

fn write_bundle(
    parameters: &Value,
    input: &ModuleResearchRepairRequest,
    observation: &ModuleResearchRepairObservation,
) -> Result<Vec<ModuleResearchArtifactIdentity>, Error> {
    if !state::has_digest_id(&input.repair_bundle_id, "repair-") {
        return Err(invalid("Stage 6 repair bundle identity is not a canonical digest"));
    }
    let relative_root = PathBuf::from("research-artifacts").join(&input.repair_bundle_id);
    let private_root = state::private_root(parameters)?;
    let root = private_root.join(&relative_root);
    if root.exists() {
        return Err(invalid("Stage 6 artifact destination already exists"));
    }
    let patch = &observation.diff_bytes;
    let script = crate::runtime_browser::REPAIR_REGRESSION.as_bytes();
    let matrix = serde_json::to_vec_pretty(&observation.matrix)?;
    let review = serde_json::to_vec_pretty(&observation.review)?;
    let evidence = serde_json::to_vec_pretty(observation)?;
    let manifest = serde_json::to_vec_pretty(&json!({
        "schema": 2,
        "repair_bundle_id": input.repair_bundle_id,
        "poc_bundle_id": input.poc_bundle_id,
        "graph_id": input.graph_id,
        "chain_id": input.chain_id,
        "source_snapshot": input.source_snapshot,
        "patch": observation.patch,
        "regression_script_digest": observation.regression_script_digest,
        "verification_digest": observation.verification_digest,
        "copy_only": true,
        "original_verification_pending": true,
        "limitations": observation.limitations,
    }))?;
    let specifications = vec![
        (
            "repair.patch",
            patch.as_slice(),
            "text/x-diff",
            ModuleResearchArtifactClassification::PrivateRepairPatch,
        ),
        (
            "regression-replay.py",
            script,
            "text/x-python",
            ModuleResearchArtifactClassification::PrivateRegressionEvidence,
        ),
        (
            "regression-matrix.json",
            matrix.as_slice(),
            "application/json",
            ModuleResearchArtifactClassification::PrivateRegressionEvidence,
        ),
        (
            "patch-review.json",
            review.as_slice(),
            "application/json",
            ModuleResearchArtifactClassification::PrivateRegressionEvidence,
        ),
        (
            "manifest.json",
            manifest.as_slice(),
            "application/json",
            ModuleResearchArtifactClassification::PrivateGraphEvidence,
        ),
        (
            "evidence.json",
            evidence.as_slice(),
            "application/json",
            ModuleResearchArtifactClassification::PrivateReceipt,
        ),
    ];
    let parent = private_root.join("research-artifacts");
    fs::create_dir_all(&parent)?;
    if parent.is_symlink() || !parent.is_dir() {
        return Err(invalid("Stage 6 artifact parent is not a private directory"));
    }
    set_private_directory(&parent)?;
    let temporary = tempfile::Builder::new().prefix("stage6-").tempdir_in(&parent)?;
    set_private_directory(temporary.path())?;
    for (name, bytes, _, _) in &specifications {
        write_private(&temporary.path().join(name), bytes)?;
    }
    let temporary_path = temporary.keep();
    fs::rename(&temporary_path, &root)?;
    #[cfg(unix)]
    fs::File::open(&parent)?.sync_all()?;
    let mut artifacts = Vec::new();
    for (name, bytes, media_type, classification) in specifications {
        let relative = relative_root
            .join(name)
            .to_str()
            .ok_or_else(|| invalid("Stage 6 artifact path is not UTF-8"))?
            .replace('\\', "/");
        artifacts.push(ModuleResearchArtifactIdentity {
            schema: MODULE_RESEARCH_CONTRACT_VERSION,
            identity: ModuleResearchIdentity {
                schema: MODULE_RESEARCH_CONTRACT_VERSION,
                kind: ModuleResearchIdentityKind::Artifact,
                value: relative.clone(),
                digest: digest(bytes),
            },
            media_type: media_type.into(),
            bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            classification,
            relative_private_path: relative,
            owner_only: true,
        });
    }
    Ok(artifacts)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    #[cfg(unix)]
    let options = {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        options
    };
    #[cfg(not(unix))]
    let options = {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        options
    };
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn set_private_directory(path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn plan(state: &state::State) -> String {
    let verified = state
        .research_poc_bundles
        .iter()
        .filter(|bundle| bundle.state == ModuleResearchPocState::Verified)
        .collect::<Vec<_>>();
    let twins = crate::chain_confirmation::ready_twins(state).is_ok();
    let adapter = adapter::installed_runtime(state, crate::attack_graph::ADAPTER_ID).is_some();
    let mut text = format!(
        "# Stage 6 root-cause repair plan\n\n- Verified Stage 5 PoC bundles: {}\n- Vulnerable and safe twins ready: {}\n- Registered repair adapter installed: {}\n- Pending host request: {}\n\n",
        verified.len(),
        twins,
        adapter,
        state.pending.is_some(),
    );
    for bundle in verified {
        text.push_str(&format!(
            "- `{}` — chain `{}` — replay `{}`\n",
            bundle.id,
            bundle.chain_id,
            bundle.replay.as_ref().map_or("none", |value| value.digest.as_str()),
        ));
    }
    text.push_str("\n`repair-start [POC_BUNDLE_ID]` creates a fresh patched twin from an exact source preimage, replays the PoC and chain, runs bounded mutations and legitimate controls, performs independent review, and asks the host to re-read the selected workspace. No patch is applied to the selected source.\n");
    text
}

fn history(state: &state::State) -> String {
    let mut text = String::from("# Stage 6 private repair history\n\n");
    if state.research_repair_bundles.is_empty() {
        text.push_str("No Stage 6 repair has been planned or verified.\n");
        return text;
    }
    for bundle in &state.research_repair_bundles {
        text.push_str(&format!(
            "- `{}` — `{:?}` — PoC `{}` — chain `{}` — patch `{}` — artifacts {} — original unchanged `{}`\n",
            bundle.id,
            bundle.state,
            bundle.poc_bundle_id,
            bundle.chain_id,
            bundle.patch.as_ref().map_or("none", |patch| patch.patch_digest.as_str()),
            bundle.artifacts.len(),
            bundle.original_verification.as_ref().is_some_and(|value| value.unchanged),
        ));
        for limitation in &bundle.limitations {
            text.push_str(&format!("  - {limitation}\n"));
        }
    }
    text
}
