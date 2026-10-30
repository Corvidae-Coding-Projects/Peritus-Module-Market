//! Stage 6 exact-preimage repair, patched-twin replay, mutation, and independent review.

use super::{runtime_attack_graph, runtime_browser, runtime_laboratory};
use crate::digest;
use peritus_plugin_sdk::{
    ModuleAttackGraphCampaignRequest, ModuleAttackGraphDisposition, ModuleResearchPatchIdentity,
    ModuleResearchPatchRejection, ModuleResearchPatchReview, ModuleResearchPocReplayObservation,
    ModuleResearchPocTargetIdentity, ModuleResearchRegressionCase,
    ModuleResearchRegressionCategory, ModuleResearchRegressionObservation,
    ModuleResearchRepairObservation, ModuleResearchRepairRequest,
};
use serde_json::json;
use std::{collections::BTreeSet, fs, path::Path};

pub(super) const OPERATION: &str = "research-chain.repair.v1";
pub(super) const PROFILE: &str = "peritus.research-chain-repair.standard@1";
pub(super) const REVIEWER: &str = "peritus-chain-patch-reviewer-2026-10-30.1";
pub(super) const ROOT_CAUSE_GROUP: &str = "root-unsafe-stored-markup-rendering";
pub(super) const EARLIEST_PREREQUISITE: &str = "source-config:VULNERABLE";

const VULNERABLE_PREIMAGE: &[u8] = b"VULNERABLE = True";
const PATCHED_PREIMAGE: &[u8] = b"VULNERABLE = False";

pub(super) fn execute(
    request: &ModuleResearchRepairRequest,
    request_key: &str,
    host_state: &Path,
    laboratory: &runtime_laboratory::Broker,
) -> Result<ModuleResearchRepairObservation, String> {
    validate(request)?;
    let original = laboratory.attack_graph_session(
        &request.vulnerable_laboratory_id,
        &request.vulnerable_endpoint_handle,
    )?;
    if original.source_snapshot != request.source_snapshot {
        return Err("Stage 6 target belongs to another immutable source snapshot".into());
    }
    let occurrences = original
        .service_bytes
        .windows(VULNERABLE_PREIMAGE.len())
        .filter(|window| *window == VULNERABLE_PREIMAGE)
        .count();
    if occurrences != 1
        || original
            .service_bytes
            .windows(PATCHED_PREIMAGE.len())
            .any(|window| window == PATCHED_PREIMAGE)
    {
        return Err(
            "Stage 6 requires one exact vulnerable configuration preimage and no prior repair"
                .into(),
        );
    }
    let patched_bytes =
        replace_once(&original.service_bytes, VULNERABLE_PREIMAGE, PATCHED_PREIMAGE)?;
    let diff_bytes = unified_diff(&original.service_path, &original.service_bytes, &patched_bytes)?;
    let patch = ModuleResearchPatchIdentity {
        target_path: original.service_path.clone(),
        original_digest: original.service_digest.clone(),
        patched_digest: digest(&patched_bytes),
        patch_digest: digest(
            format!(
                "peritus.red-team.repair.patch.v1\0{}\0{}\0{}",
                original.service_digest,
                digest(&patched_bytes),
                digest(&diff_bytes),
            )
            .as_bytes(),
        ),
        diff_digest: digest(&diff_bytes),
        root_cause_group: ROOT_CAUSE_GROUP.into(),
        earliest_prerequisite: EARLIEST_PREREQUISITE.into(),
    };

    let root = std::env::current_dir().map_err(|error| error.to_string())?;
    let private_root = root.join(".red-team-worker-private");
    fs::create_dir_all(&private_root).map_err(|error| error.to_string())?;
    let staging = tempfile::Builder::new()
        .prefix("stage6-patched-")
        .tempdir_in(&private_root)
        .map_err(|error| error.to_string())?;
    let patched_root = staging.path().to_path_buf();
    let application_path = staging.path().join("application.py");
    let service_path = staging.path().join("service.py");
    write_private(&application_path, &original.application_bytes)?;
    write_private(&service_path, &patched_bytes)?;
    let application_relative = relative(&root, &application_path)?;
    let service_relative = relative(&root, &service_path)?;
    let patched_laboratory_id = digest(
        format!(
            "stage6-patched-laboratory-v1\0{}\0{}\0{}",
            request.repair_bundle_id, patch.patch_digest, request.source_snapshot,
        )
        .as_bytes(),
    );
    let patched_endpoint_handle =
        digest(format!("stage6-patched-endpoint-v1\0{patched_laboratory_id}").as_bytes());
    let original_binding = runtime_laboratory::TargetBinding {
        laboratory_id: request.vulnerable_laboratory_id.clone(),
        target: runtime_laboratory::TargetPaths {
            application_path: original.application_path.clone(),
            service_path: original.service_path.clone(),
        },
    };
    let patched_binding = runtime_laboratory::TargetBinding {
        laboratory_id: patched_laboratory_id.clone(),
        target: runtime_laboratory::TargetPaths {
            application_path: application_relative,
            service_path: service_relative,
        },
    };
    let replay_broker = runtime_laboratory::Broker::new(
        request.source_snapshot.clone(),
        vec![original_binding, patched_binding.clone()],
    );
    let full_request = ModuleAttackGraphCampaignRequest {
        schema: 1,
        source: request.source.clone(),
        vulnerable_laboratory_id: request.vulnerable_laboratory_id.clone(),
        vulnerable_endpoint_handle: request.vulnerable_endpoint_handle.clone(),
        repaired_laboratory_id: patched_laboratory_id.clone(),
        repaired_endpoint_handle: patched_endpoint_handle.clone(),
        profile: runtime_attack_graph::PROFILE.into(),
        maximum_browser_actions: request.maximum_browser_actions,
        maximum_requests: request.maximum_requests,
        maximum_artifact_bytes: request.maximum_artifact_bytes,
    };
    let full_replay = runtime_attack_graph::execute_fresh(
        &full_request,
        request_key,
        host_state,
        &replay_broker,
    )?;
    let patched_session =
        replay_broker.attack_graph_session(&patched_laboratory_id, &patched_endpoint_handle)?;
    let patched_target = target(&patched_session);
    let browser_root = tempfile::Builder::new()
        .prefix("stage6-browser-")
        .tempdir_in(host_state)
        .map_err(|error| error.to_string())?;
    let patched_poc: ModuleResearchPocReplayObservation =
        serde_json::from_value(runtime_browser::research_poc(
            &browser_root.path().join("minimized-poc"),
            &patched_target,
            &request.destination,
            &request.synthetic_identity,
            false,
            request.maximum_browser_actions / 3,
            request.maximum_requests / 3,
        )?)
        .map_err(|error| format!("patched minimized PoC returned invalid evidence: {error}"))?;
    validate_patched_poc(&patched_poc, &patched_target)?;

    let identity_rejection = match runtime_browser::repair_regression(
        &browser_root.path().join("wrong-identity"),
        &replay_broker
            .browser_session(
                &patched_laboratory_id,
                &patched_endpoint_handle,
                request.maximum_requests,
            )?
            .target_socket,
        &request.destination,
        "unauthorized-user:ambient-credential",
        request.maximum_browser_actions,
        request.maximum_requests.saturating_mul(2),
    ) {
        Ok(_) => return Err("Stage 6 regression driver accepted a wrong identity".into()),
        Err(error) => error,
    };
    if !identity_rejection.contains("exact synthetic credential-free subject") {
        return Err("Stage 6 identity mutation did not fail at the policy boundary".into());
    }
    let destination_rejection = match runtime_browser::repair_regression(
        &browser_root.path().join("wrong-destination"),
        &replay_broker
            .browser_session(
                &patched_laboratory_id,
                &patched_endpoint_handle,
                request.maximum_requests,
            )?
            .target_socket,
        "https://public.invalid/target",
        &request.synthetic_identity,
        request.maximum_browser_actions,
        request.maximum_requests.saturating_mul(2),
    ) {
        Ok(_) => return Err("Stage 6 regression driver accepted a non-private destination".into()),
        Err(error) => error,
    };
    if !destination_rejection.contains("exact private Unix destination") {
        return Err("Stage 6 transport mutation did not fail at the policy boundary".into());
    }

    let regression_laboratory_id =
        digest(format!("stage6-regression-laboratory-v1\0{}", request.repair_bundle_id).as_bytes());
    let regression_endpoint_handle =
        digest(format!("stage6-regression-endpoint-v1\0{regression_laboratory_id}").as_bytes());
    let regression_broker = runtime_laboratory::Broker::new(
        request.source_snapshot.clone(),
        vec![runtime_laboratory::TargetBinding {
            laboratory_id: regression_laboratory_id.clone(),
            target: patched_binding.target,
        }],
    );
    let regression_session = regression_broker.browser_session(
        &regression_laboratory_id,
        &regression_endpoint_handle,
        request.maximum_requests.saturating_mul(2),
    )?;
    let regression: ModuleResearchRegressionObservation =
        serde_json::from_value(runtime_browser::repair_regression(
            &browser_root.path().join("matrix"),
            &regression_session.target_socket,
            &request.destination,
            &request.synthetic_identity,
            request.maximum_browser_actions,
            request.maximum_requests.saturating_mul(2),
        )?)
        .map_err(|error| format!("Stage 6 regression driver returned invalid evidence: {error}"))?;
    validate_regression(request, &regression)?;
    let mut matrix = regression.cases.clone();
    matrix.extend(core_matrix(
        &full_replay,
        &patched_poc,
        &identity_rejection,
        &destination_rejection,
    ));
    let regression_script_digest = digest(runtime_browser::REPAIR_REGRESSION.as_bytes());
    let review = review(
        &patch,
        &diff_bytes,
        &full_replay,
        &matrix,
        &original.service_path,
        &regression_script_digest,
    )?;

    let original_source_unchanged = fs::read(&original.application_path)
        .map_err(|error| error.to_string())?
        == original.application_bytes
        && fs::read(&original.service_path).map_err(|error| error.to_string())?
            == original.service_bytes;
    drop(regression_broker);
    drop(replay_broker);
    drop(browser_root);
    staging.close().map_err(|error| error.to_string())?;
    let cleanup_complete = !patched_root.exists();
    if !cleanup_complete || !original_source_unchanged {
        return Err("Stage 6 disposable cleanup or worker-source preservation proof failed".into());
    }
    let verification_digest = digest(
        &serde_json::to_vec(&json!({
            "schema": 2,
            "repair": request.repair_bundle_id,
            "patch": patch,
            "full_replay": full_replay.campaign_digest,
            "poc": patched_poc.result_digest,
            "regression": regression.result_digest,
            "matrix": matrix,
            "review": review,
            "cleanup": cleanup_complete,
            "source_unchanged": original_source_unchanged,
        }))
        .map_err(|error| error.to_string())?,
    );
    Ok(ModuleResearchRepairObservation {
        schema: 2,
        graph_id: request.graph_id.clone(),
        chain_id: request.chain_id.clone(),
        poc_bundle_id: request.poc_bundle_id.clone(),
        repair_bundle_id: request.repair_bundle_id.clone(),
        source_snapshot: request.source_snapshot.clone(),
        profile: PROFILE.into(),
        patched_laboratory_id,
        patch,
        diff_bytes,
        full_replay,
        patched_poc,
        regression,
        matrix,
        review,
        regression_script_digest,
        cleanup_complete,
        original_source_unchanged,
        verification_digest,
        limitations: vec![
            "This exact repair is qualified only for the confirmed stored-content client-script chain and the retained bounded mutation matrix.".into(),
            "The patch was applied only inside a disposable worker copy; applying it to a vendor repository remains a separate user-controlled action.".into(),
            "Mutation dimensions are finite and do not establish absence of every equivalent bypass.".into(),
        ],
    })
}

fn validate(request: &ModuleResearchRepairRequest) -> Result<(), String> {
    if request.schema != 2
        || request.profile != PROFILE
        || request.destination != super::runtime_chain_confirmation::DESTINATION
        || request.synthetic_identity != super::runtime_chain_confirmation::SYNTHETIC_IDENTITY
        || request.graph_id.is_empty()
        || request.chain_id.is_empty()
        || request.poc_bundle_id.is_empty()
        || request.repair_bundle_id.is_empty()
        || request.source_snapshot.len() != 64
    {
        return Err("Stage 6 repair request has an invalid identity or policy".into());
    }
    for value in [
        &request.vulnerable_laboratory_id,
        &request.vulnerable_endpoint_handle,
        &request.source_snapshot,
    ] {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("Stage 6 repair requires opaque SHA-256 target identities".into());
        }
    }
    if !(24..=32).contains(&request.maximum_browser_actions)
        || !(32..=80).contains(&request.maximum_requests)
        || !(6..=16).contains(&request.maximum_mutations)
        || !(512 * 1024..=8 * 1024 * 1024).contains(&request.maximum_artifact_bytes)
    {
        return Err("Stage 6 repair bounds are outside the registered profile".into());
    }
    Ok(())
}

fn validate_patched_poc(
    replay: &ModuleResearchPocReplayObservation,
    target: &ModuleResearchPocTargetIdentity,
) -> Result<(), String> {
    if replay.schema != 2
        || &replay.target != target
        || replay.expected_signal
        || replay.observed_signal
        || replay.browser_identity.is_empty()
        || replay.traffic_digest.len() != 64
        || replay.result_digest.len() != 64
        || replay.requests_observed == 0
        || replay.actions_executed == 0
        || !replay.cleanup_complete
        || !replay.original_source_unchanged
    {
        return Err("Stage 6 patched PoC violated its exact safe-result contract".into());
    }
    Ok(())
}

fn validate_regression(
    request: &ModuleResearchRepairRequest,
    regression: &ModuleResearchRegressionObservation,
) -> Result<(), String> {
    let mutation_count = regression
        .cases
        .iter()
        .filter(|case| case.category == ModuleResearchRegressionCategory::Mutation)
        .count();
    let dimensions =
        regression.cases.iter().map(|case| case.dimension.as_str()).collect::<BTreeSet<_>>();
    let required = BTreeSet::from([
        "behavior",
        "encoding",
        "ordering",
        "transport",
        "state",
        "timing",
        "alternate_entry",
        "equivalent_adapter_path",
    ]);
    if regression.schema != 2
        || regression.browser_identity.is_empty()
        || regression.cases.len() < 10
        || mutation_count > request.maximum_mutations as usize
        || !required.is_subset(&dimensions)
        || regression.cases.iter().any(|case| {
            case.id.is_empty()
                || case.expected.is_empty()
                || case.observed.is_empty()
                || !case.passed
                || case.evidence_digest.len() != 64
        })
        || regression.actions_executed > u64::from(request.maximum_browser_actions)
        || regression.requests_observed > u64::from(request.maximum_requests.saturating_mul(2))
        || regression.traffic_digest.len() != 64
        || regression.result_digest.len() != 64
        || !regression.browser_cleanup_complete
    {
        return Err("Stage 6 bounded regression matrix is incomplete or failed".into());
    }
    Ok(())
}

fn core_matrix(
    full: &peritus_plugin_sdk::ModuleAttackGraphObservation,
    poc: &ModuleResearchPocReplayObservation,
    identity_rejection: &str,
    destination_rejection: &str,
) -> Vec<ModuleResearchRegressionCase> {
    let full_blocked = full.repair.review_accepted
        && full
            .repair
            .replays
            .iter()
            .any(|case| case.case_id == "stored-script-blocked" && case.passed);
    let counterfactual =
        full.chains.iter().any(|chain| chain.disposition == ModuleAttackGraphDisposition::Broken);
    let mut cases = vec![
        matrix_case(
            "minimized-poc-patched",
            ModuleResearchRegressionCategory::MinimizedPoc,
            "original_poc",
            "no canary impact",
            format!("observed_signal={}", poc.observed_signal),
            !poc.observed_signal && poc.cleanup_complete,
            &poc.result_digest,
        ),
        matrix_case(
            "original-full-chain-patched",
            ModuleResearchRegressionCategory::FullChain,
            "original_chain",
            "full chain blocked on patched twin",
            full.repair.review_detail.clone(),
            full_blocked,
            &full.campaign_digest,
        ),
        matrix_case(
            "removed-prerequisite-control",
            ModuleResearchRegressionCategory::Counterfactual,
            "counterfactual",
            "legitimate route remains while impact is absent",
            "broken-prerequisite chain retained".into(),
            counterfactual,
            &full.campaign_digest,
        ),
        matrix_case(
            "wrong-identity-refused",
            ModuleResearchRegressionCategory::SafetyControl,
            "identity",
            "rejected before target launch",
            identity_rejection.chars().take(2048).collect(),
            identity_rejection.contains("exact synthetic credential-free subject"),
            &digest(identity_rejection.as_bytes()),
        ),
        matrix_case(
            "non-private-transport-refused",
            ModuleResearchRegressionCategory::SafetyControl,
            "transport",
            "rejected before target launch",
            destination_rejection.chars().take(2048).collect(),
            destination_rejection.contains("exact private Unix destination"),
            &digest(destination_rejection.as_bytes()),
        ),
    ];
    cases.extend(full.repair.replays.iter().map(|replay| {
        matrix_case(
            &format!("supporting-{}-{}", replay.adapter_id, replay.case_id),
            ModuleResearchRegressionCategory::SupportingAdapter,
            "adapter_obligation",
            "registered adapter obligation passes",
            replay.detail.clone(),
            replay.passed,
            &replay.evidence_digest,
        )
    }));
    cases
}

fn review(
    patch: &ModuleResearchPatchIdentity,
    diff_bytes: &[u8],
    full: &peritus_plugin_sdk::ModuleAttackGraphObservation,
    matrix: &[ModuleResearchRegressionCase],
    original_path: &str,
    regression_script_digest: &str,
) -> Result<ModuleResearchPatchReview, String> {
    let exact_preimage = patch.target_path == original_path
        && patch.original_digest == full.repair.original_digest
        && patch.patched_digest == full.repair.patched_digest
        && patch.diff_digest == digest(diff_bytes)
        && full.repair.diff_bytes == diff_bytes;
    let root_cause_repaired = patch.root_cause_group == ROOT_CAUSE_GROUP
        && patch.earliest_prerequisite == EARLIEST_PREREQUISITE
        && full.repair.review_accepted;
    let legitimate_behavior_preserved = full.repair.legitimate_behavior_preserved
        && matrix.iter().any(|case| {
            case.category == ModuleResearchRegressionCategory::Legitimate && case.passed
        });
    let oracle_preserved = regression_script_digest.len() == 64
        && matrix.iter().any(|case| {
            case.category == ModuleResearchRegressionCategory::MinimizedPoc && case.passed
        });
    let target_preserved = full.repair.target_path == original_path;
    let categories = matrix.iter().map(|case| case.category).collect::<BTreeSet<_>>();
    let complete_matrix = matrix.iter().all(|case| case.passed)
        && [
            ModuleResearchRegressionCategory::MinimizedPoc,
            ModuleResearchRegressionCategory::FullChain,
            ModuleResearchRegressionCategory::Counterfactual,
            ModuleResearchRegressionCategory::SupportingAdapter,
            ModuleResearchRegressionCategory::Legitimate,
            ModuleResearchRegressionCategory::Malformed,
            ModuleResearchRegressionCategory::Adjacent,
            ModuleResearchRegressionCategory::Mutation,
            ModuleResearchRegressionCategory::SafetyControl,
        ]
        .into_iter()
        .all(|category| categories.contains(&category));
    let rejected_strategies = vec![
        rejection(
            "disable-stored-content-feature",
            legitimate_behavior_preserved,
            "feature removal fails the required legitimate store/read replay",
        ),
        rejection(
            "suppress-signal-or-error",
            oracle_preserved,
            "oracle or error suppression changes the fixed PoC evidence identity",
        ),
        rejection(
            "replace-target-with-safe-fixture",
            target_preserved,
            "target replacement breaks the exact vulnerable source preimage identity",
        ),
        rejection(
            "patch-later-symptom-only",
            root_cause_repaired,
            "a later symptom does not repair the earliest shared source prerequisite",
        ),
    ];
    let accepted = exact_preimage
        && root_cause_repaired
        && legitimate_behavior_preserved
        && oracle_preserved
        && target_preserved
        && complete_matrix
        && rejected_strategies.iter().all(|item| item.rejected);
    if !accepted {
        return Err("independent Stage 6 reviewer rejected the exact diff or replay matrix".into());
    }
    Ok(ModuleResearchPatchReview {
        reviewer: REVIEWER.into(),
        accepted,
        exact_preimage,
        root_cause_repaired,
        legitimate_behavior_preserved,
        oracle_preserved,
        target_preserved,
        complete_matrix,
        rejected_strategies,
        detail: "The independent reviewer bound the one-line exact-preimage root-cause diff to the original target, unchanged oracles, the minimized PoC, original chain, counterfactual, three adapter obligations, legitimate and malformed behavior, adjacent entries, bounded mutations, safety refusals, and cleanup.".into(),
    })
}

fn rejection(
    strategy: &str,
    invalid_condition: bool,
    reason: &str,
) -> ModuleResearchPatchRejection {
    ModuleResearchPatchRejection {
        strategy: strategy.into(),
        rejected: invalid_condition,
        reason: reason.into(),
    }
}

fn matrix_case(
    id: &str,
    category: ModuleResearchRegressionCategory,
    dimension: &str,
    expected: &str,
    observed: String,
    passed: bool,
    evidence_digest: &str,
) -> ModuleResearchRegressionCase {
    ModuleResearchRegressionCase {
        id: id.into(),
        category,
        dimension: dimension.into(),
        expected: expected.into(),
        observed,
        passed,
        evidence_digest: evidence_digest.into(),
    }
}

fn target(
    session: &runtime_laboratory::AttackGraphLaboratorySession,
) -> ModuleResearchPocTargetIdentity {
    let target_identity = digest(
        format!(
            "peritus.red-team.poc.target.v1\0{}\0{}\0{}\0{}",
            session.application_path,
            session.application_digest,
            session.service_path,
            session.service_digest,
        )
        .as_bytes(),
    );
    ModuleResearchPocTargetIdentity {
        application_path: session.application_path.clone(),
        application_digest: session.application_digest.clone(),
        service_path: session.service_path.clone(),
        service_digest: session.service_digest.clone(),
        target_identity,
    }
}

fn relative(root: &Path, path: &Path) -> Result<String, String> {
    path.strip_prefix(root)
        .map_err(|_| "Stage 6 patched target escaped the disposable source root".to_string())?
        .to_str()
        .ok_or_else(|| "Stage 6 patched target path is not UTF-8".to_string())
        .map(str::to_owned)
}

fn replace_once(bytes: &[u8], needle: &[u8], replacement: &[u8]) -> Result<Vec<u8>, String> {
    let offset = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .ok_or_else(|| "Stage 6 patch preimage is absent".to_string())?;
    let mut patched = Vec::with_capacity(bytes.len() - needle.len() + replacement.len());
    patched.extend_from_slice(&bytes[..offset]);
    patched.extend_from_slice(replacement);
    patched.extend_from_slice(&bytes[offset + needle.len()..]);
    Ok(patched)
}

fn unified_diff(path: &str, original: &[u8], replacement: &[u8]) -> Result<Vec<u8>, String> {
    let original =
        std::str::from_utf8(original).map_err(|_| "Stage 6 patch preimage is not UTF-8")?;
    let replacement =
        std::str::from_utf8(replacement).map_err(|_| "Stage 6 patch replacement is not UTF-8")?;
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

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}
