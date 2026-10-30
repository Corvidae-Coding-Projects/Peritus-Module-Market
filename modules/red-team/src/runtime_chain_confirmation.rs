//! Stage 5 fresh full-chain replay and standalone private PoC verification.

use super::{runtime_attack_graph, runtime_browser, runtime_laboratory::Broker};
use crate::digest;
use peritus_plugin_sdk::{
    ModuleAttackGraphCampaignRequest, ModuleAttackGraphDisposition,
    ModuleResearchChainConfirmationObservation, ModuleResearchChainConfirmationRequest,
    ModuleResearchPocReplayObservation, ModuleResearchPocTargetIdentity,
};
use serde_json::json;
use std::path::Path;

pub(super) const OPERATION: &str = "research-chain.confirm.v1";
pub(super) const PROFILE: &str = "peritus.research-chain-confirmation.standard@1";
pub(super) const MINIMIZER_VERSION: &str = "peritus-chain-minimizer-2026-10-30.1";
pub(super) const DESTINATION: &str = "unix://poc-private/target.sock";
pub(super) const SYNTHETIC_IDENTITY: &str = "ordinary-user:credential-free";

pub(super) fn execute(
    request: &ModuleResearchChainConfirmationRequest,
    request_key: &str,
    host_state: &Path,
    laboratory: &Broker,
) -> Result<ModuleResearchChainConfirmationObservation, String> {
    validate(request)?;
    let full_request = ModuleAttackGraphCampaignRequest {
        schema: 1,
        source: request.source.clone(),
        vulnerable_laboratory_id: request.vulnerable_laboratory_id.clone(),
        vulnerable_endpoint_handle: request.vulnerable_endpoint_handle.clone(),
        repaired_laboratory_id: request.safe_laboratory_id.clone(),
        repaired_endpoint_handle: request.safe_endpoint_handle.clone(),
        profile: runtime_attack_graph::PROFILE.into(),
        maximum_browser_actions: request.maximum_browser_actions,
        maximum_requests: request.maximum_requests,
        maximum_artifact_bytes: request.maximum_artifact_bytes,
    };
    let full_replay =
        runtime_attack_graph::execute_fresh(&full_request, request_key, host_state, laboratory)?;
    if !full_replay.skeptic.accepted
        || !full_replay
            .chains
            .iter()
            .any(|chain| chain.disposition == ModuleAttackGraphDisposition::Confirmed)
        || !full_replay
            .chains
            .iter()
            .any(|chain| chain.disposition == ModuleAttackGraphDisposition::Broken)
        || !full_replay
            .chains
            .iter()
            .any(|chain| chain.disposition == ModuleAttackGraphDisposition::Rejected)
    {
        return Err(
            "fresh Stage 5 replay omitted confirmation, counterfactual, or rejection proof".into(),
        );
    }

    let vulnerable = laboratory.attack_graph_session(
        &request.vulnerable_laboratory_id,
        &request.vulnerable_endpoint_handle,
    )?;
    let safe = laboratory
        .attack_graph_session(&request.safe_laboratory_id, &request.safe_endpoint_handle)?;
    let vulnerable_target = target(&vulnerable);
    let safe_target = target(&safe);
    let staging = tempfile::Builder::new()
        .prefix("stage5-confirmation-")
        .tempdir_in(host_state)
        .map_err(|error| error.to_string())?;
    let vulnerable_poc: ModuleResearchPocReplayObservation =
        serde_json::from_value(runtime_browser::research_poc(
            &staging.path().join("vulnerable"),
            &vulnerable_target,
            &request.destination,
            &request.synthetic_identity,
            true,
            request.maximum_browser_actions / 3,
            request.maximum_requests / 3,
        )?)
        .map_err(|error| format!("vulnerable standalone PoC returned invalid evidence: {error}"))?;
    let safe_poc: ModuleResearchPocReplayObservation =
        serde_json::from_value(runtime_browser::research_poc(
            &staging.path().join("safe"),
            &safe_target,
            &request.destination,
            &request.synthetic_identity,
            false,
            request.maximum_browser_actions / 3,
            request.maximum_requests / 3,
        )?)
        .map_err(|error| format!("safe standalone PoC returned invalid evidence: {error}"))?;
    validate_poc(&vulnerable_poc, &vulnerable_target, true)?;
    validate_poc(&safe_poc, &safe_target, false)?;

    let poc_script_digest = digest(runtime_browser::RESEARCH_POC.as_bytes());
    let verification_digest = digest(
        &serde_json::to_vec(&json!({
            "schema": 2,
            "graph": request.graph_id,
            "chain": request.chain_id,
            "bundle": request.bundle_id,
            "source": request.source_snapshot,
            "full_replay": full_replay.campaign_digest,
            "vulnerable_poc": vulnerable_poc.result_digest,
            "safe_poc": safe_poc.result_digest,
            "script": poc_script_digest,
            "minimizer": MINIMIZER_VERSION,
        }))
        .map_err(|error| error.to_string())?,
    );
    Ok(ModuleResearchChainConfirmationObservation {
        schema: 2,
        graph_id: request.graph_id.clone(),
        chain_id: request.chain_id.clone(),
        bundle_id: request.bundle_id.clone(),
        source_snapshot: request.source_snapshot.clone(),
        minimizer_version: MINIMIZER_VERSION.into(),
        poc_script_digest,
        full_replay,
        vulnerable_poc,
        safe_poc,
        verification_digest,
        limitations: vec![
            "The minimized PoC demonstrates only the fixed harmless stored-content canary in exact disposable vulnerable and safe twins.".into(),
            "The PoC accepts one literal private Unix destination and one synthetic credential-free identity; public, LAN, loopback, unresolved, and identity-mismatched targets are rejected before launch.".into(),
            "Standalone replay must run inside an operator-provided disposable sandbox suitable for untrusted target code; the script clears the target environment and uses a private Unix socket but is not itself an operating-system sandbox.".into(),
            "Other products, versions, entry points, encodings, client engines, and exploit impacts remain untested.".into(),
        ],
    })
}

fn validate(request: &ModuleResearchChainConfirmationRequest) -> Result<(), String> {
    if request.schema != 2
        || request.profile != PROFILE
        || request.destination != DESTINATION
        || request.synthetic_identity != SYNTHETIC_IDENTITY
        || request.graph_id.is_empty()
        || request.chain_id.is_empty()
        || request.bundle_id.is_empty()
        || request.source_snapshot.len() != 64
    {
        return Err("Stage 5 confirmation request has an invalid identity or policy".into());
    }
    for value in [
        &request.vulnerable_laboratory_id,
        &request.vulnerable_endpoint_handle,
        &request.safe_laboratory_id,
        &request.safe_endpoint_handle,
        &request.source_snapshot,
    ] {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("Stage 5 confirmation requires opaque SHA-256 target identities".into());
        }
    }
    if request.vulnerable_laboratory_id == request.safe_laboratory_id
        || !(9..=32).contains(&request.maximum_browser_actions)
        || !(24..=64).contains(&request.maximum_requests)
        || !(256 * 1024..=8 * 1024 * 1024).contains(&request.maximum_artifact_bytes)
    {
        return Err(
            "Stage 5 confirmation twins or bounds are outside the registered profile".into()
        );
    }
    Ok(())
}

fn target(
    session: &super::runtime_laboratory::AttackGraphLaboratorySession,
) -> ModuleResearchPocTargetIdentity {
    let target_identity = crate::digest(
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

fn validate_poc(
    replay: &ModuleResearchPocReplayObservation,
    target: &ModuleResearchPocTargetIdentity,
    expected_signal: bool,
) -> Result<(), String> {
    if replay.schema != 2
        || &replay.target != target
        || replay.expected_signal != expected_signal
        || replay.observed_signal != expected_signal
        || replay.browser_identity.is_empty()
        || replay.traffic_digest.len() != 64
        || replay.result_digest.len() != 64
        || replay.requests_observed == 0
        || replay.actions_executed == 0
        || !replay.cleanup_complete
        || !replay.original_source_unchanged
    {
        return Err("standalone Stage 5 PoC violated its exact replay contract".into());
    }
    Ok(())
}
