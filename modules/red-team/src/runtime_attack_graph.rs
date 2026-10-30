//! Composite cross-adapter attack graph, counterfactual, and copy-only repair replay.

use super::{runtime_http_api as http_api, runtime_laboratory::Broker};
use peritus_plugin_sdk::{
    ModuleAttackGraphCampaignRequest, ModuleAttackGraphChainObservation,
    ModuleAttackGraphDeduplicationObservation, ModuleAttackGraphDisposition,
    ModuleAttackGraphEdgeObservation, ModuleAttackGraphNodeKind, ModuleAttackGraphNodeObservation,
    ModuleAttackGraphObservation, ModuleAttackGraphRepairObservation,
    ModuleAttackGraphReplayObservation, ModuleAttackGraphSkepticObservation,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::{fs, path::Path};

pub(super) const PROFILE: &str = "peritus.attack-graph.standard@1";
pub(super) const ADAPTER_VERSION: &str = "peritus-attack-graph-2026-10-24.1";
pub(super) const SUITE_VERSION: &str = "peritus-attack-graph-suite-2026-10-24.1";

const ATTACK_PAYLOAD: &str = "<img src=x onerror=\"fetch('/signal?case=stored')\">";
const LEGITIMATE_NOTE: &str = "ordinary retained note";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserObservation {
    schema: u16,
    browser_identity: String,
    status: u16,
    signal_observed: bool,
    stored_text: String,
    rendered_html_digest: String,
    traffic_digest: String,
    requests_observed: u64,
    actions_executed: u64,
    off_scope_requests_blocked: u64,
    screenshot_digest: String,
    screenshot_bytes: u64,
}

pub(super) fn execute(
    request: &ModuleAttackGraphCampaignRequest,
    identity: &str,
    host_state: &Path,
    laboratory: &Broker,
) -> Result<ModuleAttackGraphObservation, String> {
    execute_with_retention(request, identity, host_state, laboratory, true)
}

pub(super) fn execute_fresh(
    request: &ModuleAttackGraphCampaignRequest,
    identity: &str,
    host_state: &Path,
    laboratory: &Broker,
) -> Result<ModuleAttackGraphObservation, String> {
    execute_with_retention(request, identity, host_state, laboratory, false)
}

fn execute_with_retention(
    request: &ModuleAttackGraphCampaignRequest,
    identity: &str,
    host_state: &Path,
    laboratory: &Broker,
    allow_retained: bool,
) -> Result<ModuleAttackGraphObservation, String> {
    validate(request)?;
    let vulnerable = laboratory.attack_graph_session(
        &request.vulnerable_laboratory_id,
        &request.vulnerable_endpoint_handle,
    )?;
    let repaired = laboratory
        .attack_graph_session(&request.repaired_laboratory_id, &request.repaired_endpoint_handle)?;
    if vulnerable.source_snapshot != repaired.source_snapshot {
        return Err("attack-graph twins do not share one immutable source snapshot".into());
    }
    if vulnerable.application_bytes != repaired.application_bytes
        || vulnerable.application_digest != repaired.application_digest
    {
        return Err("attack-graph twins have different application controllers".into());
    }
    let vulnerable_text = std::str::from_utf8(&vulnerable.service_bytes)
        .map_err(|_| "attack-graph vulnerable service is not UTF-8")?;
    let repaired_text = std::str::from_utf8(&repaired.service_bytes)
        .map_err(|_| "attack-graph repaired service is not UTF-8")?;
    if !vulnerable_text.contains("VULNERABLE = True")
        || !repaired_text.contains("VULNERABLE = False")
        || vulnerable.service_path == repaired.service_path
    {
        return Err(
            "attack-graph twins do not expose the registered vulnerable/repaired source contract"
                .into(),
        );
    }

    let root = host_state.join("attack-graph-campaigns-v1");
    fs::create_dir_all(&root).map_err(|error| error.to_string())?;
    let retained_id = digest(
        format!(
            "peritus.attack-graph.retained.v1\0{}\0{}\0{}\0{}",
            vulnerable.source_snapshot,
            request.vulnerable_laboratory_id,
            request.repaired_laboratory_id,
            ADAPTER_VERSION,
        )
        .as_bytes(),
    );
    let retained = root.join(&retained_id).join("observation.json");
    if allow_retained && retained.is_file() && !retained.is_symlink() {
        let observation: ModuleAttackGraphObservation =
            serde_json::from_slice(&fs::read(&retained).map_err(|error| error.to_string())?)
                .map_err(|error| {
                    format!("retained attack-graph observation is invalid: {error}")
                })?;
        if observation.source_snapshot != vulnerable.source_snapshot {
            return Err("retained attack graph belongs to another source snapshot".into());
        }
        return Ok(observation);
    }

    let staging = tempfile::Builder::new()
        .prefix("attack-graph-")
        .tempdir_in(&root)
        .map_err(|error| error.to_string())?;
    let source_evidence = digest(
        format!(
            "source\0{}\0{}\0{}",
            vulnerable.service_path, vulnerable.service_digest, repaired.service_digest
        )
        .as_bytes(),
    );

    let vulnerable_store = store(
        laboratory,
        &request.vulnerable_laboratory_id,
        &request.vulnerable_endpoint_handle,
        ATTACK_PAYLOAD,
    )?;
    if vulnerable_store.response_status != 200
        || !vulnerable_store.changed_state_keys.iter().any(|key| key == "comment")
    {
        return Err("vulnerable graph entry did not create the required copied-state effect".into());
    }
    let vulnerable_browser = browse(laboratory, request, true, staging.path().join("vulnerable"))?;
    if !vulnerable_browser.signal_observed
        || !vulnerable_browser.stored_text.contains("onerror")
        || !vulnerable_browser.stored_text.contains("/signal?case=stored")
    {
        return Err(format!(
            "vulnerable graph impact was not observed in the real browser: signal={}, stored={:?}, requests={}, traffic={}",
            vulnerable_browser.signal_observed,
            vulnerable_browser.stored_text,
            vulnerable_browser.requests_observed,
            vulnerable_browser.traffic_digest,
        ));
    }

    let counterfactual_store = store(
        laboratory,
        &request.vulnerable_laboratory_id,
        &request.vulnerable_endpoint_handle,
        LEGITIMATE_NOTE,
    )?;
    let counterfactual_browser =
        browse(laboratory, request, true, staging.path().join("counterfactual"))?;
    if counterfactual_store.response_status != 200
        || counterfactual_browser.signal_observed
        || counterfactual_browser.stored_text != LEGITIMATE_NOTE
    {
        return Err("counterfactual replay did not remove the persisted-markup prerequisite".into());
    }

    let repaired_store = store(
        laboratory,
        &request.repaired_laboratory_id,
        &request.repaired_endpoint_handle,
        ATTACK_PAYLOAD,
    )?;
    let repaired_browser = browse(laboratory, request, false, staging.path().join("repaired"))?;
    if repaired_store.response_status != 200
        || !repaired_store.changed_state_keys.iter().any(|key| key == "comment")
        || repaired_browser.signal_observed
        || repaired_browser.stored_text != ATTACK_PAYLOAD
    {
        return Err(
            "repaired twin did not preserve storage while preventing browser execution".into()
        );
    }

    let diff_bytes =
        unified_diff(&vulnerable.service_path, &vulnerable.service_bytes, &repaired.service_bytes)?;
    if u64::try_from(diff_bytes.len()).unwrap_or(u64::MAX) > request.maximum_artifact_bytes {
        return Err("attack-graph repair diff exceeds its admitted artifact bound".into());
    }

    let entry_evidence = vulnerable_store.request_digest.clone();
    let state_evidence = digest(
        format!(
            "{}\0{}\0{}",
            vulnerable_store.state_before_digest,
            vulnerable_store.state_after_digest,
            vulnerable_store.changed_state_keys.join(",")
        )
        .as_bytes(),
    );
    let impact_evidence = vulnerable_browser.traffic_digest.clone();
    let counterfactual_evidence = digest(
        format!(
            "{}\0{}\0{}",
            counterfactual_store.state_after_digest,
            counterfactual_browser.traffic_digest,
            counterfactual_browser.rendered_html_digest,
        )
        .as_bytes(),
    );
    let repaired_evidence = digest(
        format!(
            "{}\0{}\0{}",
            repaired_store.state_after_digest,
            repaired_browser.traffic_digest,
            repaired_browser.rendered_html_digest,
        )
        .as_bytes(),
    );
    let invented_evidence = digest(b"unsupported:peritus.identity-access:cross-tenant-read");

    let nodes = vec![
        node(
            "entry-unauthenticated-store",
            ModuleAttackGraphNodeKind::EntryPoint,
            "peritus.http-api",
            "An unauthenticated private HTTP request reached the stored-content endpoint.",
            &entry_evidence,
        ),
        node(
            "prerequisite-unsafe-render",
            ModuleAttackGraphNodeKind::Prerequisite,
            "peritus.source-analysis",
            "Exact copied source selected the unescaped rendering branch.",
            &source_evidence,
        ),
        node(
            "effect-persisted-markup",
            ModuleAttackGraphNodeKind::StateEffect,
            "peritus.http-api",
            "The attacker markup became copied application state.",
            &state_evidence,
        ),
        node(
            "impact-browser-script",
            ModuleAttackGraphNodeKind::Impact,
            "peritus.browser-client",
            "A real isolated browser requested the pinned signal from stored markup.",
            &impact_evidence,
        ),
    ];
    let edges = vec![
        edge(
            "edge-entry-persists",
            "entry-unauthenticated-store",
            "effect-persisted-markup",
            "unauthenticated_store_changes_copied_state@1",
            "peritus.http-api",
            &state_evidence,
            true,
        ),
        edge(
            "edge-source-enables-impact",
            "prerequisite-unsafe-render",
            "impact-browser-script",
            "unescaped_render_enables_browser_execution@1",
            "peritus.source-analysis",
            &source_evidence,
            true,
        ),
        edge(
            "edge-state-reaches-browser",
            "effect-persisted-markup",
            "impact-browser-script",
            "persisted_markup_reaches_real_browser@1",
            "peritus.browser-client",
            &impact_evidence,
            true,
        ),
        edge(
            "edge-invented-cross-tenant",
            "entry-unauthenticated-store",
            "impact-browser-script",
            "cross_tenant_read_escalates_browser_impact@1",
            "peritus.identity-access",
            &invented_evidence,
            false,
        ),
    ];
    let confirmed_replay =
        digest(format!("{source_evidence}\0{state_evidence}\0{impact_evidence}").as_bytes());
    let chains = vec![
        ModuleAttackGraphChainObservation {
            id: "chain-stored-browser-execution".into(),
            nodes: vec![
                "entry-unauthenticated-store".into(),
                "effect-persisted-markup".into(),
                "prerequisite-unsafe-render".into(),
                "impact-browser-script".into(),
            ],
            edges: vec![
                "edge-entry-persists".into(),
                "edge-state-reaches-browser".into(),
                "edge-source-enables-impact".into(),
            ],
            adapter_families: vec![
                "peritus.source-analysis".into(),
                "peritus.http-api".into(),
                "peritus.browser-client".into(),
            ],
            disposition: ModuleAttackGraphDisposition::Confirmed,
            removed_prerequisite: None,
            replay_digest: confirmed_replay,
            detail: "Exact source, copied-state, and real-browser receipts confirm the three-family chain.".into(),
        },
        ModuleAttackGraphChainObservation {
            id: "chain-counterfactual-without-markup".into(),
            nodes: vec![
                "entry-unauthenticated-store".into(),
                "effect-persisted-markup".into(),
                "impact-browser-script".into(),
            ],
            edges: vec!["edge-entry-persists".into(), "edge-state-reaches-browser".into()],
            adapter_families: vec!["peritus.http-api".into(), "peritus.browser-client".into()],
            disposition: ModuleAttackGraphDisposition::Broken,
            removed_prerequisite: Some("effect-persisted-markup".into()),
            replay_digest: counterfactual_evidence.clone(),
            detail: "Replacing attacker markup with an ordinary note removed the signal while the same store/read path remained live.".into(),
        },
        ModuleAttackGraphChainObservation {
            id: "chain-invented-cross-tenant".into(),
            nodes: vec!["entry-unauthenticated-store".into(), "impact-browser-script".into()],
            edges: vec!["edge-invented-cross-tenant".into()],
            adapter_families: vec!["peritus.identity-access".into()],
            disposition: ModuleAttackGraphDisposition::Rejected,
            removed_prerequisite: None,
            replay_digest: invented_evidence.clone(),
            detail: "No identity/access receipt supports the proposed cross-tenant edge, so search rejected the chain.".into(),
        },
    ];
    let deduplication = vec![ModuleAttackGraphDeduplicationObservation {
        root_cause_id: "root-unsafe-stored-markup-rendering".into(),
        member_nodes: vec![
            "prerequisite-unsafe-render".into(),
            "effect-persisted-markup".into(),
            "impact-browser-script".into(),
        ],
        retained_entry_points: vec!["entry-unauthenticated-store".into()],
        retained_impacts: vec!["impact-browser-script".into()],
        rationale: "Group symptoms only when they share the exact unsafe-render source preimage; retain independently evidenced entry and impact nodes.".into(),
    }];
    let inspected_evidence = vec![
        source_evidence.clone(),
        entry_evidence,
        state_evidence.clone(),
        impact_evidence.clone(),
        counterfactual_evidence.clone(),
    ];
    let skeptic = skeptic(&nodes, &edges, &chains, inspected_evidence)?;
    let replays = vec![
        replay(
            "peritus.source-analysis",
            "exact-preimage-replacement",
            repaired_text.contains("VULNERABLE = False")
                && !repaired_text.contains("VULNERABLE = True"),
            &source_evidence,
            "The repaired copy selects the escaped rendering branch from the exact vulnerable preimage.",
        ),
        replay(
            "peritus.http-api",
            "legitimate-store-retained",
            repaired_store.response_status == 200
                && repaired_store.changed_state_keys.iter().any(|key| key == "comment"),
            &repaired_store.response_digest,
            "The repaired twin still accepted and persisted an ordinary application write.",
        ),
        replay(
            "peritus.browser-client",
            "stored-script-blocked",
            !repaired_browser.signal_observed && repaired_browser.stored_text == ATTACK_PAYLOAD,
            &repaired_evidence,
            "The repaired twin rendered the stored value as text without executing it.",
        ),
    ];
    let repair = review_repair(
        &vulnerable.service_path,
        &vulnerable.service_digest,
        &repaired.service_digest,
        diff_bytes,
        replays,
    )?;
    let operations_executed = 3_u64
        .saturating_add(vulnerable_browser.actions_executed)
        .saturating_add(counterfactual_browser.actions_executed)
        .saturating_add(repaired_browser.actions_executed);
    let campaign_digest = digest(
        &serde_json::to_vec(&json!({
            "suite": SUITE_VERSION,
            "identity": identity,
            "source": vulnerable.source_snapshot,
            "nodes": nodes,
            "edges": edges,
            "chains": chains,
            "deduplication": deduplication,
            "skeptic": skeptic,
            "repair": repair,
        }))
        .map_err(|error| error.to_string())?,
    );
    let observation = ModuleAttackGraphObservation {
        schema: 1,
        source_snapshot: vulnerable.source_snapshot,
        adapter_version: ADAPTER_VERSION.into(),
        suite_version: SUITE_VERSION.into(),
        vulnerable_laboratory_id: request.vulnerable_laboratory_id.clone(),
        repaired_laboratory_id: request.repaired_laboratory_id.clone(),
        nodes,
        edges,
        chains,
        deduplication,
        skeptic,
        repair,
        operations_executed,
        campaign_digest,
        gaps: vec![
            "The initial graph profile proves one stored-content chain across exact source, private HTTP, and isolated-browser adapters; other adapter combinations require registered graph profiles.".into(),
            "The repaired twin is accepted only because the host binds its complete replacement bytes to the vulnerable preimage and replays the declared source, HTTP, and browser obligations.".into(),
            "Graph search is bounded to admitted host receipts; it does not infer unsupported causal edges from naming, model output, or temporal proximity.".into(),
            "Cloud, distributed-system, public-network, non-browser client, and privileged-host chains remain unexamined.".into(),
        ],
    };
    let bytes = serde_json::to_vec_pretty(&observation).map_err(|error| error.to_string())?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > request.maximum_artifact_bytes {
        return Err("attack-graph observation exceeds its admitted artifact bound".into());
    }
    if allow_retained {
        write_private(&staging.path().join("observation.json"), &bytes)?;
        let destination = root.join(retained_id);
        fs::rename(staging.keep(), &destination)
            .map_err(|error| format!("retain attack-graph campaign: {error}"))?;
    }
    Ok(observation)
}

fn validate(request: &ModuleAttackGraphCampaignRequest) -> Result<(), String> {
    if request.schema != 1 || request.profile != PROFILE {
        return Err("attack-graph campaigns require schema 1 and the registered profile".into());
    }
    for value in [
        &request.vulnerable_laboratory_id,
        &request.vulnerable_endpoint_handle,
        &request.repaired_laboratory_id,
        &request.repaired_endpoint_handle,
    ] {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("attack-graph campaigns require opaque laboratory identities".into());
        }
    }
    if request.vulnerable_laboratory_id == request.repaired_laboratory_id {
        return Err(
            "attack-graph campaigns require distinct vulnerable and repaired laboratories".into()
        );
    }
    if !(9..=32).contains(&request.maximum_browser_actions)
        || !(24..=64).contains(&request.maximum_requests)
        || !(256 * 1024..=8 * 1024 * 1024).contains(&request.maximum_artifact_bytes)
    {
        return Err("attack-graph campaign bounds are outside the registered profile".into());
    }
    Ok(())
}

fn store(
    laboratory: &Broker,
    laboratory_id: &str,
    endpoint_handle: &str,
    value: &str,
) -> Result<http_api::Exchange, String> {
    let body =
        serde_json::to_string(&json!({"comment": value})).map_err(|error| error.to_string())?;
    laboratory.http_exchange(
        laboratory_id,
        endpoint_handle,
        &http_api::WireRequest {
            method: "POST".into(),
            target: "/store-comment".into(),
            headers: vec![
                ("host".into(), "laboratory.invalid".into()),
                ("content-type".into(), "application/json".into()),
                ("content-length".into(), body.len().to_string()),
                ("connection".into(), "close".into()),
            ],
            body,
            websocket_message: None,
            maximum_request_bytes: 64 * 1024,
            maximum_response_bytes: 256 * 1024,
        },
    )
}

fn browse(
    laboratory: &Broker,
    request: &ModuleAttackGraphCampaignRequest,
    vulnerable: bool,
    directory: impl AsRef<Path>,
) -> Result<BrowserObservation, String> {
    let (laboratory_id, endpoint_handle) = if vulnerable {
        (&request.vulnerable_laboratory_id, &request.vulnerable_endpoint_handle)
    } else {
        (&request.repaired_laboratory_id, &request.repaired_endpoint_handle)
    };
    let session =
        laboratory.browser_session(laboratory_id, endpoint_handle, request.maximum_requests)?;
    let raw = crate::runtime_browser::attack_graph(
        directory.as_ref(),
        &session.target_socket,
        request.maximum_browser_actions / 3,
        request.maximum_requests / 3,
    )?;
    let observation: BrowserObservation = serde_json::from_value(raw)
        .map_err(|error| format!("attack-graph browser returned invalid evidence: {error}"))?;
    if observation.schema != 1
        || observation.browser_identity.is_empty()
        || observation.status != 200
        || observation.rendered_html_digest.len() != 64
        || observation.traffic_digest.len() != 64
        || observation.screenshot_digest.len() != 64
        || observation.screenshot_bytes == 0
        || observation.actions_executed > u64::from(request.maximum_browser_actions / 3)
        || observation.requests_observed > u64::from(request.maximum_requests / 3)
    {
        return Err("attack-graph browser violated the registered result contract".into());
    }
    let _ = observation.off_scope_requests_blocked;
    Ok(observation)
}

fn node(
    id: &str,
    kind: ModuleAttackGraphNodeKind,
    adapter_id: &str,
    label: &str,
    evidence_digest: &str,
) -> ModuleAttackGraphNodeObservation {
    ModuleAttackGraphNodeObservation {
        id: id.into(),
        kind,
        adapter_id: adapter_id.into(),
        label: label.into(),
        evidence_digest: evidence_digest.into(),
    }
}

#[allow(clippy::too_many_arguments)]
fn edge(
    id: &str,
    from: &str,
    to: &str,
    relation: &str,
    adapter_id: &str,
    evidence_digest: &str,
    supported: bool,
) -> ModuleAttackGraphEdgeObservation {
    ModuleAttackGraphEdgeObservation {
        id: id.into(),
        from: from.into(),
        to: to.into(),
        relation: relation.into(),
        adapter_id: adapter_id.into(),
        evidence_digest: evidence_digest.into(),
        supported,
    }
}

fn replay(
    adapter_id: &str,
    case_id: &str,
    passed: bool,
    evidence_digest: &str,
    detail: &str,
) -> ModuleAttackGraphReplayObservation {
    ModuleAttackGraphReplayObservation {
        adapter_id: adapter_id.into(),
        case_id: case_id.into(),
        passed,
        evidence_digest: evidence_digest.into(),
        detail: detail.into(),
    }
}

fn skeptic(
    nodes: &[ModuleAttackGraphNodeObservation],
    edges: &[ModuleAttackGraphEdgeObservation],
    chains: &[ModuleAttackGraphChainObservation],
    inspected_evidence: Vec<String>,
) -> Result<ModuleAttackGraphSkepticObservation, String> {
    let confirmed = chains
        .iter()
        .find(|chain| chain.disposition == ModuleAttackGraphDisposition::Confirmed)
        .ok_or_else(|| "skeptic received no confirmed chain".to_string())?;
    let accepted = confirmed.adapter_families.len() >= 3
        && confirmed
            .edges
            .iter()
            .all(|id| edges.iter().any(|edge| edge.id == *id && edge.supported))
        && confirmed.nodes.iter().all(|id| nodes.iter().any(|node| node.id == *id))
        && inspected_evidence.iter().all(|digest| digest.len() == 64);
    let rejected_edges =
        edges.iter().filter(|edge| !edge.supported).map(|edge| edge.id.clone()).collect::<Vec<_>>();
    if !accepted || rejected_edges.is_empty() {
        return Err(
            "independent graph skeptic rejected the supported chain or admitted an invented edge"
                .into(),
        );
    }
    Ok(ModuleAttackGraphSkepticObservation {
        reviewer: "peritus-red-team/attack-graph-skeptic-2026-10-24.1".into(),
        accepted,
        inspected_evidence,
        rejected_edges,
        detail: "Every confirmed edge has an exact raw receipt; the unsupported identity edge was excluded from search.".into(),
    })
}

fn review_repair(
    target_path: &str,
    original_digest: &str,
    patched_digest: &str,
    diff_bytes: Vec<u8>,
    replays: Vec<ModuleAttackGraphReplayObservation>,
) -> Result<ModuleAttackGraphRepairObservation, String> {
    let legitimate_behavior_preserved = replays.iter().any(|replay| {
        replay.adapter_id == "peritus.http-api"
            && replay.case_id == "legitimate-store-retained"
            && replay.passed
    });
    let review_accepted = replays.len() == 3
        && replays.iter().all(|replay| replay.passed && replay.evidence_digest.len() == 64)
        && legitimate_behavior_preserved
        && original_digest != patched_digest
        && !diff_bytes.is_empty();
    if !review_accepted {
        return Err("independent patch reviewer rejected the exact diff or replay matrix".into());
    }
    Ok(ModuleAttackGraphRepairObservation {
        target_path: target_path.into(),
        original_digest: original_digest.into(),
        patched_digest: patched_digest.into(),
        diff_artifact: digest(&diff_bytes),
        diff_bytes,
        addressed_chains: vec!["chain-stored-browser-execution".into()],
        prerequisites: vec![
            "exact vulnerable preimage".into(),
            "ready repaired disposable twin".into(),
            "source, HTTP, and browser adapter receipts".into(),
        ],
        replays,
        legitimate_behavior_preserved,
        reviewer: "peritus-red-team/attack-graph-patch-reviewer-2026-10-24.1".into(),
        review_accepted,
        review_detail: "The reviewer inspected the exact diff and source, HTTP, and real-browser replay receipts; the stored-content feature remained observable without script execution.".into(),
    })
}

fn unified_diff(path: &str, original: &[u8], replacement: &[u8]) -> Result<Vec<u8>, String> {
    let original = std::str::from_utf8(original)
        .map_err(|_| "attack-graph copy repair requires UTF-8 source")?;
    let replacement = std::str::from_utf8(replacement)
        .map_err(|_| "attack-graph copy repair requires UTF-8 replacement")?;
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
    if path.is_symlink() {
        return Err("attack-graph artifact path is a symbolic link".into());
    }
    fs::write(path, bytes).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    let value = Sha256::digest(bytes);
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(64);
    for byte in value {
        text.push(DIGITS[usize::from(byte >> 4)] as char);
        text.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    text
}
