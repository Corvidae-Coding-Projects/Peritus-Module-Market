//! Stage 5 candidate-chain confirmation, skepticism, minimization, and private PoC retention.

use crate::{Error, adapter, digest, invalid, reply, state, state::PendingRequest};
use peritus_plugin_sdk::{
    MODULE_RESEARCH_CONTRACT_VERSION, ModuleAction, ModuleAdapterExecuteRequest,
    ModuleAdapterExecutionReceipt, ModuleHostProfile, ModuleLaboratoryPhase,
    ModuleResearchArtifactClassification, ModuleResearchArtifactIdentity,
    ModuleResearchCapabilityKind, ModuleResearchChainConfirmationObservation,
    ModuleResearchChainConfirmationRequest, ModuleResearchChainDisposition,
    ModuleResearchGraphEdgeDisposition, ModuleResearchGraphRecord, ModuleResearchIdentity,
    ModuleResearchIdentityKind, ModuleResearchPocBundle, ModuleResearchPocState,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
};

const RECEIPT_DECODER: &str = "peritus.attack-graph.decoder@1";
const EXECUTED_BY: &str = "peritus-red-team/attack-graph@1";
const REQUIRED_ADAPTERS: [&str; 3] =
    ["peritus.source-analysis", "peritus.http-api", "peritus.browser-client"];

pub(crate) fn handles(command: &str) -> bool {
    matches!(command, "poc" | "poc-plan" | "poc-history" | "poc-cancel")
        || command == "poc-start"
        || command.starts_with("poc-start ")
}

pub(crate) fn command(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
    command: &str,
) -> Result<ModuleAction, Error> {
    match command {
        "poc" | "poc-plan" => Ok(reply(plan(state), profile, super::actions(state), None)),
        "poc-history" => Ok(reply(history(state), profile, super::actions(state), None)),
        "poc-cancel" => cancel(parameters, profile, state),
        _ => {
            let chain = command.strip_prefix("poc-start").unwrap_or_default().trim();
            start(parameters, profile, state, (!chain.is_empty()).then_some(chain))
        }
    }
}

fn start(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
    selected_chain: Option<&str>,
) -> Result<ModuleAction, Error> {
    if !adapter::supports(profile) {
        return Ok(reply(
            "This Peritus host does not advertise generic isolated module workers. Stage 5 remains blocked; no ambient process, browser, network, or credential fallback was attempted.",
            profile,
            super::actions(state),
            None,
        ));
    }
    if state.pending.is_some() {
        return Err(invalid("settle or cancel the retained host request before starting Stage 5"));
    }
    let runtime = adapter::installed_runtime(state, crate::attack_graph::ADAPTER_ID)
        .ok_or_else(|| invalid("install the registered attack-graph adapter before `poc-start`"))?;
    let graph = active_graph(state)
        .ok_or_else(|| invalid("build and select graph-v2 before starting Stage 5"))?;
    let chain =
        if let Some(id) = selected_chain {
            graph.chains.iter().find(|chain| chain.id == id).ok_or_else(|| {
                invalid("poc-start names no chain in the selected graph-v2 record")
            })?
        } else {
            graph.chains.iter().find(|chain| eligible(graph, chain)).ok_or_else(|| {
                invalid("the selected graph has no fully supported Stage 5 candidate")
            })?
        };
    if !eligible(graph, chain) {
        return Err(invalid(
            "Stage 5 requires one candidate client-script chain with no missing experiment and exact supported receipts across source, HTTP, and browser adapters",
        ));
    }
    if state.research_poc_bundles.iter().any(|bundle| {
        bundle.chain_id == chain.id
            && matches!(
                bundle.state,
                ModuleResearchPocState::Planned | ModuleResearchPocState::Verified
            )
    }) {
        return Err(invalid(
            "this chain already has a planned or verified PoC bundle; inspect `poc-history`",
        ));
    }
    let (vulnerable, safe) = ready_twins(state)?;
    let source_snapshot = state
        .active_snapshot()
        .ok_or_else(|| invalid("Stage 5 has no immutable source snapshot"))?
        .snapshot_digest
        .clone();
    let source = state
        .active_handle()
        .ok_or_else(|| invalid("Stage 5 has no active scoped-source authority"))?;
    if vulnerable.handle.source_snapshot != source_snapshot
        || safe.handle.source_snapshot != source_snapshot
    {
        return Err(invalid("Stage 5 twins do not belong to the active immutable source snapshot"));
    }
    let bundle_id = format!(
        "poc-{}",
        digest(
            format!(
                "stage5-bundle-v2\0{}\0{}\0{}\0{}\0{}\0{}",
                graph.id,
                chain.id,
                source_snapshot,
                vulnerable.handle.laboratory_id,
                safe.handle.laboratory_id,
                state.research_poc_bundles.len(),
            )
            .as_bytes(),
        )
    );
    let request = ModuleResearchChainConfirmationRequest {
        schema: MODULE_RESEARCH_CONTRACT_VERSION,
        graph_id: graph.id.clone(),
        chain_id: chain.id.clone(),
        bundle_id: bundle_id.clone(),
        source_snapshot,
        source,
        vulnerable_laboratory_id: vulnerable.handle.laboratory_id.clone(),
        vulnerable_endpoint_handle: vulnerable.handle.endpoint_handle.clone(),
        safe_laboratory_id: safe.handle.laboratory_id.clone(),
        safe_endpoint_handle: safe.handle.endpoint_handle.clone(),
        profile: crate::runtime_chain_confirmation::PROFILE.into(),
        destination: crate::runtime_chain_confirmation::DESTINATION.into(),
        synthetic_identity: crate::runtime_chain_confirmation::SYNTHETIC_IDENTITY.into(),
        maximum_browser_actions: 12,
        maximum_requests: 36,
        maximum_artifact_bytes: 4 * 1024 * 1024,
    };
    state.research_poc_bundles.push(ModuleResearchPocBundle {
        schema: MODULE_RESEARCH_CONTRACT_VERSION,
        id: bundle_id.clone(),
        chain_id: chain.id.clone(),
        minimizer: identity(
            ModuleResearchIdentityKind::Minimizer,
            crate::runtime_chain_confirmation::MINIMIZER_VERSION,
        ),
        state: ModuleResearchPocState::Planned,
        artifacts: Vec::new(),
        replay: None,
        limitations: vec![
            "Fresh full-chain, broken-prerequisite, safe-twin, skeptic, and standalone PoC replays are pending one bounded host worker.".into(),
        ],
    });
    adapter::execute_confirmation(
        parameters,
        state,
        &bundle_id,
        ModuleAdapterExecuteRequest {
            schema: 1,
            runtime,
            operation: crate::runtime_chain_confirmation::OPERATION.into(),
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
    let result = admit_inner(parameters, profile, state, request, receipt);
    if let Err(error) = &result {
        block_request(state, request, &format!("receipt admission failed closed: {error}"));
        state.pending = None;
        state::save(parameters, state)?;
    }
    result
}

fn admit_inner(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
    request: &ModuleAdapterExecuteRequest,
    receipt: ModuleAdapterExecutionReceipt,
) -> Result<ModuleAction, Error> {
    if request.operation != crate::runtime_chain_confirmation::OPERATION
        || receipt.operation != request.operation
        || receipt.receipt_decoder != RECEIPT_DECODER
        || receipt.executed_by != EXECUTED_BY
        || receipt.input_digest != digest(&serde_json::to_vec(&request.input)?)
    {
        return Err(invalid("Stage 5 receipt has an unregistered or mismatched runtime identity"));
    }
    let input: ModuleResearchChainConfirmationRequest =
        serde_json::from_value(request.input.clone())?;
    let observation: ModuleResearchChainConfirmationObservation =
        serde_json::from_value(receipt.observation.clone())?;
    validate_observation(state, &input, &observation)?;
    let graph = state
        .research_graphs
        .iter()
        .find(|graph| graph.id == input.graph_id)
        .cloned()
        .ok_or_else(|| invalid("Stage 5 graph disappeared before receipt admission"))?;
    let chain = graph
        .chains
        .iter()
        .find(|chain| chain.id == input.chain_id)
        .ok_or_else(|| invalid("Stage 5 chain disappeared before receipt admission"))?;
    if !eligible(&graph, chain) {
        return Err(invalid("Stage 5 chain is no longer eligible for confirmation"));
    }
    let bundle_index = state
        .research_poc_bundles
        .iter()
        .position(|bundle| {
            bundle.id == input.bundle_id
                && bundle.state == ModuleResearchPocState::Planned
                && bundle.chain_id == input.chain_id
        })
        .ok_or_else(|| invalid("Stage 5 receipt does not match one planned PoC bundle"))?;
    let artifacts = write_bundle(parameters, &input, &observation)?;
    state.adapter_receipts.push(receipt.clone());
    let replay = identity(
        ModuleResearchIdentityKind::Receipt,
        &format!(
            "{}:{}:{}",
            crate::runtime_chain_confirmation::OPERATION,
            receipt.input_digest,
            observation.verification_digest,
        ),
    );
    let confirmed = confirmed_graph(graph, &input.chain_id, replay.clone(), &observation)?;
    if !state.research_graphs.iter().any(|graph| graph.id == confirmed.id) {
        state.research_graphs.push(confirmed.clone());
    }
    state.research_active_graph = Some(confirmed.id.clone());
    for artifact in &artifacts {
        if !state
            .research_artifacts
            .iter()
            .any(|existing| existing.relative_private_path == artifact.relative_private_path)
        {
            state.research_artifacts.push(artifact.clone());
        }
    }
    let bundle = &mut state.research_poc_bundles[bundle_index];
    bundle.state = ModuleResearchPocState::Verified;
    bundle.artifacts = artifacts;
    bundle.replay = Some(replay);
    bundle.limitations = observation.limitations.clone();
    let artifact_count = bundle.artifacts.len();
    state.pending = None;
    state::save(parameters, state)?;
    Ok(reply(
        format!(
            "# Stage 5 chain confirmed\n\n- Original graph: `{}`\n- Confirmed graph: `{}`\n- Chain: `{}`\n- PoC bundle: `{}`\n- Fresh full-chain impact: reproduced\n- Removed prerequisite: no impact\n- Safe twin: no impact\n- Independent skeptic: accepted\n- Standalone vulnerable / safe PoC: passed / passed\n- Owner-only artifacts: {}\n- Verification digest: `{}`\n\nThe emitted scripts accept only the exact private Unix destination, exact copied target hashes, and the synthetic credential-free identity. No external delivery occurred.",
            input.graph_id,
            confirmed.id,
            input.chain_id,
            input.bundle_id,
            artifact_count,
            observation.verification_digest,
        ),
        profile,
        super::actions(state),
        None,
    ))
}

pub(crate) fn host_failure(state: &mut state::State, pending: &PendingRequest, detail: &str) {
    let PendingRequest::AdapterExecute { request, .. } = pending else {
        return;
    };
    if request.operation != crate::runtime_chain_confirmation::OPERATION {
        return;
    }
    block_request(state, request, detail);
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
    if request.operation != crate::runtime_chain_confirmation::OPERATION {
        return;
    }
    let Ok(input) =
        serde_json::from_value::<ModuleResearchChainConfirmationRequest>(request.input.clone())
    else {
        return;
    };
    if let Some(bundle) = state.research_poc_bundles.iter_mut().find(|bundle| {
        bundle.id == input.bundle_id && bundle.state == ModuleResearchPocState::Planned
    }) {
        bundle.state = ModuleResearchPocState::Blocked;
        bundle.replay = None;
        bundle.artifacts.clear();
        bundle.limitations = vec![format!(
            "Stage 5 emitted no PoC because fresh replay or minimization failed safely: {}",
            detail.chars().take(2_048).collect::<String>()
        )];
    }
}

fn cancel(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
) -> Result<ModuleAction, Error> {
    let pending = state.pending.clone();
    let Some(pending @ PendingRequest::AdapterExecute { request, .. }) = pending.as_ref() else {
        return Err(invalid("no retained Stage 5 confirmation is available to cancel"));
    };
    if request.operation != crate::runtime_chain_confirmation::OPERATION {
        return Err(invalid("the retained host request is not a Stage 5 confirmation"));
    }
    host_failure(
        state,
        pending,
        "cancelled before receipt admission; owned worker cleanup remains a host obligation",
    );
    state.pending = None;
    state::save(parameters, state)?;
    Ok(reply(
        "Stage 5 was cancelled. The planned bundle is blocked, no incomplete output or PoC artifact was admitted, and a late worker result cannot match retained state.",
        profile,
        super::actions(state),
        None,
    ))
}

fn validate_observation(
    state: &state::State,
    input: &ModuleResearchChainConfirmationRequest,
    observation: &ModuleResearchChainConfirmationObservation,
) -> Result<(), Error> {
    let active_source = state
        .active_handle()
        .ok_or_else(|| invalid("Stage 5 observation has no active scoped-source authority"))?;
    if observation.schema != MODULE_RESEARCH_CONTRACT_VERSION
        || observation.graph_id != input.graph_id
        || observation.chain_id != input.chain_id
        || observation.bundle_id != input.bundle_id
        || observation.source_snapshot != input.source_snapshot
        || observation.minimizer_version != crate::runtime_chain_confirmation::MINIMIZER_VERSION
        || observation.poc_script_digest != digest(crate::runtime_browser::RESEARCH_POC.as_bytes())
        || observation.verification_digest.len() != 64
        || observation.limitations.is_empty()
        || input.source != active_source
    {
        return Err(invalid("Stage 5 observation identity or minimizer proof is invalid"));
    }
    crate::attack_graph::validate_observation(state, &observation.full_replay)?;
    if observation.full_replay.vulnerable_laboratory_id != input.vulnerable_laboratory_id
        || observation.full_replay.repaired_laboratory_id != input.safe_laboratory_id
        || !observation.full_replay.skeptic.accepted
        || !observation.full_replay.chains.iter().any(|chain| {
            chain.disposition == peritus_plugin_sdk::ModuleAttackGraphDisposition::Confirmed
        })
        || !observation.full_replay.chains.iter().any(|chain| {
            chain.disposition == peritus_plugin_sdk::ModuleAttackGraphDisposition::Broken
        })
        || !observation.full_replay.chains.iter().any(|chain| {
            chain.disposition == peritus_plugin_sdk::ModuleAttackGraphDisposition::Rejected
        })
    {
        return Err(invalid(
            "Stage 5 full replay lacks exact twin, skeptic, counterfactual, or rejection evidence",
        ));
    }
    for (replay, expected) in [(&observation.vulnerable_poc, true), (&observation.safe_poc, false)]
    {
        if replay.schema != MODULE_RESEARCH_CONTRACT_VERSION
            || replay.expected_signal != expected
            || replay.observed_signal != expected
            || replay.browser_identity.is_empty()
            || replay.traffic_digest.len() != 64
            || replay.result_digest.len() != 64
            || replay.requests_observed == 0
            || replay.actions_executed == 0
            || !replay.cleanup_complete
            || !replay.original_source_unchanged
        {
            return Err(invalid("Stage 5 standalone PoC replay evidence is incomplete"));
        }
    }
    Ok(())
}

fn confirmed_graph(
    mut graph: ModuleResearchGraphRecord,
    chain_id: &str,
    replay: ModuleResearchIdentity,
    observation: &ModuleResearchChainConfirmationObservation,
) -> Result<ModuleResearchGraphRecord, Error> {
    graph.id.clear();
    graph.builder =
        identity(ModuleResearchIdentityKind::RoleImplementation, "peritus-chain-confirmation@1");
    let chain = graph
        .chains
        .iter_mut()
        .find(|chain| chain.id == chain_id)
        .ok_or_else(|| invalid("confirmed graph has no selected chain"))?;
    chain.disposition = ModuleResearchChainDisposition::Confirmed;
    chain.missing_experiments.clear();
    chain.replay = Some(replay);
    chain.detail = format!(
        "Fresh full-chain replay `{}` reproduced the harmless impact; the removed prerequisite and exact safe twin did not; the independent skeptic accepted every supported edge and rejected unsupported edges.",
        observation.full_replay.campaign_digest
    );
    graph.gaps.retain(|gap| !gap.contains("Stage 5") && !gap.contains("full-chain replay"));
    graph.gaps.extend(observation.limitations.iter().cloned());
    graph.gaps.sort();
    graph.gaps.dedup();
    graph.id = format!("graph-v2-confirmed-{}", digest(&serde_json::to_vec(&graph)?));
    Ok(graph)
}

fn write_bundle(
    parameters: &Value,
    input: &ModuleResearchChainConfirmationRequest,
    observation: &ModuleResearchChainConfirmationObservation,
) -> Result<Vec<ModuleResearchArtifactIdentity>, Error> {
    if !state::has_digest_id(&input.bundle_id, "poc-") {
        return Err(invalid("Stage 5 PoC bundle identity is not a canonical digest"));
    }
    let relative_root = PathBuf::from("research-artifacts").join(&input.bundle_id);
    let private_root = state::private_root(parameters)?;
    let root = private_root.join(&relative_root);
    if root.exists() {
        return Err(invalid("Stage 5 artifact destination already exists"));
    }
    let script = crate::runtime_browser::RESEARCH_POC.as_bytes();
    let manifest = serde_json::to_vec_pretty(&json!({
        "schema": 2,
        "bundle_id": input.bundle_id,
        "graph_id": input.graph_id,
        "chain_id": input.chain_id,
        "source_snapshot": input.source_snapshot,
        "minimizer": observation.minimizer_version,
        "script_digest": observation.poc_script_digest,
        "destination": input.destination,
        "synthetic_identity": input.synthetic_identity,
        "fixtures": [
            {"name":"vulnerable", "target":observation.vulnerable_poc.target, "expected_signal":true},
            {"name":"safe", "target":observation.safe_poc.target, "expected_signal":false},
        ],
        "invocation": "python3 SCRIPT --target-root EXACT_DISPOSABLE_ROOT --application-path PATH --application-digest SHA256 --service-path PATH --service-digest SHA256 --target-identity SHA256 --destination unix://poc-private/target.sock --synthetic-identity ordinary-user:credential-free --expect vulnerable|safe --browser-executable ABSOLUTE_PATH --output OWNER_ONLY_DIRECTORY --result RESULT_JSON",
        "cleanup_required": true,
        "original_source_unchanged_required": true,
        "verification_digest": observation.verification_digest,
        "limitations": observation.limitations,
    }))?;
    let evidence = serde_json::to_vec_pretty(observation)?;
    let readme = format!(
        "# Private laboratory PoC bundle\n\nBundle: `{}`\n\nThis owner-only bundle replays one harmless canary against exact disposable vulnerable and safe target identities. Read `manifest.json` for literal invocation arguments, fixture identities, expected outcomes, cleanup requirements, and limitations. Run only inside an operator-provided disposable sandbox. Public, LAN, host-loopback, unresolved, credential-bearing, persistent, destructive, or propagating targets are forbidden.\n",
        input.bundle_id
    )
    .into_bytes();
    let specifications = vec![
        (
            "README.md",
            readme.as_slice(),
            "text/markdown",
            ModuleResearchArtifactClassification::PrivateGraphEvidence,
        ),
        (
            "vendor-poc.py",
            script,
            "text/x-python",
            ModuleResearchArtifactClassification::PrivateVendorPoc,
        ),
        (
            "regression-poc.py",
            script,
            "text/x-python",
            ModuleResearchArtifactClassification::MinimalRegressionPoc,
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
        return Err(invalid("Stage 5 artifact parent is not a private directory"));
    }
    set_private_directory(&parent)?;
    let temporary = tempfile::Builder::new().prefix("stage5-").tempdir_in(&parent)?;
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
        let relative = relative_root.join(name);
        let relative = relative
            .to_str()
            .ok_or_else(|| invalid("Stage 5 artifact path is not UTF-8"))?
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

fn eligible(
    graph: &ModuleResearchGraphRecord,
    chain: &peritus_plugin_sdk::ModuleResearchChainRecord,
) -> bool {
    if chain.disposition != ModuleResearchChainDisposition::Candidate
        || chain.goal != ModuleResearchCapabilityKind::ClientScriptExecution
        || !chain.missing_experiments.is_empty()
        || !REQUIRED_ADAPTERS
            .iter()
            .all(|required| chain.adapter_families.iter().any(|adapter| adapter == required))
    {
        return false;
    }
    chain.edges.iter().all(|id| {
        graph.edges.iter().any(|edge| {
            edge.id == *id
                && edge.disposition == ModuleResearchGraphEdgeDisposition::Supported
                && !edge.receipts.is_empty()
        })
    })
}

pub(crate) fn active_graph(state: &state::State) -> Option<&ModuleResearchGraphRecord> {
    crate::capability_graph::current_graph(state)
}

pub(crate) fn ready_twins(
    state: &state::State,
) -> Result<
    (&peritus_plugin_sdk::ModuleLaboratoryStatus, &peritus_plugin_sdk::ModuleLaboratoryStatus),
    Error,
> {
    let mut latest = BTreeMap::new();
    for status in &state.laboratory_statuses {
        latest.insert(status.handle.laboratory_id.as_str(), status);
    }
    let mut vulnerable = None;
    let mut safe = None;
    for binding in &state.runtime_targets {
        let Some(status) = latest.get(binding.laboratory_id.as_str()).copied() else {
            continue;
        };
        if status.phase != ModuleLaboratoryPhase::Ready {
            continue;
        }
        let paths = format!("{}/{}", binding.target.application_path, binding.target.service_path);
        if paths.contains("/vulnerable/") {
            vulnerable = Some(status);
        } else if paths.contains("/safe/") {
            safe = Some(status);
        }
    }
    let vulnerable = vulnerable.ok_or_else(|| {
        invalid("Stage 5 requires one ready module-bound vulnerable HTTP laboratory")
    })?;
    let safe = safe
        .ok_or_else(|| invalid("Stage 5 requires one ready module-bound safe HTTP laboratory"))?;
    if vulnerable.handle.laboratory_id == safe.handle.laboratory_id {
        return Err(invalid("Stage 5 requires distinct vulnerable and safe laboratories"));
    }
    Ok((vulnerable, safe))
}

fn plan(state: &state::State) -> String {
    let Some(graph) = active_graph(state) else {
        return "# Stage 5 chain confirmation plan\n\nNo selected graph-v2 record exists. Build graph-v2 and settle its required Stage 4 experiments before generating a PoC.\n".into();
    };
    let candidates = graph.chains.iter().filter(|chain| eligible(graph, chain)).collect::<Vec<_>>();
    let twins = ready_twins(state).is_ok();
    let adapter = adapter::installed_runtime(state, crate::attack_graph::ADAPTER_ID).is_some();
    let mut text = format!(
        "# Stage 5 chain confirmation plan\n\n- Graph: `{}`\n- Eligible supported candidates: {}\n- Vulnerable and safe twins ready: {}\n- Registered confirmation adapter installed: {}\n- Pending host request: {}\n\n",
        graph.id,
        candidates.len(),
        twins,
        adapter,
        state.pending.is_some(),
    );
    for chain in candidates {
        text.push_str(&format!(
            "- `{}` — goal `{:?}` — adapters {} — edges {} — cost {}\n",
            chain.id,
            chain.goal,
            chain.adapter_families.join(", "),
            chain.edges.len(),
            chain.cost,
        ));
    }
    text.push_str("\n`poc-start [CHAIN_ID]` runs a fresh full replay, removed-prerequisite control, safe twin, independent skeptic, and the exact standalone minimized PoC. It emits owner-only local artifacts and performs no delivery.\n");
    text
}

fn history(state: &state::State) -> String {
    let mut text = String::from("# Stage 5 private PoC history\n\n");
    if state.research_poc_bundles.is_empty() {
        text.push_str("No Stage 5 bundle has been planned or verified.\n");
        return text;
    }
    for bundle in &state.research_poc_bundles {
        text.push_str(&format!(
            "- `{}` — `{:?}` — chain `{}` — artifacts {} — replay `{}`\n",
            bundle.id,
            bundle.state,
            bundle.chain_id,
            bundle.artifacts.len(),
            bundle.replay.as_ref().map_or("none", |identity| identity.digest.as_str()),
        ));
        for limitation in &bundle.limitations {
            text.push_str(&format!("  - {limitation}\n"));
        }
    }
    text
}

pub(crate) fn identity(kind: ModuleResearchIdentityKind, value: &str) -> ModuleResearchIdentity {
    ModuleResearchIdentity {
        schema: MODULE_RESEARCH_CONTRACT_VERSION,
        kind,
        value: value.into(),
        digest: digest(
            format!("research-identity-v2\0{}\0{value}", identity_kind_code(kind)).as_bytes(),
        ),
    }
}

const fn identity_kind_code(kind: ModuleResearchIdentityKind) -> &'static str {
    match kind {
        ModuleResearchIdentityKind::RoleImplementation => "role_implementation",
        ModuleResearchIdentityKind::ExperimentRequest => "experiment_request",
        ModuleResearchIdentityKind::Target => "target",
        ModuleResearchIdentityKind::Authority => "authority",
        ModuleResearchIdentityKind::Subject => "subject",
        ModuleResearchIdentityKind::Oracle => "oracle",
        ModuleResearchIdentityKind::Receipt => "receipt",
        ModuleResearchIdentityKind::GraphRelation => "graph_relation",
        ModuleResearchIdentityKind::Minimizer => "minimizer",
        ModuleResearchIdentityKind::Template => "template",
        ModuleResearchIdentityKind::Artifact => "artifact",
    }
}
