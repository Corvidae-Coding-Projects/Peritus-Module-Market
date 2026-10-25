//! Honest Markdown, JSON, SARIF, patch, and replay-bundle publication.

use crate::{
    Error, invalid,
    records::*,
    state::{ObservationState, PHASE, State},
};
use peritus_plugin_sdk::ModuleAttachment;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{fs, io::Write as _, path::Path};

#[derive(Serialize)]
struct ReportSnapshot<'a> {
    schema: u16,
    phase: u8,
    campaign: &'a CampaignRecord,
    active_scope: Option<&'a ScopeRevisionRecord>,
    active_snapshot: Option<&'a SourceSnapshotRecord>,
    coverage: &'a [CoverageRecord],
    target_profiles: &'a [TargetProfileRecord],
    application_components: &'a [ApplicationComponentRecord],
    application_surfaces: &'a [ApplicationSurfaceRecord],
    trust_boundaries: &'a [TrustBoundaryRecord],
    identity_configurations: &'a [IdentityConfigurationRecord],
    security_properties: &'a [SecurityPropertyRecord],
    methods: &'a [MethodRecord],
    coverage_cells: &'a [CoverageCellRecord],
    hypotheses: &'a [HypothesisRecord],
    observations: Vec<ObservationSummary<'a>>,
    jobs: &'a [JobRecord],
    job_evidence: &'a [EvidenceRecord],
    job_receipts: &'a [peritus_plugin_sdk::ModuleJobReceipt],
    adapter_statuses: &'a [peritus_plugin_sdk::ModuleAdapterStatus],
    adapter_receipts: &'a [peritus_plugin_sdk::ModuleAdapterExecutionReceipt],
    adapter_errors: &'a [String],
    analysis_observations: &'a [peritus_plugin_sdk::ModuleSourceAnalysisObservation],
    analysis_evidence: &'a [EvidenceRecord],
    api_observations: &'a [peritus_plugin_sdk::ModuleHttpApiObservation],
    api_evidence: &'a [EvidenceRecord],
    browser_observations: &'a [peritus_plugin_sdk::ModuleBrowserObservation],
    browser_evidence: &'a [EvidenceRecord],
    identity_observations: &'a [peritus_plugin_sdk::ModuleIdentityAccessObservation],
    identity_evidence: &'a [EvidenceRecord],
    file_fuzz_observations: &'a [peritus_plugin_sdk::ModuleFileFuzzObservation],
    file_fuzz_evidence: &'a [EvidenceRecord],
    workflow_observations: &'a [peritus_plugin_sdk::ModuleWorkflowObservation],
    workflow_evidence: &'a [EvidenceRecord],
    boundary_observations: &'a [peritus_plugin_sdk::ModuleBoundaryObservation],
    boundary_evidence: &'a [EvidenceRecord],
    attack_graph_observations: &'a [peritus_plugin_sdk::ModuleAttackGraphObservation],
    attack_graph_evidence: &'a [EvidenceRecord],
    laboratory_statuses: &'a [peritus_plugin_sdk::ModuleLaboratoryStatus],
    laboratory_receipts: &'a [peritus_plugin_sdk::ModuleLaboratoryReceipt],
    laboratory_errors: &'a [String],
    findings: &'a [FindingRecord],
    patches: &'a [PatchRecord],
    patch_receipts: &'a [peritus_plugin_sdk::ModulePatchReceipt],
    reviews: &'a [ReviewRecord],
    investigation: &'a crate::state::InvestigationState,
    repair: &'a crate::state::RepairState,
    journey: &'a crate::state::JourneyState,
    original_verification: &'a Option<peritus_plugin_sdk::ScopedSourceVerification>,
    limitations: Vec<String>,
}

#[derive(Serialize)]
struct ReplayBundle<'a> {
    schema: u16,
    phase: u8,
    campaign: &'a CampaignRecord,
    source_snapshot: Option<&'a SourceSnapshotRecord>,
    findings: &'a [FindingRecord],
    patches: &'a [PatchRecord],
    patch_plans: &'a [crate::state::PatchPlan],
    patch_receipts: &'a [peritus_plugin_sdk::ModulePatchReceipt],
    job_receipts: &'a [peritus_plugin_sdk::ModuleJobReceipt],
    analysis_observations: &'a [peritus_plugin_sdk::ModuleSourceAnalysisObservation],
    analysis_evidence: &'a [EvidenceRecord],
    api_observations: &'a [peritus_plugin_sdk::ModuleHttpApiObservation],
    api_evidence: &'a [EvidenceRecord],
    browser_observations: &'a [peritus_plugin_sdk::ModuleBrowserObservation],
    browser_evidence: &'a [EvidenceRecord],
    identity_observations: &'a [peritus_plugin_sdk::ModuleIdentityAccessObservation],
    identity_evidence: &'a [EvidenceRecord],
    file_fuzz_observations: &'a [peritus_plugin_sdk::ModuleFileFuzzObservation],
    file_fuzz_evidence: &'a [EvidenceRecord],
    workflow_observations: &'a [peritus_plugin_sdk::ModuleWorkflowObservation],
    workflow_evidence: &'a [EvidenceRecord],
    boundary_observations: &'a [peritus_plugin_sdk::ModuleBoundaryObservation],
    boundary_evidence: &'a [EvidenceRecord],
    attack_graph_observations: &'a [peritus_plugin_sdk::ModuleAttackGraphObservation],
    attack_graph_evidence: &'a [EvidenceRecord],
    laboratory_statuses: &'a [peritus_plugin_sdk::ModuleLaboratoryStatus],
    laboratory_receipts: &'a [peritus_plugin_sdk::ModuleLaboratoryReceipt],
    laboratory_errors: &'a [String],
    reviews: &'a [ReviewRecord],
    journey: &'a crate::state::JourneyState,
    original_verification: &'a Option<peritus_plugin_sdk::ScopedSourceVerification>,
    patch_artifacts: Vec<String>,
    replay_instructions: Vec<String>,
    limitations: Vec<String>,
}

#[derive(Serialize)]
struct ObservationSummary<'a> {
    id: &'a RecordId,
    path: &'a str,
    source_digest: &'a str,
    range_start: u64,
    range_end: u64,
    artifact_digest: &'a str,
    state: ObservationState,
    reuse_count: u64,
}

pub(crate) fn publish_report(
    root: &Path,
    state: &mut State,
    kind: &str,
) -> Result<ModuleAttachment, Error> {
    let mut limitations = vec![
        "Coverage is bounded to the recorded source observations, hypotheses, inputs and host receipts; it is not a clean-codebase claim.".into(),
        "An examined family or unsuccessful probe is not evidence that the application is secure.".into(),
        "The current trusted runtime adapter observes exact canary disclosure. Other interfaces remain analysis-supported, inconclusive, blocked or unexamined unless a suitable module adapter produced evidence.".into(),
        "Patch validation is bounded to the recorded attack, legitimate, malformed and adjacent cases. It is not proof against every input or security property.".into(),
        "The current application laboratories prove the copied Linux Python key/value and HTTP/API fixture lifecycles. They do not establish coverage for other stacks, stores, operating systems, or unregistered security classes.".into(),
        "The Phase 12 static analyzer provides pinned deterministic source, dependency, secret and configuration leads. Its bounded same-file flow and finite advisory data do not replace compiler-semantic analyzers, full advisory services, or runtime proof.".into(),
        "The Phase 13 HTTP/API adapter covers its pinned HTTP/1.1, live OpenAPI, REST, GraphQL, WebSocket and JSON-RPC suite. HTTP/2, HTTP/3, TLS, arbitrary schema generation, multipart bodies and authentication remain separate gaps.".into(),
        "The Phase 14 browser adapter covers a pinned Chromium client-security suite. Other browser engines and application-specific authenticated workflows remain explicit gaps.".into(),
        "The Phase 15 identity adapter covers a pinned laboratory-generated multi-user topology. External identity onboarding, federation, hardware authenticators, and application-specific permission semantics remain explicit gaps.".into(),
        "The Phase 16 file/parser adapter covers registered Linux Python HTTP twins, real filesystem/TAR effects, a small PH16 grammar, behavioral edges, and one CPython-to-libc child fault. Arbitrary grammars, other ABIs, and compiler sanitizer builds remain explicit gaps.".into(),
        "The Phase 17 workflow adapter covers one pinned approval/accounting domain and one retained deterministic two-worker schedule. Application-specific contracts, arbitrary schedules, distributed stores, and non-Linux runtimes remain explicit gaps.".into(),
        "The Phase 18 boundary adapter covers module-private Unix-socket DNS, HTTP and TLS peers, deny-all IP networking, lab certificates, copied policy/privilege checks, and copied-application authority cases. Live cloud providers, host-privileged runtimes, arbitrary protocols, public PKI, and production infrastructure remain explicit gaps.".into(),
        "The Phase 19 attack graph proves one stored-content chain across exact source, private HTTP, and isolated Chromium receipts. Other cross-adapter combinations, distributed systems, public networks, non-browser clients, and privileged-host chains remain explicit gaps until separately registered profiles execute them.".into(),
        "The Phase 20 source-bound journey coordinates source analysis, real entry-point execution, cleanup, and explicit per-adapter gap accounting one host operation at a time. Final exports are generated only after that journey reaches its durable terminal state. Class-specific execution still requires independently derived compatible application contracts. It does not claim universal vulnerability coverage, expert parity, or support for unregistered adapters and target technologies.".into(),
    ];
    if !matches!(state.investigation.stage, crate::state::InvestigationStage::Complete) {
        limitations.push(format!(
            "This is a partial report from investigation stage `{:?}`; pending work remains durable.",
            state.investigation.stage
        ));
    }
    if state.journey.stage != crate::state::JourneyStage::Complete {
        limitations.push(format!(
            "This is a partial complete-journey report from stage `{:?}` at step {}/{}; pending, blocked, or skipped work remains explicit.",
            state.journey.stage,
            state.journey.cursor,
            state.journey.steps.len()
        ));
    }
    let snapshot = ReportSnapshot {
        schema: 1,
        phase: PHASE,
        campaign: &state.campaign,
        active_scope: state.scopes.last(),
        active_snapshot: state.snapshots.last(),
        coverage: &state.coverage,
        target_profiles: &state.target_profiles,
        application_components: &state.application_components,
        application_surfaces: &state.application_surfaces,
        trust_boundaries: &state.trust_boundaries,
        identity_configurations: &state.identity_configurations,
        security_properties: &state.security_properties,
        methods: &state.methods,
        coverage_cells: &state.coverage_cells,
        hypotheses: &state.hypotheses,
        observations: state
            .observations
            .iter()
            .map(|observation| ObservationSummary {
                id: &observation.record.id,
                path: &observation.path,
                source_digest: &observation.source_digest,
                range_start: observation.range_start,
                range_end: observation.range_end,
                artifact_digest: &observation.record.artifact_digest,
                state: observation.state,
                reuse_count: observation.reuse_count,
            })
            .collect(),
        jobs: &state.jobs,
        job_evidence: &state.job_evidence,
        job_receipts: &state.job_receipts,
        adapter_statuses: &state.adapter_statuses,
        adapter_receipts: &state.adapter_receipts,
        adapter_errors: &state.adapter_errors,
        analysis_observations: &state.analysis_observations,
        analysis_evidence: &state.analysis_evidence,
        api_observations: &state.api_observations,
        api_evidence: &state.api_evidence,
        browser_observations: &state.browser_observations,
        browser_evidence: &state.browser_evidence,
        identity_observations: &state.identity_observations,
        identity_evidence: &state.identity_evidence,
        file_fuzz_observations: &state.file_fuzz_observations,
        file_fuzz_evidence: &state.file_fuzz_evidence,
        workflow_observations: &state.workflow_observations,
        workflow_evidence: &state.workflow_evidence,
        boundary_observations: &state.boundary_observations,
        boundary_evidence: &state.boundary_evidence,
        attack_graph_observations: &state.attack_graph_observations,
        attack_graph_evidence: &state.attack_graph_evidence,
        laboratory_statuses: &state.laboratory_statuses,
        laboratory_receipts: &state.laboratory_receipts,
        laboratory_errors: &state.laboratory_errors,
        findings: &state.findings,
        patches: &state.patches,
        patch_receipts: &state.patch_receipts,
        reviews: &state.reviews,
        investigation: &state.investigation,
        repair: &state.repair,
        journey: &state.journey,
        original_verification: &state.original_verification,
        limitations: limitations.clone(),
    };
    let json = serde_json::to_vec_pretty(&snapshot)?;
    let markdown = markdown(state, &limitations);
    let sarif = serde_json::to_vec_pretty(&sarif(state, &limitations))?;
    let json_digest = digest(&json);
    let markdown_digest = digest(markdown.as_bytes());
    let sarif_digest = digest(&sarif);
    let reports = root.join("reports");
    let json_relative = format!("reports/{json_digest}.json");
    let markdown_relative = format!("reports/{markdown_digest}.md");
    let sarif_relative = format!("reports/{sarif_digest}.sarif");
    publish_bytes(&reports.join(format!("{json_digest}.json")), &json)?;
    publish_bytes(&reports.join(format!("{markdown_digest}.md")), markdown.as_bytes())?;
    publish_bytes(&reports.join(format!("{sarif_digest}.sarif")), &sarif)?;
    let patches = root.join("patches");
    let mut patch_artifacts = Vec::new();
    for plan in &state.repair.plans {
        let (Some(artifact), Some(bytes)) = (&plan.diff_artifact, &plan.diff_bytes) else {
            continue;
        };
        if digest(bytes) != *artifact {
            return Err(invalid(
                "retained patch bytes do not match their module-authored identity",
            ));
        }
        publish_bytes(&patches.join(format!("{artifact}.patch")), bytes)?;
        if !patch_artifacts.contains(artifact) {
            patch_artifacts.push(artifact.clone());
        }
    }
    for observation in &state.attack_graph_observations {
        let repair = &observation.repair;
        if digest(&repair.diff_bytes) != repair.diff_artifact {
            return Err(invalid(
                "attack-graph diff bytes do not match their module-authored identity",
            ));
        }
        publish_bytes(
            &patches.join(format!("{}.patch", repair.diff_artifact)),
            &repair.diff_bytes,
        )?;
        if !patch_artifacts.contains(&repair.diff_artifact) {
            patch_artifacts.push(repair.diff_artifact.clone());
        }
    }
    let bundle = ReplayBundle {
        schema: 1,
        phase: PHASE,
        campaign: &state.campaign,
        source_snapshot: state.snapshots.last(),
        findings: &state.findings,
        patches: &state.patches,
        patch_plans: &state.repair.plans,
        patch_receipts: &state.patch_receipts,
        job_receipts: &state.job_receipts,
        analysis_observations: &state.analysis_observations,
        analysis_evidence: &state.analysis_evidence,
        api_observations: &state.api_observations,
        api_evidence: &state.api_evidence,
        browser_observations: &state.browser_observations,
        browser_evidence: &state.browser_evidence,
        identity_observations: &state.identity_observations,
        identity_evidence: &state.identity_evidence,
        file_fuzz_observations: &state.file_fuzz_observations,
        file_fuzz_evidence: &state.file_fuzz_evidence,
        workflow_observations: &state.workflow_observations,
        workflow_evidence: &state.workflow_evidence,
        boundary_observations: &state.boundary_observations,
        boundary_evidence: &state.boundary_evidence,
        attack_graph_observations: &state.attack_graph_observations,
        attack_graph_evidence: &state.attack_graph_evidence,
        laboratory_statuses: &state.laboratory_statuses,
        laboratory_receipts: &state.laboratory_receipts,
        laboratory_errors: &state.laboratory_errors,
        reviews: &state.reviews,
        journey: &state.journey,
        original_verification: &state.original_verification,
        patch_artifacts: patch_artifacts.clone(),
        replay_instructions: vec![
            "Reopen this bundle in a fresh Peritus process with the exact source snapshot named here.".into(),
            "Re-run the original finding receipt against the immutable original target; do not substitute target, evaluator, canary or proof rule.".into(),
            "Apply patch files in recorded order only to a new disposable copy after verifying each expected preimage digest.".into(),
            "Replay every recorded attack, legitimate, malformed and adjacent case through the named module adapter and compare module-authored receipts.".into(),
            "For HTTP/API findings, replay the exact minimized method, target, headers and body digest against a freshly launched laboratory and compare response plus copied-state receipts.".into(),
            "For browser findings, replay the exact case digest in a fresh isolated browser context and compare browser, traffic, artifact and copied-state receipts.".into(),
            "For identity/access findings, recreate the opaque laboratory identity topology and replay the credential-free case digest through module-private credentials; compare lifecycle, differential response, copied-state, and redaction receipts.".into(),
            "For file/parser findings, recreate the exact disposable laboratory, decode the retained bounded base64 input, and compare the fixed canary, response, native-signal, behavioral-edge, resource, and campaign digests.".into(),
            "For workflow findings, recreate the exact starting snapshot and identity/action order, replay the retained schedule when present, and compare host-read final state plus documented invariant disposition. Proposed invariants and unrelated transport failures never prove a finding.".into(),
            "For boundary findings, recreate the exact disposable laboratory and module-private peer set, replay the retained case digest, and compare copied state, peer counters, TLS outcomes, policy effects, and containing-host authority invariants. Blocked live-cloud and host-privileged cases remain gaps.".into(),
            "For attack graphs, recreate both exact ready laboratory twins, verify the vulnerable preimage and replacement digests, replay every source, HTTP, and browser obligation, remove the recorded prerequisite to reproduce the broken path, and reject every edge without a retained receipt.".into(),
            "Re-read the original workspace and compare every included path, byte digest and executable bit with the starting snapshot.".into(),
        ],
        limitations: limitations.clone(),
    };
    let bundle_bytes = serde_json::to_vec_pretty(&bundle)?;
    let bundle_digest = digest(&bundle_bytes);
    let bundles = root.join("bundles");
    publish_bytes(&bundles.join(format!("{bundle_digest}.json")), &bundle_bytes)?;
    let prior = state.reports.last().map(|report| report.id.clone());
    let revision = u64::try_from(state.reports.len())
        .map_err(|_| invalid("report history is too large"))?
        .checked_add(1)
        .ok_or_else(|| invalid("report revision overflow"))?;
    state.reports.push(ReportRecord {
        schema: RECORD_SCHEMA_VERSION,
        id: RecordId::new(RecordKind::Report, format!("report-{revision}-{:.12}", markdown_digest))
            .map_err(invalid)?,
        campaign: state.campaign.id.clone(),
        revision,
        findings: state.findings.iter().map(|finding| finding.id.clone()).collect(),
        reviews: state.reviews.iter().map(|review| review.id.clone()).collect(),
        markdown_artifact: markdown_digest,
        json_artifact: json_digest,
        sarif_artifact: Some(sarif_digest),
        reproduction_bundle_artifact: Some(bundle_digest.clone()),
        patch_artifacts,
        limitations,
        supersedes: prior,
    });
    Ok(if kind == "report-json" {
        ModuleAttachment { name: "Red Team report (JSON)".into(), path: json_relative }
    } else if kind == "sarif" {
        ModuleAttachment { name: "Red Team report (SARIF 2.1.0)".into(), path: sarif_relative }
    } else if kind == "bundle" {
        ModuleAttachment {
            name: "Red Team replay bundle (JSON)".into(),
            path: format!("bundles/{bundle_digest}.json"),
        }
    } else {
        ModuleAttachment { name: "Red Team report (Markdown)".into(), path: markdown_relative }
    })
}

fn sarif(state: &State, limitations: &[String]) -> Value {
    let mut rules = serde_json::Map::new();
    let mut results = Vec::new();
    for observation in &state.analysis_observations {
        for finding in &observation.findings {
            rules.entry(finding.rule_id.clone()).or_insert_with(|| {
                json!({
                    "id": finding.rule_id,
                    "name": finding.rule_id,
                    "shortDescription": {"text": finding.message},
                    "properties": {
                        "evidenceBoundary": "source-analysis-lead",
                        "analyzerSet": observation.analyzer_set_version,
                        "ruleSet": observation.rule_set_version
                    }
                })
            });
            let mut region = json!({});
            if let Some(line) = finding.line {
                region = json!({"startLine": line});
            }
            results.push(json!({
                "ruleId": finding.rule_id,
                "level": sarif_level(&format!("{:?}", finding.severity)),
                "message": {"text": format!("{} This is a source-analysis lead, not runtime confirmation.", finding.message)},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": finding.path},
                    "region": region
                }}],
                "partialFingerprints": {"peritusRawResult": observation.raw_result_digest},
                "properties": {
                    "classification": "analysis_lead",
                    "reachability": format!("{:?}", finding.reachability),
                    "sourceSnapshot": observation.source_snapshot
                }
            }));
        }
    }
    for finding in &state.findings {
        if matches!(
            finding.classification,
            FindingClassification::Refuted | FindingClassification::NotReproduced
        ) {
            continue;
        }
        let hypothesis =
            state.hypotheses.iter().find(|hypothesis| hypothesis.id.value == finding.hypothesis_id);
        let rule_id = format!("peritus/{}", finding.hypothesis_id);
        let description = hypothesis.map_or_else(
            || "Evidence-bounded Red Team finding".into(),
            |hypothesis| hypothesis.security_property.clone(),
        );
        rules.entry(rule_id.clone()).or_insert_with(|| {
            json!({
                "id": rule_id,
                "name": finding.hypothesis_id,
                "shortDescription": {"text": description},
                "properties": {"evidenceBoundary": "skeptically-adjudicated"}
            })
        });
        results.push(json!({
            "ruleId": rule_id,
            "level": match finding.classification {
                FindingClassification::Confirmed => "error",
                FindingClassification::AnalysisSupported => "warning",
                FindingClassification::Inconclusive | FindingClassification::Blocked => "note",
                FindingClassification::Refuted | FindingClassification::NotReproduced => "none",
            },
            "message": {"text": format!("{} Classification: {:?}.", description, finding.classification)},
            "partialFingerprints": {"peritusFindingId": finding.id.value},
            "properties": {
                "classification": format!("{:?}", finding.classification),
                "evidence": finding.evidence.iter().map(|id| id.value.as_str()).collect::<Vec<_>>(),
                "review": finding.review.as_ref().map(|id| id.value.as_str()),
                "sourceSnapshot": finding.source_snapshot.value
            }
        }));
    }
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Peritus Red Team",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": "https://github.com/Corvidae-Coding-Projects/Peritus-Module-Market",
                "rules": rules.into_values().collect::<Vec<_>>()
            }},
            "results": results,
            "properties": {
                "phase": PHASE,
                "campaign": state.campaign.id.value,
                "limitations": limitations,
                "journeyStage": format!("{:?}", state.journey.stage),
                "expertParityClaim": false
            }
        }]
    })
}

fn sarif_level(severity: &str) -> &'static str {
    match severity.to_ascii_lowercase().as_str() {
        "critical" | "high" | "error" => "error",
        "medium" | "warning" => "warning",
        _ => "note",
    }
}

fn markdown(state: &State, limitations: &[String]) -> String {
    let scope = state.scopes.last();
    let snapshot = state.snapshots.last();
    let current = state
        .observations
        .iter()
        .filter(|observation| observation.state == ObservationState::Current)
        .count();
    let invalidated = state.observations.len().saturating_sub(current);
    let reused = state.observations.iter().map(|observation| observation.reuse_count).sum::<u64>();
    let mut text = format!(
        "# Red Team investigation and repair report\n\n## Scope and source\n\n- Campaign: `{}`\n- Scope revision: `{}`\n- Source snapshot: `{}`\n- Manifest artifact: `{}`\n- Investigation stage: `{:?}`\n- Repair stage: `{:?}`\n- Complete-journey stage: `{:?}`\n- Complete-journey progress: {}/{}\n- Complete-journey gaps/failures: {}\n- Skill digest: `{}`\n- Provider routes: {}\n- Current source observations: {current}\n- Invalidated source observations: {invalidated}\n- Reused identical observations: {reused}\n- Module worker operations: {}\n- Trusted job receipts: {}\n- Managed-adapter receipts: {}\n- Static-analysis observations: {}\n- HTTP/API observations: {}\n- Real-browser observations: {}\n- Identity/access observations: {}\n- File/parser observations: {}\n- Workflow/state observations: {}\n- Boundary/authority observations: {}\n- Attack-graph observations: {}\n- Application-laboratory receipts: {}\n- Adjudicated findings: {}\n- Patch revisions: {}\n\n",
        state.campaign.id.value,
        scope.map_or("not selected", |record| record.id.value.as_str()),
        snapshot.map_or("not captured", |record| record.snapshot_digest.as_str()),
        snapshot.map_or("not captured", |record| record.manifest_artifact.as_str()),
        state.investigation.stage,
        state.repair.stage,
        state.journey.stage,
        state.journey.cursor,
        state.journey.steps.len(),
        state.journey.failures.len(),
        if state.investigation.skill_digest.is_empty() {
            "not started"
        } else {
            &state.investigation.skill_digest
        },
        if state.investigation.provider_routes.is_empty() {
            "not observed".into()
        } else {
            state
                .investigation
                .provider_routes
                .iter()
                .map(|route| format!("{}={}/{}", route.role, route.provider, route.model))
                .collect::<Vec<_>>()
                .join(", ")
        },
        state.jobs.len(),
        state.job_receipts.len(),
        state.adapter_receipts.len(),
        state.analysis_observations.len(),
        state.api_observations.len(),
        state.browser_observations.len(),
        state.identity_observations.len(),
        state.file_fuzz_observations.len(),
        state.workflow_observations.len(),
        state.boundary_observations.len(),
        state.attack_graph_observations.len(),
        state.laboratory_receipts.len(),
        state.findings.len(),
        state.patches.len(),
    );
    text.push_str("## Target profiles and surface graph\n\n");
    if state.target_profiles.is_empty() {
        text.push_str("No target profile or surface graph has been compiled.\n\n");
    }
    for profile in &state.target_profiles {
        text.push_str(&format!(
            "- Profile `{}` (`{:?}`): interfaces {}; unavailable claims {}\n",
            profile.name,
            profile.kind,
            if profile.interfaces.is_empty() {
                "none".into()
            } else {
                profile.interfaces.join(", ")
            },
            if profile.unavailable_claims.is_empty() {
                "none".into()
            } else {
                profile.unavailable_claims.join(", ")
            },
        ));
    }
    for surface in &state.application_surfaces {
        text.push_str(&format!(
            "- Surface `{}` (`{:?}` / `{:?}`): entry `{}`; paths {}; invalidated by `{}`\n",
            surface.name,
            surface.kind,
            surface.state,
            surface.entry_point,
            surface.source_paths.join(", "),
            surface.invalidated_by.as_deref().unwrap_or("none"),
        ));
    }
    text.push_str("\n## Method-backed coverage\n\nEvery cell names an exact surface, identity/configuration, property and method. `unexamined` and `blocked` are gaps, not clean results.\n\n");
    for method in &state.methods {
        text.push_str(&format!(
            "- Method `{}` — `{:?}`; operation `{}`; {}\n",
            method.name,
            method.availability,
            method.operation.as_deref().unwrap_or("none"),
            method.limitation,
        ));
    }
    for cell in &state.coverage_cells {
        text.push_str(&format!(
            "- Cell `{}`: `{}` / surface `{}` / identity `{}` / property `{}` / method `{}` — `{:?}`: {}\n",
            cell.id.value,
            cell.family,
            cell.surface.value,
            cell.identity_configuration.value,
            cell.security_property.value,
            cell.method.value,
            cell.state,
            cell.reason,
        ));
    }
    text.push_str("\n## Retained source evidence\n\n");
    if state.observations.is_empty() {
        text.push_str("No source ranges have been observed.\n");
    } else {
        for observation in &state.observations {
            text.push_str(&format!(
                "- `{}` bytes {}..{} — `{:?}`; source `{}`; artifact `{}`; reuse {}\n",
                observation.path,
                observation.range_start,
                observation.range_end,
                observation.state,
                observation.source_digest,
                observation.record.artifact_digest,
                observation.reuse_count,
            ));
        }
    }
    text.push_str("\n## Deterministic source analysis\n\nEvery item in this section is a source lead, not runtime confirmation.\n\n");
    if state.analysis_observations.is_empty() {
        text.push_str("No static-analysis receipt has been admitted.\n");
    }
    for observation in &state.analysis_observations {
        text.push_str(&format!(
            "### Snapshot `{}`\n\n- Analyzer set: `{}`\n- Rule set: `{}`\n- Advisory data: `{}`\n- Raw result: `{}`\n- Files / bytes: {} / {}\n- Components / raw matches / deduplicated leads: {} / {} / {}\n- Truncated: {}\n\n",
            observation.source_snapshot,
            observation.analyzer_set_version,
            observation.rule_set_version,
            observation.advisory_dataset_version,
            observation.raw_result_digest,
            observation.scanned_files,
            observation.scanned_bytes,
            observation.components.len(),
            observation.raw_findings.len(),
            observation.findings.len(),
            observation.truncated,
        ));
        for finding in &observation.findings {
            text.push_str(&format!(
                "- `{}` · `{:?}` · `{:?}` · `{}`{} — {}\n",
                finding.rule_id,
                finding.severity,
                finding.reachability,
                finding.path,
                finding.line.map_or_else(String::new, |line| format!(":{line}")),
                finding.message,
            ));
        }
    }
    text.push_str("\n## HTTP/API real-interface campaigns\n\nOnly module-oracle violations are runtime-confirmed. Rejections and unreachable routes remain distinct outcomes.\n\n");
    if state.api_observations.is_empty() {
        text.push_str("No HTTP/API campaign receipt has been admitted.\n");
    }
    for observation in &state.api_observations {
        text.push_str(&format!(
            "### Laboratory `{}`\n\n- Adapter / suite: `{}` / `{}`\n- OpenAPI schema: `{}`\n- Routes / exchanges / violations: {} / {} / {}\n- Traffic: `{}`\n- Final state: `{}`\n\n",
            observation.laboratory_id,
            observation.adapter_version,
            observation.suite_version,
            observation.imported_schema_digest.as_deref().unwrap_or("not imported"),
            observation.routes.len(),
            observation.requests_executed,
            observation.findings.len(),
            observation.traffic_digest,
            observation.final_state_digest,
        ));
        for finding in &observation.findings {
            text.push_str(&format!(
                "- `{:?}` · `{}` · case `{}` · replay `{}` — {}\n",
                finding.severity,
                finding.category,
                finding.case_id,
                finding.replay_request_digest,
                finding.message,
            ));
        }
        text.push_str("\nDiscovered routes:\n\n");
        for route in &observation.routes {
            text.push_str(&format!(
                "- `{}` — methods {}; parameters {}; source `{}`\n",
                route.path,
                if route.methods.is_empty() { "none".into() } else { route.methods.join(", ") },
                if route.parameters.is_empty() {
                    "none".into()
                } else {
                    route.parameters.join(", ")
                },
                route.source,
            ));
        }
        text.push_str("\nExecuted request ledger:\n\n");
        for case in &observation.cases {
            text.push_str(&format!(
                "- `{}` · `{:?}` · `{:?}` · `{} {}` · request `{}` · response {} / `{}` · state `{}` → `{}` — {}\n",
                case.id,
                case.protocol,
                case.disposition,
                case.request.method,
                case.request.target,
                case.request.digest,
                case.response.status,
                case.response.digest,
                case.state_before_digest,
                case.state_after_digest,
                case.oracle,
            ));
        }
        text.push_str("\nKnown adapter gaps:\n\n");
        for gap in &observation.gaps {
            text.push_str(&format!("- {gap}\n"));
        }
    }
    text.push_str("\n## Real-browser client campaigns\n\nBrowser findings require a real client effect and the pinned module oracle. Rejected behavior is retained separately from runtime-confirmed violations.\n\n");
    if state.browser_observations.is_empty() {
        text.push_str("No real-browser campaign receipt has been admitted.\n");
    }
    for observation in &state.browser_observations {
        text.push_str(&format!(
            "### Laboratory `{}`\n\n- Browser: `{}`\n- Adapter / suite: `{}` / `{}`\n- Actions / requests / violations: {} / {} / {}\n- Coverage nodes / artifacts: {} / {}\n- Fresh-context isolation: {}\n- Off-scope requests blocked: {}\n- Traffic: `{}`\n- Final state: `{}`\n\n",
            observation.laboratory_id,
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
            observation.traffic_digest,
            observation.final_state_digest,
        ));
        for finding in &observation.findings {
            text.push_str(&format!(
                "- `{:?}` · `{}` · case `{}` · replay `{}` — {}\n",
                finding.severity,
                finding.category,
                finding.case_id,
                finding.replay_digest,
                finding.message,
            ));
        }
        text.push_str("\nExecuted browser cases:\n\n");
        for case in &observation.cases {
            text.push_str(&format!(
                "- `{}` · `{:?}` · replay `{}` · reset replay {} — {}; {}\n",
                case.id,
                case.disposition,
                case.replay_digest,
                case.replayed_after_reset,
                case.browser_effect,
                case.server_effect,
            ));
        }
        text.push_str("\nKnown browser adapter gaps:\n\n");
        for gap in &observation.gaps {
            text.push_str(&format!("- {gap}\n"));
        }
    }
    text.push_str("\n## Authentication, session, authorization, and tenancy campaigns\n\nCredentials remain module-private. Reports retain only opaque identities, lifecycle/differential oracles, copied-state facts, and the redaction record.\n\n");
    if state.identity_observations.is_empty() {
        text.push_str("No identity/access campaign receipt has been admitted.\n");
    }
    for observation in &state.identity_observations {
        text.push_str(&format!(
            "### Laboratory `{}`\n\n- Adapter / suite: `{}` / `{}`\n- Opaque identities / session transitions: {} / {}\n- Operations / cases / violations: {} / {} / {}\n- Credential values checked: {}\n- Request / response credential fields withheld: {} / {}\n- Provider projection clean: {}\n- Projection digest: `{}`\n- Traffic: `{}`\n- Final state: `{}`\n\n",
            observation.laboratory_id,
            observation.adapter_version,
            observation.suite_version,
            observation.identities.len(),
            observation.session_transitions.len(),
            observation.operations_executed,
            observation.cases.len(),
            observation.findings.len(),
            observation.redaction.credential_values_checked,
            observation.redaction.request_fields_redacted,
            observation.redaction.response_fields_redacted,
            observation.redaction.provider_projection_clean,
            observation.redaction.projection_digest,
            observation.traffic_digest,
            observation.final_state_digest,
        ));
        for finding in &observation.findings {
            text.push_str(&format!(
                "- `{:?}` · `{}` · case `{}` · replay `{}` — {}\n",
                finding.severity,
                finding.category,
                finding.case_id,
                finding.replay_digest,
                finding.message,
            ));
        }
        text.push_str("\nDifferential and lifecycle case ledger:\n\n");
        for case in &observation.cases {
            text.push_str(&format!(
                "- `{}` · `{:?}` · `{}` → {} · state change {} · replay `{}` — {}\n",
                case.id,
                case.disposition,
                case.operation,
                case.response_status,
                case.state_change_observed,
                case.replay_digest,
                case.oracle,
            ));
        }
        text.push_str("\nKnown identity adapter gaps:\n\n");
        for gap in &observation.gaps {
            text.push_str(&format!("- {gap}\n"));
        }
    }
    text.push_str("\n## File, archive, parser, native-fault, and fuzz campaigns\n\nExact minimized inputs are retained as bounded base64. Filesystem effects and native signals are host-observed; behavioral edges are not represented as compiler source coverage.\n\n");
    if state.file_fuzz_observations.is_empty() {
        text.push_str("No file/parser campaign receipt has been admitted.\n");
    }
    for observation in &state.file_fuzz_observations {
        text.push_str(&format!(
            "### Laboratory `{}`\n\n- Adapter / suite: `{}` / `{}`\n- Seed / corpus: `{}` / `{}`\n- Generated / retained cases / findings: {} / {} / {}\n- Coverage model / edges / digest: `{}` / {} / `{}`\n- Native instrumentation: {}\n- Compiler sanitizer active: {}\n- Operations / request bytes / response bytes / wall ms: {} / {} / {} / {}\n- Crash groups / laboratory remained ready: {} / {}\n- Campaign / final state: `{}` / `{}`\n\n",
            observation.laboratory_id,
            observation.adapter_version,
            observation.suite_version,
            observation.seed,
            observation.corpus_digest,
            observation.generated_cases,
            observation.cases.len(),
            observation.findings.len(),
            observation.instrumentation.coverage_model,
            observation.instrumentation.coverage_edges,
            observation.instrumentation.coverage_digest,
            observation.instrumentation.native_fault_instrumentation,
            observation.instrumentation.compiler_sanitizer_active,
            observation.resources.operations,
            observation.resources.request_bytes,
            observation.resources.response_bytes,
            observation.resources.wall_millis,
            observation.crash_groups,
            observation.resources.laboratory_remained_ready,
            observation.campaign_digest,
            observation.final_state_digest,
        ));
        for finding in &observation.findings {
            text.push_str(&format!(
                "- `{:?}` · `{}` · case `{}` · minimized `{}` · replay `{}` — {}\n",
                finding.severity,
                finding.category,
                finding.case_id,
                finding.minimized_input_digest,
                finding.replay_digest,
                finding.message,
            ));
        }
        text.push_str("\nKnown file/parser adapter gaps:\n\n");
        for gap in &observation.gaps {
            text.push_str(&format!("- {gap}\n"));
        }
    }
    text.push_str("\n## Stateful workflow and concurrency campaigns\n\nDocumented requirements and model-proposed candidate invariants retain separate provenance. Only host-observed violations of documented invariants may become findings.\n\n");
    if state.workflow_observations.is_empty() {
        text.push_str("No workflow/state campaign receipt has been admitted.\n");
    }
    for observation in &state.workflow_observations {
        text.push_str(&format!(
            "### Laboratory `{}`\n\n- Adapter / suite: `{}` / `{}`\n- Seed: `{}`\n- Invariants / sequences / findings: {} / {} / {}\n- Real actions: {}\n- Schedule replays / divergent / excluded harness failures: {} / {} / {}\n- Campaign / final state: `{}` / `{}`\n\n",
            observation.laboratory_id,
            observation.adapter_version,
            observation.suite_version,
            observation.seed,
            observation.invariants.len(),
            observation.sequences.len(),
            observation.findings.len(),
            observation.actions_executed,
            observation.nondeterminism.replays,
            observation.nondeterminism.divergent_replays,
            observation.nondeterminism.excluded_harness_failures,
            observation.campaign_digest,
            observation.final_state_digest,
        ));
        for invariant in &observation.invariants {
            text.push_str(&format!(
                "- invariant `{}` · `{:?}` · `{:?}` · oracle `{}` — {}\n",
                invariant.id,
                invariant.origin,
                invariant.disposition,
                invariant.oracle,
                invariant.statement,
            ));
        }
        for finding in &observation.findings {
            text.push_str(&format!(
                "- finding `{:?}` · invariant `{}` · sequence `{}` · replay `{}` — {}\n",
                finding.severity,
                finding.invariant_id,
                finding.sequence_id,
                finding.replay_digest,
                finding.message,
            ));
        }
        text.push_str("\nKnown workflow/state adapter gaps:\n\n");
        for gap in &observation.gaps {
            text.push_str(&format!("- {gap}\n"));
        }
    }
    text.push_str("\n## Private-network, TLS, platform, and delegated-authority campaigns\n\nNetwork peers and certificates are module-created and reachable only through private laboratory sockets. Public, LAN, host-loopback, host-privilege, and host-tool effects must remain zero.\n\n");
    if state.boundary_observations.is_empty() {
        text.push_str("No boundary-authority campaign receipt has been admitted.\n");
    }
    for observation in &state.boundary_observations {
        text.push_str(&format!(
            "### Laboratory `{}`\n\n- Adapter / suite: `{}` / `{}`\n- Operations / cases / findings: {} / {} / {}\n- Private DNS / callbacks / redirects / proxies: {} / {} / {} / {}\n- Forbidden attempts; host-loopback / LAN / external effects: {}; {} / {} / {}\n- TLS handshakes / connection reuse: {} / {}\n- Privilege attempts / host effects / containment held: {} / {} / {}\n- Untrusted directives / copied privileged effects / host authority unchanged: {} / {} / {}\n- Campaign / final state: `{}` / `{}`\n\n",
            observation.laboratory_id,
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
            observation.policy.containment_held,
            observation.authority.untrusted_directives,
            observation.authority.privileged_effects,
            observation.authority.host_authority_unchanged,
            observation.campaign_digest,
            observation.final_state_digest,
        ));
        for finding in &observation.findings {
            text.push_str(&format!(
                "- finding `{:?}` · standards `{}` · case `{}` · replay `{}` — {}\n",
                finding.severity,
                finding.standards.join(", "),
                finding.case_id,
                finding.replay_digest,
                finding.message,
            ));
        }
        text.push_str("\nExecuted boundary cases:\n\n");
        for case in &observation.cases {
            text.push_str(&format!(
                "- `{}` · `{:?}` · `{:?}` · request `{}` · state `{}` → `{}` · replay `{}` — {}\n",
                case.id,
                case.class,
                case.disposition,
                case.request_digest,
                case.state_before_digest,
                case.state_after_digest,
                case.replay_digest,
                case.oracle,
            ));
        }
        text.push_str("\nKnown boundary-authority gaps:\n\n");
        for gap in &observation.gaps {
            text.push_str(&format!("- {gap}\n"));
        }
    }
    text.push_str("\n## Cross-adapter attack graphs and repair replay\n\nOnly edges backed by exact host receipts are admissible. Broken and rejected paths remain visible rather than being silently discarded.\n\n");
    if state.attack_graph_observations.is_empty() {
        text.push_str("No attack-graph campaign receipt has been admitted.\n");
    }
    for observation in &state.attack_graph_observations {
        text.push_str(&format!(
            "### Campaign `{}`\n\n- Adapter / suite: `{}` / `{}`\n- Source snapshot: `{}`\n- Vulnerable / repaired laboratories: `{}` / `{}`\n- Nodes / edges / chains / root-cause groups: {} / {} / {} / {}\n- Operations: {}\n- Skeptic / repair review accepted: {} / {}\n- Legitimate behavior preserved: {}\n- Exact diff: `{}` for `{}`\n\n",
            observation.campaign_digest,
            observation.adapter_version,
            observation.suite_version,
            observation.source_snapshot,
            observation.vulnerable_laboratory_id,
            observation.repaired_laboratory_id,
            observation.nodes.len(),
            observation.edges.len(),
            observation.chains.len(),
            observation.deduplication.len(),
            observation.operations_executed,
            observation.skeptic.accepted,
            observation.repair.review_accepted,
            observation.repair.legitimate_behavior_preserved,
            observation.repair.diff_artifact,
            observation.repair.target_path,
        ));
        text.push_str("Graph nodes:\n\n");
        for node in &observation.nodes {
            text.push_str(&format!(
                "- `{}` · `{:?}` · `{}` · evidence `{}` — {}\n",
                node.id, node.kind, node.adapter_id, node.evidence_digest, node.label,
            ));
        }
        text.push_str("\nGraph edges and searched chains:\n\n");
        for edge in &observation.edges {
            text.push_str(&format!(
                "- edge `{}` · `{}` → `{}` · `{}` · supported {} · evidence `{}`\n",
                edge.id, edge.from, edge.to, edge.adapter_id, edge.supported, edge.evidence_digest,
            ));
        }
        for chain in &observation.chains {
            text.push_str(&format!(
                "- chain `{}` · `{:?}` · families `{}` · removed prerequisite `{}` · replay `{}` — {}\n",
                chain.id,
                chain.disposition,
                chain.adapter_families.join(", "),
                chain.removed_prerequisite.as_deref().unwrap_or("none"),
                chain.replay_digest,
                chain.detail,
            ));
        }
        text.push_str("\nRepair replay matrix:\n\n");
        for replay in &observation.repair.replays {
            text.push_str(&format!(
                "- `{}` / `{}` · passed {} · evidence `{}` — {}\n",
                replay.adapter_id,
                replay.case_id,
                replay.passed,
                replay.evidence_digest,
                replay.detail,
            ));
        }
        text.push_str("\nKnown attack-graph gaps:\n\n");
        for gap in &observation.gaps {
            text.push_str(&format!("- {gap}\n"));
        }
    }
    text.push_str("\n## Module worker operations\n\n");
    if state.jobs.is_empty() {
        text.push_str("No dependency preparation or contained proof has been observed.\n");
    } else {
        for job in &state.jobs {
            let resources = state
                .job_receipts
                .iter()
                .find(|receipt| receipt.job_id == job.host_job_id)
                .map(|receipt| {
                    format!(
                        "memory {} bytes; storage {} bytes; CPU {} ms; wall {} ms; processes {}",
                        receipt.limits.memory_bytes,
                        receipt.limits.storage_bytes,
                        receipt.limits.cpu_millis,
                        receipt.limits.wall_millis,
                        receipt.limits.processes,
                    )
                })
                .unwrap_or_else(|| "resources not observed".into());
            text.push_str(&format!(
                "- `{}` — `{:?}` — `{}` — request `{}` — {}\n",
                job.host_job_id, job.state, job.operation, job.request_digest, resources
            ));
        }
    }
    text.push_str("\n## Disposable application laboratories\n\n");
    if state.laboratory_statuses.is_empty() {
        text.push_str("No copied application laboratory has been created.\n");
    } else {
        for status in &state.laboratory_statuses {
            text.push_str(&format!(
                "- `{}` — `{:?}` — recipe `{}`; requests {}; state `{}`; snapshots {}; receipts {}; cleanup {}; {}\n",
                status.handle.laboratory_id,
                status.phase,
                status.handle.recipe_id,
                status.telemetry.requests,
                status.telemetry.state_digest,
                status.snapshots,
                status.receipts,
                status.cleanup_complete,
                status.detail,
            ));
        }
    }
    for receipt in &state.laboratory_receipts {
        text.push_str(&format!(
            "- Receipt `{}` — app `{}`; service `{}`; backend `{}`; network `{}`; cleanup {}; original unchanged `{}`\n",
            receipt.operation,
            receipt.application_digest,
            receipt.service_digest,
            receipt.isolation_backend,
            receipt.network_policy,
            receipt.process_cleanup_complete,
            receipt
                .original_source_unchanged
                .map_or("not checked".into(), |value| value.to_string()),
        ));
    }
    for error in &state.laboratory_errors {
        text.push_str(&format!("- Retained laboratory error: {error}\n"));
    }
    text.push_str("\n## Hypotheses, probes, and findings\n\n");
    if state.hypotheses.is_empty() {
        text.push_str("No falsifiable hypothesis has been committed yet.\n");
    }
    for hypothesis in &state.hypotheses {
        let plan = state
            .investigation
            .hypothesis_plans
            .iter()
            .find(|plan| plan.hypothesis_id == hypothesis.id.value);
        let finding =
            state.findings.iter().find(|finding| finding.hypothesis_id == hypothesis.id.value);
        text.push_str(&format!(
            "### `{}`\n\n- Family: `{}`\n- Origin: `{:?}`\n- Attacker: {}\n- Entry point: {}\n- Security property: {}\n- Falsifiable observation: {}\n- Classification: `{}`\n",
            hypothesis.id.value,
            plan.map_or("unrecorded", |plan| plan.family.as_str()),
            plan.map(|plan| plan.origin),
            hypothesis.attacker,
            hypothesis.entry_point,
            hypothesis.security_property,
            hypothesis.falsifiable_observation,
            finding.map_or("pending".into(), |finding| format!("{:?}", finding.classification)),
        ));
        for probe in state
            .investigation
            .probes
            .iter()
            .filter(|probe| probe.hypothesis_id == hypothesis.id.value)
        {
            text.push_str(&format!(
                "- Probe `{}`: `{:?}`; target `{}`; argv elements: {}; stdin template: `{}`; environment values: {}; changed dimension: {}; host job `{}`; {}\n",
                probe.id,
                probe.state,
                probe.target_path,
                probe.arguments.len(),
                probe.stdin_digest.as_deref().unwrap_or("none"),
                if probe.environment_digests.is_empty() {
                    "none".into()
                } else {
                    probe.environment_digests
                        .iter()
                        .map(|(name, value)| format!("{name}=sha256:{value}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                },
                probe.changed_dimension,
                probe.host_job_id.as_deref().unwrap_or("not submitted"),
                probe.detail,
            ));
        }
        if let Some(finding) = finding
            && let Some(review) =
                state.reviews.iter().find(|review| finding.review.as_ref() == Some(&review.id))
        {
            text.push_str(&format!("- Independent skeptical review: {}\n", review.detail));
        }
        text.push('\n');
    }
    text.push_str("## Reuse and progress\n\n");
    text.push_str(&format!(
        "- Manifest pages retained: {}\n- Scoped source reads requested: {}\n- Exact source reads reused: {}\n- Build identities reused: {}\n- Meaningful repeated probes: {}\n",
        state.investigation.reuse.manifest_pages,
        state.investigation.reuse.source_reads_requested,
        state.investigation.reuse.source_reads_reused,
        state.investigation.reuse.builds_reused,
        state.investigation.reuse.probes_repeated,
    ));
    text.push_str("\n## Copy-only patches and replay\n\n");
    if state.repair.plans.is_empty() {
        text.push_str("No copy-only patch plan has been retained.\n");
    }
    for plan in &state.repair.plans {
        text.push_str(&format!(
            "### Finding `{}` · order {}\n\n- Root cause: {}\n- Target: `{}`\n- Expected preimage: `{}`\n- Patch identity: `{}`\n- Diff artifact: `{}`\n- Prerequisites: {}\n- Dependencies: {}\n",
            plan.finding_id,
            plan.order,
            plan.root_cause,
            plan.target_path,
            plan.expected_source_digest,
            plan.patch_digest.as_deref().unwrap_or("not materialized"),
            plan.diff_artifact.as_deref().unwrap_or("not materialized"),
            if plan.prerequisites.is_empty() { "none".into() } else { plan.prerequisites.join("; ") },
            if plan.dependencies.is_empty() { "none".into() } else { plan.dependencies.join(", ") },
        ));
        for case in &plan.cases {
            text.push_str(&format!(
                "- Case `{}` (`{:?}`): `{:?}`; input `{}`; expected stdout `{}`; job `{}`; {}\n",
                case.id,
                case.category,
                case.state,
                case.attacker_input,
                case.expected_stdout_fragment,
                case.host_job_id.as_deref().unwrap_or("not submitted"),
                case.detail,
            ));
        }
        if let Some(diff) = &plan.diff_bytes {
            text.push_str("\n```diff\n");
            text.push_str(&String::from_utf8_lossy(diff).replace("```", "` ` `"));
            text.push_str("```\n\n");
        }
    }
    text.push_str("## Original-workspace proof\n\n");
    if let Some(verification) = &state.original_verification {
        text.push_str(&format!(
            "- Starting snapshot: `{}`\n- Observed manifest: `{}`\n- Unchanged: {}\n- Changed: {}\n- Added: {}\n- Removed: {}\n",
            verification.snapshot_digest,
            verification.observed_manifest_digest,
            verification.unchanged,
            if verification.changed_paths.is_empty() { "none".into() } else { verification.changed_paths.join(", ") },
            if verification.added_paths.is_empty() { "none".into() } else { verification.added_paths.join(", ") },
            if verification.removed_paths.is_empty() { "none".into() } else { verification.removed_paths.join(", ") },
        ));
    } else {
        text.push_str("No final original-workspace byte comparison is retained.\n");
    }
    text.push_str("\n## Limitations\n\n");
    for limitation in limitations {
        text.push_str(&format!("- {limitation}\n"));
    }
    text
}

fn publish_bytes(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let parent = path.parent().ok_or_else(|| invalid("report path has no parent"))?;
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}
