//! Deterministic Stage 2 projection from class-specific trusted evidence into typed primitives.

use crate::{
    Error, boundary_authority, browser_client, file_fuzz, http_api, identity_access,
    records::{EvidenceKind, EvidenceRecord, RECORD_SCHEMA_VERSION},
    source_analysis,
    state::State,
    workflow_state,
};
use peritus_plugin_sdk::{
    MODULE_RESEARCH_CONTRACT_VERSION, ModuleBoundaryClass, ModuleResearchCapabilityDisposition,
    ModuleResearchCapabilityFact, ModuleResearchCapabilityFactKind, ModuleResearchCapabilityKind,
    ModuleResearchCapabilityRecord, ModuleResearchEvidenceBoundary, ModuleResearchIdentity,
    ModuleResearchIdentityKind, ModuleResearchProjectionRejection,
};
use std::collections::{BTreeMap, BTreeSet};

const SOURCE_PROJECTION: &str = "peritus-capability-projection/source-analysis@1";
const HTTP_PROJECTION: &str = "peritus-capability-projection/http-api@1";
const BROWSER_PROJECTION: &str = "peritus-capability-projection/browser-client@1";
const IDENTITY_PROJECTION: &str = "peritus-capability-projection/identity-access@1";
const FILE_PROJECTION: &str = "peritus-capability-projection/file-parser@1";
const WORKFLOW_PROJECTION: &str = "peritus-capability-projection/workflow-state@1";
const BOUNDARY_PROJECTION: &str = "peritus-capability-projection/boundary-authority@1";
const EXPERIMENT_PROJECTION: &str = "peritus-research-experiment-admission@1";
const EXPERIMENT_SOURCE_PREFIX: &str = "experiment:";
const PROJECTED_MARKER: &str = ":projected:";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProjectionSummary {
    pub(crate) projected: usize,
    pub(crate) rejected: usize,
}

/// Rebuilds only Stage 2 projection-owned records from retained class-specific observations.
/// Later experiment-owned capability records are preserved by projection-version namespace.
pub(crate) fn reconcile(state: &mut State) -> ProjectionSummary {
    let mut records = state
        .research_capabilities
        .iter()
        .filter(|record| !record.projection_version.starts_with("peritus-capability-projection/"))
        .cloned()
        .map(|record| (record.id.clone(), record))
        .collect::<BTreeMap<_, _>>();
    let experimentally_admitted = records
        .values()
        .filter(|record| record.projection_version == EXPERIMENT_PROJECTION)
        .filter_map(|record| record.source_record.split_once(PROJECTED_MARKER).map(|(_, id)| id))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();

    project_source(state, &mut records);
    project_http(state, &mut records);
    project_browser(state, &mut records);
    project_identity(state, &mut records);
    project_file(state, &mut records);
    project_workflow(state, &mut records);
    project_boundary(state, &mut records);

    records.retain(|id, record| {
        !record.projection_version.starts_with("peritus-capability-projection/")
            || !experimentally_admitted.contains(id)
    });

    state.research_capabilities = records.into_values().collect();
    ProjectionSummary {
        projected: state
            .research_capabilities
            .iter()
            .filter(|record| record.disposition == ModuleResearchCapabilityDisposition::Projected)
            .count(),
        rejected: state
            .research_capabilities
            .iter()
            .filter(|record| record.disposition == ModuleResearchCapabilityDisposition::Rejected)
            .count(),
    }
}

/// Converts only newly projected, oracle-confirmed primitives into experiment-owned records.
/// The original projection identity is retained in `source_record`, so later deterministic
/// reconciliation suppresses the duplicate projection without trusting model prose.
pub(crate) fn admit_new_from_experiment(
    state: &mut State,
    baseline: &BTreeSet<String>,
    experiment_id: &str,
    experiment_receipt: &ModuleResearchIdentity,
) -> usize {
    let candidates = state
        .research_capabilities
        .iter()
        .filter(|record| {
            !baseline.contains(&record.id)
                && record.disposition == ModuleResearchCapabilityDisposition::Projected
                && record.evidence_boundary == ModuleResearchEvidenceBoundary::RuntimeConfirmed
                && record.capability != ModuleResearchCapabilityKind::Unsupported
                && !record.receipts.is_empty()
        })
        .cloned()
        .collect::<Vec<_>>();
    let mut admitted = Vec::new();
    let mut replaced = BTreeSet::new();
    for mut record in candidates {
        let projected_id = record.id.clone();
        record.projection_version = EXPERIMENT_PROJECTION.into();
        record.source_record =
            format!("{EXPERIMENT_SOURCE_PREFIX}{experiment_id}{PROJECTED_MARKER}{projected_id}");
        record.disposition = ModuleResearchCapabilityDisposition::Admitted;
        record.receipts.push(experiment_receipt.clone());
        record.receipts.sort_by(|left, right| left.digest.cmp(&right.digest));
        record.receipts.dedup_by(|left, right| left.digest == right.digest);
        record.detail = format!(
            "{}; admitted from bounded experiment `{experiment_id}` after the existing class-specific deterministic oracle",
            record.detail
        );
        record.id = format!(
            "capability-{}",
            crate::digest(
                format!(
                    "experiment-capability-v2\0{experiment_id}\0{projected_id}\0{}",
                    experiment_receipt.digest
                )
                .as_bytes()
            )
        );
        replaced.insert(projected_id);
        admitted.push(record);
    }
    state.research_capabilities.retain(|record| !replaced.contains(&record.id));
    let count = admitted.len();
    state.research_capabilities.extend(admitted);
    state.research_capabilities.sort_by(|left, right| left.id.cmp(&right.id));
    count
}

fn project_source(state: &State, records: &mut BTreeMap<String, ModuleResearchCapabilityRecord>) {
    for observation in &state.analysis_observations {
        let adapter_version = format!(
            "{}+{}+{}",
            observation.analyzer_set_version,
            observation.rule_set_version,
            observation.advisory_dataset_version
        );
        let evidence = matching_evidence(
            state,
            &state.analysis_evidence,
            &observation.raw_result_digest,
            EvidenceKind::Analysis,
        );
        let rejection = source_rejection(state, observation, evidence);
        for finding in &observation.findings {
            let capability = map_source(&finding.category);
            let rejection = rejection.clone().or_else(|| {
                (capability == ModuleResearchCapabilityKind::Unsupported).then_some((
                    ModuleResearchProjectionRejection::UnsupportedCapabilityKind,
                    format!("unsupported source-analysis category `{}`", finding.category),
                ))
            });
            let target_value = format!("source:{}", observation.source_snapshot);
            let subject_value = format!("source-path:{}", finding.path);
            let authority_value = format!("scope:source-read:{}", observation.source_snapshot);
            let oracle_value = format!(
                "{}:{}:{}",
                observation.rule_set_version, finding.rule_id, finding.evidence_digest
            );
            let consumes = vec![
                fact(
                    ModuleResearchCapabilityFactKind::SourceSnapshot,
                    &observation.source_snapshot,
                ),
                fact(ModuleResearchCapabilityFactKind::EntryPoint, &finding.path),
                fact(ModuleResearchCapabilityFactKind::Authority, &authority_value),
                fact(ModuleResearchCapabilityFactKind::Oracle, &oracle_value),
            ];
            let produces = vec![fact(
                ModuleResearchCapabilityFactKind::SecurityProperty,
                &format!("source-lead:{}:{}", finding.category, finding.root_cause),
            )];
            insert(
                records,
                build_record(RecordInput {
                    adapter_id: source_analysis::ADAPTER_ID,
                    adapter_version: &adapter_version,
                    projection_version: SOURCE_PROJECTION,
                    source_record: &finding.id,
                    target_value: &target_value,
                    subject_value: &subject_value,
                    authority_before: &authority_value,
                    authority_after: &authority_value,
                    capability,
                    evidence_boundary: ModuleResearchEvidenceBoundary::SourceLead,
                    oracle_value: &oracle_value,
                    evidence,
                    consumes,
                    produces,
                    rejection,
                    detail: format!(
                        "source lead `{}` from pinned rule `{}` remains source-only",
                        finding.id, finding.rule_id
                    ),
                }),
            );
        }
    }
}

fn project_http(state: &State, records: &mut BTreeMap<String, ModuleResearchCapabilityRecord>) {
    for observation in &state.api_observations {
        let evidence = matching_evidence(
            state,
            &state.api_evidence,
            &observation.traffic_digest,
            EvidenceKind::HttpApi,
        );
        let base = runtime_rejection(
            state,
            &observation.source_snapshot,
            &observation.laboratory_id,
            evidence,
            || http_api::validate_observation(state, observation),
        );
        for finding in &observation.findings {
            let Some(case) = observation.cases.iter().find(|case| case.id == finding.case_id)
            else {
                continue;
            };
            let capability = map_http(&finding.category);
            let rejection = unsupported(base.clone(), capability, "HTTP/API", &finding.category);
            let authority = format!("laboratory:{}:application-user", observation.laboratory_id);
            let after = if matches!(
                capability,
                ModuleResearchCapabilityKind::AuthorizationBypass
                    | ModuleResearchCapabilityKind::UnauthorizedApplicationAction
            ) {
                format!("laboratory:{}:unauthorized-action", observation.laboratory_id)
            } else {
                authority.clone()
            };
            let oracle = format!("{}:{}", observation.suite_version, case.oracle);
            insert_runtime(
                records,
                RuntimeRecordInput {
                    adapter_id: "peritus.http-api",
                    adapter_version: &observation.adapter_version,
                    projection_version: HTTP_PROJECTION,
                    source_record: &finding.id,
                    source_snapshot: &observation.source_snapshot,
                    laboratory_id: &observation.laboratory_id,
                    final_state_digest: &observation.final_state_digest,
                    subject: &format!("endpoint:{}", observation.laboratory_id),
                    authority_before: &authority,
                    authority_after: &after,
                    capability,
                    oracle: &oracle,
                    evidence,
                    entry_point: &format!("{} {}", case.request.method, case.request.target),
                    replay: &finding.replay_request_digest,
                    produced: fact(
                        ModuleResearchCapabilityFactKind::TargetState,
                        &format!(
                            "state:{}:changed:{}",
                            case.state_after_digest, finding.state_change_observed
                        ),
                    ),
                    rejection,
                    detail: finding.message.clone(),
                },
            );
        }
    }
}

fn project_browser(state: &State, records: &mut BTreeMap<String, ModuleResearchCapabilityRecord>) {
    for observation in &state.browser_observations {
        let evidence = matching_evidence(
            state,
            &state.browser_evidence,
            &observation.traffic_digest,
            EvidenceKind::BrowserClient,
        );
        let base = runtime_rejection(
            state,
            &observation.source_snapshot,
            &observation.laboratory_id,
            evidence,
            || browser_client::validate_observation(state, observation),
        );
        for finding in &observation.findings {
            let Some(case) = observation.cases.iter().find(|case| case.id == finding.case_id)
            else {
                continue;
            };
            let capability = map_browser(&finding.category);
            let rejection = unsupported(base.clone(), capability, "browser", &finding.category);
            let authority = format!("browser-context:{}:ordinary-user", observation.laboratory_id);
            let oracle = format!("{}:{}", observation.suite_version, case.replay_digest);
            insert_runtime(
                records,
                RuntimeRecordInput {
                    adapter_id: "peritus.browser-client",
                    adapter_version: &observation.adapter_version,
                    projection_version: BROWSER_PROJECTION,
                    source_record: &finding.id,
                    source_snapshot: &observation.source_snapshot,
                    laboratory_id: &observation.laboratory_id,
                    final_state_digest: &observation.final_state_digest,
                    subject: &format!(
                        "browser:{}:{}",
                        observation.laboratory_id, observation.browser_identity
                    ),
                    authority_before: &authority,
                    authority_after: &authority,
                    capability,
                    oracle: &oracle,
                    evidence,
                    entry_point: &case.request_paths.join(","),
                    replay: &finding.replay_digest,
                    produced: fact(
                        ModuleResearchCapabilityFactKind::BrowserEffect,
                        &case.browser_effect,
                    ),
                    rejection,
                    detail: finding.message.clone(),
                },
            );
        }
    }
}

fn project_identity(state: &State, records: &mut BTreeMap<String, ModuleResearchCapabilityRecord>) {
    for observation in &state.identity_observations {
        let evidence = matching_evidence(
            state,
            &state.identity_evidence,
            &observation.traffic_digest,
            EvidenceKind::IdentityAccess,
        );
        let base = runtime_rejection(
            state,
            &observation.source_snapshot,
            &observation.laboratory_id,
            evidence,
            || identity_access::validate_observation(state, observation),
        );
        for finding in &observation.findings {
            let Some(case) = observation.cases.iter().find(|case| case.id == finding.case_id)
            else {
                continue;
            };
            let capability = map_identity(&finding.category);
            let role = observation
                .identities
                .iter()
                .find(|identity| identity.identity_handle == case.actor_identity);
            let subject_rejection = role.is_none().then_some((
                ModuleResearchProjectionRejection::IncompatibleSubjectAuthority,
                "identity finding actor is absent from the credential-free topology".into(),
            ));
            let rejection = unsupported(
                subject_rejection.or_else(|| base.clone()),
                capability,
                "identity/access",
                &finding.category,
            );
            let before = role.map_or_else(
                || format!("identity:{}:unknown", case.actor_identity),
                |identity| {
                    format!(
                        "identity:{}:role:{}:tenant:{}",
                        identity.identity_handle,
                        identity.role,
                        identity.tenant_handle.as_deref().unwrap_or("none")
                    )
                },
            );
            let after = format!(
                "identity:{}:effect:{}:target:{}",
                case.actor_identity,
                finding.category,
                case.target_identity.as_deref().unwrap_or("self")
            );
            let oracle = format!("{}:{}", observation.suite_version, case.oracle);
            insert_runtime(
                records,
                RuntimeRecordInput {
                    adapter_id: "peritus.identity-access",
                    adapter_version: &observation.adapter_version,
                    projection_version: IDENTITY_PROJECTION,
                    source_record: &finding.id,
                    source_snapshot: &observation.source_snapshot,
                    laboratory_id: &observation.laboratory_id,
                    final_state_digest: &observation.final_state_digest,
                    subject: &format!("identity:{}", case.actor_identity),
                    authority_before: &before,
                    authority_after: &after,
                    capability,
                    oracle: &oracle,
                    evidence,
                    entry_point: &case.operation,
                    replay: &finding.replay_digest,
                    produced: fact(ModuleResearchCapabilityFactKind::Authority, &after),
                    rejection,
                    detail: finding.message.clone(),
                },
            );
        }
    }
}

fn project_file(state: &State, records: &mut BTreeMap<String, ModuleResearchCapabilityRecord>) {
    for observation in &state.file_fuzz_observations {
        let evidence = matching_evidence(
            state,
            &state.file_fuzz_evidence,
            &observation.campaign_digest,
            EvidenceKind::FileFuzz,
        );
        let base = runtime_rejection(
            state,
            &observation.source_snapshot,
            &observation.laboratory_id,
            evidence,
            || file_fuzz::validate_observation(state, observation),
        );
        for finding in &observation.findings {
            let Some(case) = observation.cases.iter().find(|case| case.id == finding.case_id)
            else {
                continue;
            };
            let capability = map_file(&finding.category);
            let rejection = unsupported(base.clone(), capability, "file/parser", &finding.category);
            let authority = format!("laboratory:{}:bounded-file-input", observation.laboratory_id);
            let oracle = format!("{}:{}", observation.suite_version, case.oracle);
            let produced = case.boundary_effect.as_ref().map_or_else(
                || {
                    fact(
                        ModuleResearchCapabilityFactKind::TargetState,
                        &format!("parser-fault:{}", case.native_signal.unwrap_or_default()),
                    )
                },
                |effect| fact(ModuleResearchCapabilityFactKind::TargetState, effect),
            );
            insert_runtime(
                records,
                RuntimeRecordInput {
                    adapter_id: "peritus.file-parser",
                    adapter_version: &observation.adapter_version,
                    projection_version: FILE_PROJECTION,
                    source_record: &finding.id,
                    source_snapshot: &observation.source_snapshot,
                    laboratory_id: &observation.laboratory_id,
                    final_state_digest: &observation.final_state_digest,
                    subject: &format!("parser:{}", observation.laboratory_id),
                    authority_before: &authority,
                    authority_after: &authority,
                    capability,
                    oracle: &oracle,
                    evidence,
                    entry_point: &case.operation,
                    replay: &finding.replay_digest,
                    produced,
                    rejection,
                    detail: finding.message.clone(),
                },
            );
        }
    }
}

fn project_workflow(state: &State, records: &mut BTreeMap<String, ModuleResearchCapabilityRecord>) {
    for observation in &state.workflow_observations {
        let evidence = matching_evidence(
            state,
            &state.workflow_evidence,
            &observation.campaign_digest,
            EvidenceKind::WorkflowState,
        );
        let base = runtime_rejection(
            state,
            &observation.source_snapshot,
            &observation.laboratory_id,
            evidence,
            || workflow_state::validate_observation(state, observation),
        );
        for finding in &observation.findings {
            let Some(sequence) =
                observation.sequences.iter().find(|sequence| sequence.id == finding.sequence_id)
            else {
                continue;
            };
            let subjects = sequence.identities.iter().cloned().collect::<BTreeSet<_>>();
            let subject_rejection = subjects.is_empty().then_some((
                ModuleResearchProjectionRejection::IncompatibleSubjectAuthority,
                "workflow finding has no credential-free subject".into(),
            ));
            let rejection = subject_rejection.or_else(|| base.clone());
            let before =
                format!("workflow:{}:actors:{}", observation.laboratory_id, subjects.len());
            let after =
                format!("workflow:{}:violated:{}", observation.laboratory_id, finding.invariant_id);
            let oracle = format!("{}:{}", observation.suite_version, sequence.oracle);
            insert_runtime(
                records,
                RuntimeRecordInput {
                    adapter_id: "peritus.workflow-state",
                    adapter_version: &observation.adapter_version,
                    projection_version: WORKFLOW_PROJECTION,
                    source_record: &finding.id,
                    source_snapshot: &observation.source_snapshot,
                    laboratory_id: &observation.laboratory_id,
                    final_state_digest: &observation.final_state_digest,
                    subject: &format!(
                        "workflow-subjects:{}",
                        subjects.into_iter().collect::<Vec<_>>().join(",")
                    ),
                    authority_before: &before,
                    authority_after: &after,
                    capability: ModuleResearchCapabilityKind::WorkflowInvariantViolation,
                    oracle: &oracle,
                    evidence,
                    entry_point: &sequence
                        .actions
                        .iter()
                        .map(|action| action.operation.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                    replay: &finding.replay_digest,
                    produced: fact(
                        ModuleResearchCapabilityFactKind::SecurityProperty,
                        &finding.invariant_id,
                    ),
                    rejection,
                    detail: finding.message.clone(),
                },
            );
        }
    }
}

fn project_boundary(state: &State, records: &mut BTreeMap<String, ModuleResearchCapabilityRecord>) {
    for observation in &state.boundary_observations {
        let evidence = matching_evidence(
            state,
            &state.boundary_evidence,
            &observation.campaign_digest,
            EvidenceKind::BoundaryAuthority,
        );
        let base = runtime_rejection(
            state,
            &observation.source_snapshot,
            &observation.laboratory_id,
            evidence,
            || boundary_authority::validate_observation(state, observation),
        );
        for finding in &observation.findings {
            let Some(case) = observation.cases.iter().find(|case| case.id == finding.case_id)
            else {
                continue;
            };
            let capability = match case.class {
                ModuleBoundaryClass::PrivateNetwork => {
                    ModuleResearchCapabilityKind::PrivateNetworkBoundaryViolation
                }
                ModuleBoundaryClass::Tls => ModuleResearchCapabilityKind::TlsBoundaryViolation,
                ModuleBoundaryClass::PrivilegePolicy => {
                    ModuleResearchCapabilityKind::PrivilegeBoundaryViolation
                }
                ModuleBoundaryClass::DelegatedAuthority => {
                    ModuleResearchCapabilityKind::DelegatedAuthorityViolation
                }
                ModuleBoundaryClass::PlatformGap => ModuleResearchCapabilityKind::Unsupported,
            };
            let rejection = unsupported(base.clone(), capability, "boundary", &case.id);
            let before = format!("laboratory:{}:declared-policy", observation.laboratory_id);
            let after = if capability == ModuleResearchCapabilityKind::DelegatedAuthorityViolation {
                format!("laboratory:{}:delegated-privilege", observation.laboratory_id)
            } else {
                before.clone()
            };
            let oracle = format!("{}:{}", observation.suite_version, case.oracle);
            insert_runtime(
                records,
                RuntimeRecordInput {
                    adapter_id: "peritus.boundary-authority",
                    adapter_version: &observation.adapter_version,
                    projection_version: BOUNDARY_PROJECTION,
                    source_record: &finding.id,
                    source_snapshot: &observation.source_snapshot,
                    laboratory_id: &observation.laboratory_id,
                    final_state_digest: &observation.final_state_digest,
                    subject: &format!("boundary-subject:{}", observation.laboratory_id),
                    authority_before: &before,
                    authority_after: &after,
                    capability,
                    oracle: &oracle,
                    evidence,
                    entry_point: &case.operation,
                    replay: &finding.replay_digest,
                    produced: fact(
                        ModuleResearchCapabilityFactKind::SecurityProperty,
                        &case.detail,
                    ),
                    rejection,
                    detail: finding.message.clone(),
                },
            );
        }
    }
}

struct RecordInput<'a> {
    adapter_id: &'a str,
    adapter_version: &'a str,
    projection_version: &'a str,
    source_record: &'a str,
    target_value: &'a str,
    subject_value: &'a str,
    authority_before: &'a str,
    authority_after: &'a str,
    capability: ModuleResearchCapabilityKind,
    evidence_boundary: ModuleResearchEvidenceBoundary,
    oracle_value: &'a str,
    evidence: Option<&'a EvidenceRecord>,
    consumes: Vec<ModuleResearchCapabilityFact>,
    produces: Vec<ModuleResearchCapabilityFact>,
    rejection: Option<(ModuleResearchProjectionRejection, String)>,
    detail: String,
}

struct RuntimeRecordInput<'a> {
    adapter_id: &'a str,
    adapter_version: &'a str,
    projection_version: &'a str,
    source_record: &'a str,
    source_snapshot: &'a str,
    laboratory_id: &'a str,
    final_state_digest: &'a str,
    subject: &'a str,
    authority_before: &'a str,
    authority_after: &'a str,
    capability: ModuleResearchCapabilityKind,
    oracle: &'a str,
    evidence: Option<&'a EvidenceRecord>,
    entry_point: &'a str,
    replay: &'a str,
    produced: ModuleResearchCapabilityFact,
    rejection: Option<(ModuleResearchProjectionRejection, String)>,
    detail: String,
}

fn insert_runtime(
    records: &mut BTreeMap<String, ModuleResearchCapabilityRecord>,
    input: RuntimeRecordInput<'_>,
) {
    let target = format!(
        "source:{}:laboratory:{}:state:{}",
        input.source_snapshot, input.laboratory_id, input.final_state_digest
    );
    let consumes = vec![
        fact(ModuleResearchCapabilityFactKind::SourceSnapshot, input.source_snapshot),
        fact(ModuleResearchCapabilityFactKind::Laboratory, input.laboratory_id),
        fact(ModuleResearchCapabilityFactKind::Subject, input.subject),
        fact(ModuleResearchCapabilityFactKind::Authority, input.authority_before),
        fact(ModuleResearchCapabilityFactKind::EntryPoint, input.entry_point),
        fact(ModuleResearchCapabilityFactKind::Input, input.replay),
        fact(ModuleResearchCapabilityFactKind::Oracle, input.oracle),
    ];
    let produces = vec![
        input.produced,
        fact(ModuleResearchCapabilityFactKind::Authority, input.authority_after),
        fact(ModuleResearchCapabilityFactKind::TargetState, input.final_state_digest),
    ];
    insert(
        records,
        build_record(RecordInput {
            adapter_id: input.adapter_id,
            adapter_version: input.adapter_version,
            projection_version: input.projection_version,
            source_record: input.source_record,
            target_value: &target,
            subject_value: input.subject,
            authority_before: input.authority_before,
            authority_after: input.authority_after,
            capability: input.capability,
            evidence_boundary: ModuleResearchEvidenceBoundary::RuntimeConfirmed,
            oracle_value: input.oracle,
            evidence: input.evidence,
            consumes,
            produces,
            rejection: input.rejection,
            detail: input.detail,
        }),
    );
}

fn build_record(input: RecordInput<'_>) -> ModuleResearchCapabilityRecord {
    let rejected = input.rejection.is_some();
    let consumes_material = input
        .consumes
        .iter()
        .map(|fact| format!("{}={}", fact_kind_code(fact.kind), fact.digest))
        .collect::<Vec<_>>()
        .join(":");
    let produces_material = input
        .produces
        .iter()
        .map(|fact| format!("{}={}", fact_kind_code(fact.kind), fact.digest))
        .collect::<Vec<_>>()
        .join(":");
    let evidence_material = input.evidence.map_or_else(
        || "none".into(),
        |record| format!("{}:{}", record.id.value, record.artifact_digest),
    );
    let rejection_material =
        input.rejection.as_ref().map_or("none", |(reason, _)| projection_rejection_code(*reason));
    let material = format!(
        "capability-v2\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
        input.adapter_id,
        input.adapter_version,
        input.projection_version,
        input.source_record,
        input.target_value,
        input.subject_value,
        input.authority_before,
        input.authority_after,
        capability_code(input.capability),
        evidence_boundary_code(input.evidence_boundary),
        input.oracle_value,
        consumes_material,
        produces_material,
        evidence_material,
        rejection_material,
    );
    let id = format!("capability-{}", crate::digest(material.as_bytes()));
    let (rejection_reason, detail) =
        input.rejection.map_or((None, input.detail), |(reason, detail)| (Some(reason), detail));
    ModuleResearchCapabilityRecord {
        schema: MODULE_RESEARCH_CONTRACT_VERSION,
        id,
        adapter_id: input.adapter_id.into(),
        adapter_version: input.adapter_version.into(),
        projection_version: input.projection_version.into(),
        target: identity(ModuleResearchIdentityKind::Target, input.target_value),
        subject: identity(ModuleResearchIdentityKind::Subject, input.subject_value),
        authority_before: identity(ModuleResearchIdentityKind::Authority, input.authority_before),
        authority_after: identity(ModuleResearchIdentityKind::Authority, input.authority_after),
        capability: input.capability,
        consumes: input.consumes,
        produces: input.produces,
        evidence_boundary: if rejected {
            ModuleResearchEvidenceBoundary::Untrusted
        } else {
            input.evidence_boundary
        },
        oracle: identity(ModuleResearchIdentityKind::Oracle, input.oracle_value),
        receipts: input.evidence.into_iter().map(receipt_identity).collect(),
        source_record: input.source_record.into(),
        disposition: if rejected {
            ModuleResearchCapabilityDisposition::Rejected
        } else {
            ModuleResearchCapabilityDisposition::Projected
        },
        rejection_reason,
        detail,
    }
}

fn insert(
    records: &mut BTreeMap<String, ModuleResearchCapabilityRecord>,
    record: ModuleResearchCapabilityRecord,
) {
    records.insert(record.id.clone(), record);
}

fn source_rejection(
    state: &State,
    observation: &peritus_plugin_sdk::ModuleSourceAnalysisObservation,
    evidence: Option<&EvidenceRecord>,
) -> Option<(ModuleResearchProjectionRejection, String)> {
    if state.active_snapshot().map(|snapshot| snapshot.snapshot_digest.as_str())
        != Some(observation.source_snapshot.as_str())
    {
        return Some((
            ModuleResearchProjectionRejection::MissingTargetContinuity,
            "source-analysis observation no longer names the active source snapshot".into(),
        ));
    }
    if evidence.is_none() {
        return Some((
            ModuleResearchProjectionRejection::InsufficientOracleEvidence,
            "source-analysis observation has no exact admitted evidence record".into(),
        ));
    }
    source_analysis::validate_observation(state, observation).err().map(|error| {
        (
            ModuleResearchProjectionRejection::InsufficientOracleEvidence,
            format!("source-analysis oracle rejected the observation: {error}"),
        )
    })
}

fn runtime_rejection(
    state: &State,
    source_snapshot: &str,
    laboratory_id: &str,
    evidence: Option<&EvidenceRecord>,
    validate: impl FnOnce() -> Result<(), Error>,
) -> Option<(ModuleResearchProjectionRejection, String)> {
    if state.active_snapshot().map(|snapshot| snapshot.snapshot_digest.as_str())
        != Some(source_snapshot)
    {
        return Some((
            ModuleResearchProjectionRejection::MissingTargetContinuity,
            "runtime observation no longer names the active source snapshot".into(),
        ));
    }
    let historically_ready = state.laboratory_statuses.iter().any(|status| {
        status.handle.laboratory_id == laboratory_id
            && status.handle.source_snapshot == source_snapshot
            && status.phase == peritus_plugin_sdk::ModuleLaboratoryPhase::Ready
    });
    if !historically_ready {
        return Some((
            ModuleResearchProjectionRejection::StaleLaboratoryIdentity,
            "runtime observation has no matching historically ready laboratory identity".into(),
        ));
    }
    if evidence.is_none() {
        return Some((
            ModuleResearchProjectionRejection::InsufficientOracleEvidence,
            "runtime observation has no exact admitted class-specific evidence record".into(),
        ));
    }
    validate().err().map(|error| {
        (
            ModuleResearchProjectionRejection::InsufficientOracleEvidence,
            format!("class-specific oracle rejected the observation: {error}"),
        )
    })
}

fn matching_evidence<'a>(
    state: &State,
    records: &'a [EvidenceRecord],
    artifact_digest: &str,
    kind: EvidenceKind,
) -> Option<&'a EvidenceRecord> {
    let scope = state.scopes.last()?;
    let snapshot = state.active_snapshot()?;
    records.iter().find(|record| {
        record.schema == RECORD_SCHEMA_VERSION
            && record.kind == kind
            && record.campaign == state.campaign.id
            && record.scope_revision == scope.id
            && record.artifact_digest == artifact_digest
            && record.dependencies.contains(&snapshot.id)
    })
}

fn unsupported(
    existing: Option<(ModuleResearchProjectionRejection, String)>,
    capability: ModuleResearchCapabilityKind,
    adapter: &str,
    category: &str,
) -> Option<(ModuleResearchProjectionRejection, String)> {
    existing.or_else(|| {
        (capability == ModuleResearchCapabilityKind::Unsupported).then_some((
            ModuleResearchProjectionRejection::UnsupportedCapabilityKind,
            format!("unsupported {adapter} capability category `{category}`"),
        ))
    })
}

fn receipt_identity(record: &EvidenceRecord) -> ModuleResearchIdentity {
    identity(
        ModuleResearchIdentityKind::Receipt,
        &format!("{}:{}", record.id.value, record.artifact_digest),
    )
}

fn identity(kind: ModuleResearchIdentityKind, value: &str) -> ModuleResearchIdentity {
    let kind_name = identity_kind_code(kind);
    ModuleResearchIdentity {
        schema: MODULE_RESEARCH_CONTRACT_VERSION,
        kind,
        value: value.into(),
        digest: crate::digest(format!("research-identity-v2\0{kind_name}\0{value}").as_bytes()),
    }
}

fn fact(kind: ModuleResearchCapabilityFactKind, value: &str) -> ModuleResearchCapabilityFact {
    let kind_name = fact_kind_code(kind);
    ModuleResearchCapabilityFact {
        schema: MODULE_RESEARCH_CONTRACT_VERSION,
        kind,
        value: value.into(),
        digest: crate::digest(format!("capability-fact-v2\0{kind_name}\0{value}").as_bytes()),
    }
}

fn map_source(category: &str) -> ModuleResearchCapabilityKind {
    match category {
        "input_interpretation_and_injection"
        | "memory_integers_and_unsafe_interfaces"
        | "browser_and_client_trust"
        | "cryptography_and_key_lifecycle"
        | "dependencies_and_supply_chain"
        | "configuration_secrets_and_observability" => ModuleResearchCapabilityKind::SourceWeakness,
        _ => ModuleResearchCapabilityKind::Unsupported,
    }
}

fn map_http(category: &str) -> ModuleResearchCapabilityKind {
    match category {
        "injection"
        | "parsing"
        | "content-type"
        | "host-header"
        | "redirect"
        | "graphql-introspection" => ModuleResearchCapabilityKind::InputInterpretationViolation,
        "error-disclosure" => ModuleResearchCapabilityKind::SensitiveDataDisclosure,
        "authorization" | "method" => ModuleResearchCapabilityKind::AuthorizationBypass,
        "workflow-replay" => ModuleResearchCapabilityKind::WorkflowInvariantViolation,
        _ => ModuleResearchCapabilityKind::Unsupported,
    }
}

fn map_browser(category: &str) -> ModuleResearchCapabilityKind {
    match category {
        "reflected_xss" | "stored_xss" | "dom_xss" => {
            ModuleResearchCapabilityKind::ClientScriptExecution
        }
        "content_security_policy" | "cookie_policy" | "server_validation" => {
            ModuleResearchCapabilityKind::ClientPolicyViolation
        }
        "origin_validation" | "csrf" => ModuleResearchCapabilityKind::CrossOriginAction,
        _ => ModuleResearchCapabilityKind::Unsupported,
    }
}

fn map_identity(category: &str) -> ModuleResearchCapabilityKind {
    match category {
        "authentication" | "missing_authentication" | "multi_factor_authentication" => {
            ModuleResearchCapabilityKind::AuthenticationBypass
        }
        "ownership"
        | "object_ownership"
        | "vertical_authorization"
        | "adjacent_route_authorization"
        | "anonymous_access" => ModuleResearchCapabilityKind::AuthorizationBypass,
        "tenant_isolation" => ModuleResearchCapabilityKind::TenancyBoundaryCrossing,
        "session_logout"
        | "token_rotation"
        | "session_expiry"
        | "session_revocation"
        | "concurrent_session_revocation"
        | "account_recovery" => ModuleResearchCapabilityKind::SessionLifecycleViolation,
        _ => ModuleResearchCapabilityKind::Unsupported,
    }
}

fn map_file(category: &str) -> ModuleResearchCapabilityKind {
    match category {
        "path_traversal"
        | "symbolic_link"
        | "permission_boundary"
        | "temporary_file"
        | "archive_traversal" => ModuleResearchCapabilityKind::FileBoundaryViolation,
        "structured_parser" | "native_ffi" | "parser" => ModuleResearchCapabilityKind::ParserFault,
        _ => ModuleResearchCapabilityKind::Unsupported,
    }
}

const fn capability_code(kind: ModuleResearchCapabilityKind) -> &'static str {
    match kind {
        ModuleResearchCapabilityKind::SourceWeakness => "source_weakness",
        ModuleResearchCapabilityKind::InputInterpretationViolation => {
            "input_interpretation_violation"
        }
        ModuleResearchCapabilityKind::SensitiveDataDisclosure => "sensitive_data_disclosure",
        ModuleResearchCapabilityKind::UnauthorizedApplicationAction => {
            "unauthorized_application_action"
        }
        ModuleResearchCapabilityKind::ClientScriptExecution => "client_script_execution",
        ModuleResearchCapabilityKind::ClientPolicyViolation => "client_policy_violation",
        ModuleResearchCapabilityKind::CrossOriginAction => "cross_origin_action",
        ModuleResearchCapabilityKind::AuthenticationBypass => "authentication_bypass",
        ModuleResearchCapabilityKind::AuthorizationBypass => "authorization_bypass",
        ModuleResearchCapabilityKind::TenancyBoundaryCrossing => "tenancy_boundary_crossing",
        ModuleResearchCapabilityKind::SessionLifecycleViolation => "session_lifecycle_violation",
        ModuleResearchCapabilityKind::FileBoundaryViolation => "file_boundary_violation",
        ModuleResearchCapabilityKind::ParserFault => "parser_fault",
        ModuleResearchCapabilityKind::WorkflowInvariantViolation => "workflow_invariant_violation",
        ModuleResearchCapabilityKind::PrivateNetworkBoundaryViolation => {
            "private_network_boundary_violation"
        }
        ModuleResearchCapabilityKind::TlsBoundaryViolation => "tls_boundary_violation",
        ModuleResearchCapabilityKind::PrivilegeBoundaryViolation => "privilege_boundary_violation",
        ModuleResearchCapabilityKind::DelegatedAuthorityViolation => {
            "delegated_authority_violation"
        }
        ModuleResearchCapabilityKind::Unsupported => "unsupported",
    }
}

const fn evidence_boundary_code(kind: ModuleResearchEvidenceBoundary) -> &'static str {
    match kind {
        ModuleResearchEvidenceBoundary::SourceLead => "source_lead",
        ModuleResearchEvidenceBoundary::RuntimeConfirmed => "runtime_confirmed",
        ModuleResearchEvidenceBoundary::Untrusted => "untrusted",
    }
}

const fn projection_rejection_code(reason: ModuleResearchProjectionRejection) -> &'static str {
    match reason {
        ModuleResearchProjectionRejection::MissingTargetContinuity => "missing_target_continuity",
        ModuleResearchProjectionRejection::StaleLaboratoryIdentity => "stale_laboratory_identity",
        ModuleResearchProjectionRejection::IncompatibleSubjectAuthority => {
            "incompatible_subject_authority"
        }
        ModuleResearchProjectionRejection::InsufficientOracleEvidence => {
            "insufficient_oracle_evidence"
        }
        ModuleResearchProjectionRejection::UnsupportedCapabilityKind => {
            "unsupported_capability_kind"
        }
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

const fn fact_kind_code(kind: ModuleResearchCapabilityFactKind) -> &'static str {
    match kind {
        ModuleResearchCapabilityFactKind::SourceSnapshot => "source_snapshot",
        ModuleResearchCapabilityFactKind::Laboratory => "laboratory",
        ModuleResearchCapabilityFactKind::EntryPoint => "entry_point",
        ModuleResearchCapabilityFactKind::Subject => "subject",
        ModuleResearchCapabilityFactKind::Authority => "authority",
        ModuleResearchCapabilityFactKind::TargetState => "target_state",
        ModuleResearchCapabilityFactKind::Input => "input",
        ModuleResearchCapabilityFactKind::BrowserEffect => "browser_effect",
        ModuleResearchCapabilityFactKind::SecurityProperty => "security_property",
        ModuleResearchCapabilityFactKind::Oracle => "oracle",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::{RecordId, RecordKind, ScopeRevisionRecord, SourceSnapshotRecord};
    use peritus_plugin_sdk::{
        ModuleBoundaryObservation, ModuleBrowserObservation, ModuleFileFuzzObservation,
        ModuleHttpApiObservation, ModuleIdentityAccessObservation, ModuleLaboratoryStatus,
        ModuleSourceAnalysisObservation, ModuleWorkflowObservation,
    };
    use serde_json::json;

    fn hash(label: &str) -> String {
        crate::digest(label.as_bytes())
    }

    fn base_state() -> State {
        let mut state = State::default();
        let scope_id = RecordId::new(RecordKind::ScopeRevision, "scope-stage2").unwrap();
        let snapshot_id = RecordId::new(RecordKind::SourceSnapshot, "snapshot-stage2").unwrap();
        state.campaign.scope_revision = Some(scope_id.clone());
        state.campaign.source_snapshot = Some(snapshot_id.clone());
        state.scopes.push(ScopeRevisionRecord {
            schema: RECORD_SCHEMA_VERSION,
            id: scope_id.clone(),
            campaign: state.campaign.id.clone(),
            revision: 1,
            source_label: "stage2-fixture".into(),
            attacker_model: "bounded laboratory".into(),
            allowed_effects: vec!["copied_target_only".into()],
            exclusions: Vec::new(),
            supersedes: None,
        });
        state.snapshots.push(SourceSnapshotRecord {
            schema: RECORD_SCHEMA_VERSION,
            id: snapshot_id,
            campaign: state.campaign.id.clone(),
            scope_revision: scope_id,
            source_handle: "source-stage2".into(),
            snapshot_digest: hash("snapshot"),
            manifest_artifact: hash("manifest"),
        });
        state.laboratory_statuses.push(laboratory(&state, "lab-stage2"));
        state
    }

    fn laboratory(state: &State, id: &str) -> ModuleLaboratoryStatus {
        serde_json::from_value(json!({
            "schema": 1,
            "handle": {
                "schema": 1,
                "laboratory_id": id,
                "scope_revision": state.scopes.last().unwrap().id.value,
                "source_snapshot": state.active_snapshot().unwrap().snapshot_digest,
                "recipe_id": "stage2-fixture@1",
                "application_service": "application",
                "backing_service": "service",
                "endpoint_handle": hash("endpoint"),
                "identity_handle": hash("lab-identity"),
                "secret_handle": hash("secret")
            },
            "phase": "ready",
            "telemetry": {
                "requests": 1,
                "input_bytes": 1,
                "output_bytes": 1,
                "state_digest": hash("lab-state"),
                "host_loopback_blocked": true,
                "credential_output_blocked": true
            },
            "snapshots": 1,
            "receipts": 1,
            "detail": "ready",
            "retained_error": null,
            "cleanup_complete": false
        }))
        .unwrap()
    }

    fn evidence(state: &State, kind: EvidenceKind, label: &str, artifact: &str) -> EvidenceRecord {
        EvidenceRecord {
            schema: RECORD_SCHEMA_VERSION,
            id: RecordId::new(RecordKind::Evidence, label).unwrap(),
            campaign: state.campaign.id.clone(),
            scope_revision: state.scopes.last().unwrap().id.clone(),
            kind,
            observation: "adapter oracle evidence".into(),
            artifact_digest: artifact.into(),
            dependencies: vec![state.active_snapshot().unwrap().id.clone()],
        }
    }

    fn seed_all(state: &mut State) {
        let snapshot = state.active_snapshot().unwrap().snapshot_digest.clone();
        let lab = "lab-stage2";
        let source_digest = hash("source-results");
        state.analysis_observations.push(
            serde_json::from_value::<ModuleSourceAnalysisObservation>(json!({
                "schema": 1,
                "source_snapshot": snapshot,
                "analyzer_set_version": "analyzers@1",
                "rule_set_version": "rules@1",
                "advisory_dataset_version": "advisories@1",
                "tools": [], "languages": [], "manifests": [], "components": [],
                "raw_findings": [],
                "findings": [{
                    "id": "source-finding", "category": "input_interpretation_and_injection",
                    "rule_id": "rule-xss", "severity": "high", "path": "app.py", "line": 10,
                    "message": "unescaped input reaches a rendering sink", "root_cause": "render-sink",
                    "evidence_digest": hash("source-evidence"), "redacted": true,
                    "reachability": "runtime_referenced", "evidence_state": "source_lead",
                    "standards": ["CWE-79"], "deduplicated_from": 1
                }],
                "scanned_files": 1, "scanned_bytes": 100,
                "skipped_oversized_files": 0, "skipped_binary_files": 0,
                "truncated": false, "raw_result_digest": source_digest, "gaps": []
            }))
            .unwrap(),
        );
        state.analysis_evidence.push(evidence(
            state,
            EvidenceKind::Analysis,
            "analysis-stage2",
            &source_digest,
        ));

        let http_digest = hash("http-traffic");
        state.api_observations.push(
            serde_json::from_value::<ModuleHttpApiObservation>(json!({
                "schema": 1, "laboratory_id": lab, "source_snapshot": snapshot,
                "adapter_version": "peritus-http-api-2026-10-24.1",
                "suite_version": "peritus-http-api-suite-2026-10-24.1",
                "imported_schema_digest": null, "routes": [],
                "cases": [{
                    "id": "http-injection", "protocol": "rest", "category": "injection",
                    "disposition": "violation",
                    "request": {"method":"GET", "target":"/lookup?id=1", "headers":[], "body":"", "digest":hash("http-request"), "bytes":32},
                    "response": {"status":200, "headers":[], "body":"redacted", "digest":hash("http-response"), "bytes":8, "redacted":true},
                    "state_before_digest":hash("http-before"), "state_after_digest":hash("http-after"),
                    "changed_state_keys":["lookup"], "oracle":"secret-not-disclosed", "minimized":true
                }],
                "findings": [{
                    "id":"http-finding", "case_id":"http-injection", "category":"injection",
                    "severity":"high", "message":"lookup oracle observed prohibited disclosure",
                    "evidence_state":"runtime_confirmed", "state_change_observed":true,
                    "standards":["CWE-89"], "replay_request_digest":hash("http-request")
                }],
                "traffic_digest": http_digest, "requests_executed":1, "request_bytes":32,
                "response_bytes":8, "final_state_digest":hash("http-final"), "gaps":[]
            }))
            .unwrap(),
        );
        state.api_evidence.push(evidence(
            state,
            EvidenceKind::HttpApi,
            "http-stage2",
            &http_digest,
        ));

        let browser_digest = hash("browser-traffic");
        state.browser_observations.push(
            serde_json::from_value::<ModuleBrowserObservation>(json!({
                "schema":1, "laboratory_id":lab, "source_snapshot":snapshot,
                "adapter_version":"peritus-browser-client-2026-10-24.1",
                "suite_version":"peritus-browser-client-suite-2026-10-24.1",
                "browser_identity":"Chromium test",
                "cases":[{"id":"stored-script", "category":"stored_xss", "disposition":"violation",
                    "browser_effect":"stored markup executed", "server_effect":"signal recorded",
                    "request_paths":["/store","/stored"], "replay_digest":hash("browser-replay"),
                    "replayed_after_reset":true}],
                "findings":[{"id":"browser-finding", "case_id":"stored-script", "category":"stored_xss",
                    "severity":"high", "message":"stored script executed", "evidence_state":"runtime_confirmed",
                    "state_change_observed":true, "standards":["CWE-79"], "replay_digest":hash("browser-replay")}],
                "coverage":[], "artifacts":[], "traffic_digest":browser_digest,
                "requests_observed":2, "actions_executed":2, "final_state_digest":hash("browser-final"),
                "context_isolation_observed":true, "off_scope_requests_blocked":1, "gaps":[]
            }))
            .unwrap(),
        );
        state.browser_evidence.push(evidence(
            state,
            EvidenceKind::BrowserClient,
            "browser-stage2",
            &browser_digest,
        ));

        let actor = hash("actor");
        let target = hash("target");
        let identity_digest = hash("identity-traffic");
        state.identity_observations.push(
            serde_json::from_value::<ModuleIdentityAccessObservation>(json!({
                "schema":1, "laboratory_id":lab, "source_snapshot":snapshot,
                "adapter_version":"peritus-identity-access-2026-10-24.1",
                "suite_version":"peritus-identity-access-suite-2026-10-24.1",
                "identities":[
                    {"identity_handle":actor, "role":"user", "tenant_handle":"tenant-a", "privileged":false, "credential_source":"laboratory_generated"},
                    {"identity_handle":target, "role":"admin", "tenant_handle":"tenant-a", "privileged":true, "credential_source":"laboratory_generated"}
                ],
                "session_transitions":[],
                "cases":[{"id":"identity-admin", "category":"vertical_authorization", "disposition":"violation",
                    "actor_identity":actor, "target_identity":target, "operation":"POST /admin",
                    "response_status":200, "state_change_observed":true, "oracle":"role differential",
                    "replay_digest":hash("identity-replay")}],
                "findings":[{"id":"identity-finding", "case_id":"identity-admin", "category":"vertical_authorization",
                    "severity":"high", "message":"ordinary user performed admin action", "evidence_state":"runtime_confirmed",
                    "standards":["CWE-862"], "replay_digest":hash("identity-replay")}],
                "redaction":{"credential_values_checked":2, "request_fields_redacted":2,
                    "response_fields_redacted":1, "provider_projection_clean":true,
                    "projection_digest":hash("identity-projection")},
                "traffic_digest":identity_digest, "operations_executed":1,
                "final_state_digest":hash("identity-final"), "gaps":[]
            }))
            .unwrap(),
        );
        state.identity_evidence.push(evidence(
            state,
            EvidenceKind::IdentityAccess,
            "identity-stage2",
            &identity_digest,
        ));

        let file_digest = hash("file-campaign");
        state.file_fuzz_observations.push(
            serde_json::from_value::<ModuleFileFuzzObservation>(json!({
                "schema":1, "laboratory_id":lab, "source_snapshot":snapshot,
                "adapter_version":"peritus-file-parser-2026-10-24.1",
                "suite_version":"peritus-file-parser-suite-2026-10-24.1", "seed":7,
                "corpus_digest":hash("file-corpus"), "generated_cases":0,
                "cases":[{"id":"path-traversal", "category":"path_traversal", "disposition":"violation",
                    "operation":"POST /file", "input":{"kind":"path", "digest":hash("X"), "bytes":1,
                    "base64":"WA==", "minimized":true, "original_bytes":1}, "response_status":200,
                    "boundary_effect":"guard/escape", "native_signal":null, "coverage_before":0,
                    "coverage_after":1, "oracle":"boundary canary", "replay_digest":hash("file-replay")}],
                "findings":[{"id":"file-finding", "case_id":"path-traversal", "category":"path_traversal",
                    "severity":"high", "message":"path escaped the target directory", "evidence_state":"runtime_confirmed",
                    "standards":["CWE-22"], "minimized_input_digest":hash("X"), "replay_digest":hash("file-replay")}],
                "instrumentation":{"controller":"controller@1", "coverage_model":"edges", "coverage_edges":1,
                    "coverage_digest":hash("coverage"), "native_fault_instrumentation":"signals",
                    "compiler_sanitizer_active":false, "compiler_sanitizer_gap":"not needed"},
                "resources":{"operations":1, "request_bytes":1, "response_bytes":1, "wall_millis":1,
                    "maximum_input_bytes":16, "laboratory_remained_ready":true},
                "crash_groups":0, "campaign_digest":file_digest, "final_state_digest":hash("file-final"), "gaps":[]
            }))
            .unwrap(),
        );
        state.file_fuzz_evidence.push(evidence(
            state,
            EvidenceKind::FileFuzz,
            "file-stage2",
            &file_digest,
        ));

        let workflow_digest = hash("workflow-campaign");
        state.workflow_observations.push(
            serde_json::from_value::<ModuleWorkflowObservation>(json!({
                "schema":1, "laboratory_id":lab, "source_snapshot":snapshot,
                "adapter_version":"peritus-workflow-state-2026-10-24.1",
                "suite_version":"peritus-workflow-state-suite-2026-10-24.1", "seed":9,
                "invariants":[{"id":"inv-approval", "origin":"documented", "statement":"approval is required",
                    "oracle":"approval oracle", "disposition":"violated", "sequence_ids":["workflow-sequence"]}],
                "sequences":[{"id":"workflow-sequence", "category":"approval", "identities":["actor-a"],
                    "starting_snapshot_digest":hash("workflow-before"),
                    "actions":[{"id":"action-1", "position":0, "actor":"actor-a", "operation":"charge",
                        "request_id":"request-1", "schedule_slot":null, "request_digest":hash("workflow-request"),
                        "response_status":200, "state_before_digest":hash("workflow-before"),
                        "state_after_digest":hash("workflow-after"), "elapsed_millis":1, "outcome":"charged"}],
                    "final_state_digest":hash("workflow-after"), "invariant_ids":["inv-approval"],
                    "disposition":"violation", "oracle":"approval oracle", "schedule_id":null,
                    "replay_digest":hash("workflow-replay")}],
                "findings":[{"id":"workflow-finding", "sequence_id":"workflow-sequence", "invariant_id":"inv-approval",
                    "severity":"high", "message":"charge completed without approval", "evidence_state":"runtime_confirmed",
                    "standards":["CWE-841"], "replay_digest":hash("workflow-replay")}],
                "nondeterminism":{"schedules":[], "replays":0, "divergent_replays":0,
                    "excluded_harness_failures":0, "notes":[]},
                "actions_executed":1, "campaign_digest":workflow_digest,
                "final_state_digest":hash("workflow-final"), "gaps":[]
            }))
            .unwrap(),
        );
        state.workflow_evidence.push(evidence(
            state,
            EvidenceKind::WorkflowState,
            "workflow-stage2",
            &workflow_digest,
        ));

        let boundary_digest = hash("boundary-campaign");
        let case = |id: &str, class: &str, disposition: &str| {
            json!({
                "id":id, "class":class, "operation":format!("POST /boundary/{id}"),
                "response_status":if disposition == "blocked" { None } else { Some(200) },
                "request_digest":hash(&format!("{id}-request")),
                "state_before_digest":hash(&format!("{id}-before")),
                "state_after_digest":hash(&format!("{id}-after")), "changed_state_keys":[],
                "disposition":disposition, "oracle":"boundary oracle", "detail":"boundary result",
                "replay_digest":hash(&format!("{id}-replay"))
            })
        };
        state.boundary_observations.push(
            serde_json::from_value::<ModuleBoundaryObservation>(json!({
                "schema":1, "laboratory_id":lab, "source_snapshot":snapshot,
                "adapter_version":"peritus-boundary-authority-2026-10-24.5",
                "suite_version":"peritus-boundary-authority-suite-2026-10-24.1",
                "cases":[
                    case("authority-prompt", "delegated_authority", "violation"),
                    case("live-cloud-provider", "platform_gap", "blocked"),
                    case("host-privileged-runtime", "platform_gap", "blocked")
                ],
                "findings":[{"id":"boundary-finding", "case_id":"authority-prompt", "severity":"high",
                    "message":"delegated action exceeded caller scope", "evidence_state":"runtime_confirmed",
                    "standards":["CWE-441"], "replay_digest":hash("authority-prompt-replay")}],
                "network":{"private_dns_queries":1, "private_callbacks":0, "redirect_hops":0,
                    "proxy_requests":0, "forbidden_destination_attempts":0, "host_loopback_effects":0,
                    "lan_effects":0, "external_effects":0, "peer_receipt_digest":hash("peer")},
                "tls":{"handshakes":1, "trusted_hostname":"passed", "hostname_mismatch":"passed",
                    "expired_certificate":"passed", "downgrade":"passed", "connection_reuse":"passed",
                    "certificate_set_digest":hash("certificates")},
                "policy":{"policy_digest":hash("policy"), "run_as_user":"nobody", "requested_capabilities":[],
                    "no_new_privileges":true, "privilege_attempts":0, "host_privilege_effects":0,
                    "containment_held":true},
                "authority":{"untrusted_directives":1, "delegated_actions":1, "privileged_effects":1,
                    "confused_deputy_observed":true, "host_authority_unchanged":true},
                "operations_executed":1, "campaign_digest":boundary_digest,
                "final_state_digest":hash("boundary-final"), "gaps":[]
            }))
            .unwrap(),
        );
        state.boundary_evidence.push(evidence(
            state,
            EvidenceKind::BoundaryAuthority,
            "boundary-stage2",
            &boundary_digest,
        ));
    }

    #[test]
    fn all_seven_adapters_project_stably() {
        let mut state = base_state();
        seed_all(&mut state);
        let first = reconcile(&mut state);
        assert_eq!(first, ProjectionSummary { projected: 7, rejected: 0 });
        let ids =
            state.research_capabilities.iter().map(|record| record.id.clone()).collect::<Vec<_>>();
        let second = reconcile(&mut state);
        assert_eq!(second, first);
        assert_eq!(
            state.research_capabilities.iter().map(|record| record.id.clone()).collect::<Vec<_>>(),
            ids
        );
    }

    #[test]
    fn negative_controls_never_become_primitives() {
        let mut state = base_state();
        seed_all(&mut state);
        state.api_observations[0].findings[0].replay_request_digest = hash("forged");
        state.file_fuzz_observations[0].findings.clear();
        state.workflow_observations[0].invariants[0].origin =
            peritus_plugin_sdk::ModuleWorkflowInvariantOrigin::ModelProposed;
        let summary = reconcile(&mut state);
        assert_eq!(summary.projected, 4);
        assert_eq!(summary.rejected, 2);
        assert!(state.research_capabilities.iter().all(|record| {
            record.source_record != "http-finding"
                || record.disposition == ModuleResearchCapabilityDisposition::Rejected
        }));
        assert!(state.research_capabilities.iter().all(|record| {
            record.source_record != "workflow-finding"
                || record.disposition == ModuleResearchCapabilityDisposition::Rejected
        }));
        assert!(
            state.research_capabilities.iter().all(|record| record.source_record != "file-finding")
        );
    }

    #[test]
    fn wrong_target_and_stale_laboratory_are_rejected() {
        let mut wrong_target = base_state();
        seed_all(&mut wrong_target);
        wrong_target.api_observations[0].source_snapshot = hash("other-target");
        let summary = reconcile(&mut wrong_target);
        assert_eq!(summary.projected, 6);
        assert_eq!(summary.rejected, 1);
        assert_eq!(
            wrong_target
                .research_capabilities
                .iter()
                .find(|record| record.source_record == "http-finding")
                .and_then(|record| record.rejection_reason),
            Some(ModuleResearchProjectionRejection::MissingTargetContinuity)
        );

        let mut stale = base_state();
        seed_all(&mut stale);
        stale.laboratory_statuses.clear();
        let summary = reconcile(&mut stale);
        assert_eq!(summary.projected, 1);
        assert_eq!(summary.rejected, 6);
        assert!(
            stale
                .research_capabilities
                .iter()
                .filter(|record| {
                    record.rejection_reason
                        == Some(ModuleResearchProjectionRejection::StaleLaboratoryIdentity)
                })
                .count()
                == 6
        );
    }

    #[test]
    fn incompatible_subject_and_unsupported_kind_have_stable_reasons() {
        let mut incompatible = base_state();
        seed_all(&mut incompatible);
        incompatible.identity_observations[0].cases[0].actor_identity = hash("unknown-actor");
        reconcile(&mut incompatible);
        assert_eq!(
            incompatible
                .research_capabilities
                .iter()
                .find(|record| record.source_record == "identity-finding")
                .and_then(|record| record.rejection_reason),
            Some(ModuleResearchProjectionRejection::IncompatibleSubjectAuthority)
        );

        let mut unsupported = base_state();
        seed_all(&mut unsupported);
        unsupported.browser_observations[0].cases[0].category = "future-browser-class".into();
        unsupported.browser_observations[0].findings[0].category = "future-browser-class".into();
        reconcile(&mut unsupported);
        assert_eq!(
            unsupported
                .research_capabilities
                .iter()
                .find(|record| record.source_record == "browser-finding")
                .and_then(|record| record.rejection_reason),
            Some(ModuleResearchProjectionRejection::UnsupportedCapabilityKind)
        );
    }

    #[test]
    fn safe_twin_has_no_prohibited_capability() {
        let mut state = base_state();
        seed_all(&mut state);
        state.analysis_observations[0].findings.clear();
        state.api_observations[0].findings.clear();
        state.browser_observations[0].findings.clear();
        state.identity_observations[0].findings.clear();
        state.file_fuzz_observations[0].findings.clear();
        state.workflow_observations[0].findings.clear();
        state.boundary_observations[0].findings.clear();
        assert_eq!(reconcile(&mut state), ProjectionSummary::default());
        assert!(state.research_capabilities.is_empty());
    }

    #[test]
    fn primitive_identity_binds_adapter_subject_authority_and_facts() {
        let common = |version: &str, subject: &str, authority: &str, input: &str| {
            build_record(RecordInput {
                adapter_id: "adapter",
                adapter_version: version,
                projection_version: HTTP_PROJECTION,
                source_record: "finding",
                target_value: "target",
                subject_value: subject,
                authority_before: authority,
                authority_after: authority,
                capability: ModuleResearchCapabilityKind::InputInterpretationViolation,
                evidence_boundary: ModuleResearchEvidenceBoundary::RuntimeConfirmed,
                oracle_value: "oracle",
                evidence: None,
                consumes: vec![fact(ModuleResearchCapabilityFactKind::Input, input)],
                produces: vec![fact(ModuleResearchCapabilityFactKind::TargetState, "state")],
                rejection: Some((
                    ModuleResearchProjectionRejection::InsufficientOracleEvidence,
                    "test rejection".into(),
                )),
                detail: "unused".into(),
            })
        };
        let baseline = common("adapter@1", "subject", "authority", "input").id;
        assert_ne!(baseline, common("adapter@2", "subject", "authority", "input").id);
        assert_ne!(baseline, common("adapter@1", "other-subject", "authority", "input").id);
        assert_ne!(baseline, common("adapter@1", "subject", "other-authority", "input").id);
        assert_ne!(baseline, common("adapter@1", "subject", "authority", "other-input").id);
    }
}
