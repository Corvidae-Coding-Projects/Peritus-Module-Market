//! Phase-twelve deterministic source, dependency, secret, and configuration analysis.

use crate::{
    Error, adapter, digest, invalid,
    records::{EvidenceKind, EvidenceRecord, RECORD_SCHEMA_VERSION, RecordId, RecordKind},
    reply, state,
};
use peritus_plugin_sdk::{
    ModuleAction, ModuleAdapterExecuteRequest, ModuleAdapterExecutionReceipt, ModuleHostProfile,
    ModuleSourceAnalysisLimits, ModuleSourceAnalysisObservation, ModuleSourceReachability,
};
use serde_json::Value;
use std::collections::BTreeSet;

pub(crate) const ADAPTER_ID: &str = "peritus.source-analysis";
pub(crate) const OPERATION: &str = "source.scan.v1";
const RECEIPT_DECODER: &str = "peritus.source-analysis.decoder@1";

pub(crate) fn handles(command: &str) -> bool {
    matches!(
        command,
        "analyzers"
            | "analyzer-install"
            | "analyze"
            | "analysis-history"
            | "analyzer-status"
            | "analyzer-remove"
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
            "This Peritus host does not advertise generic isolated module workers. Static analysis remains blocked; no ambient scanner, executable or source path was used.",
            profile,
            super::actions(state),
            None,
        ));
    }
    match command {
        "analyzers" => Ok(reply(view(state), profile, super::actions(state), None)),
        "analyzer-install" => adapter::install(parameters, state, ADAPTER_ID),
        "analyzer-status" => adapter::status_for(parameters, state, ADAPTER_ID),
        "analyzer-remove" => adapter::remove_for(parameters, state, ADAPTER_ID),
        "analysis-history" => Ok(reply(history(state), profile, super::actions(state), None)),
        "analyze" => {
            let source = state.active_handle().ok_or_else(|| {
                invalid("select source with scope before running static analysis")
            })?;
            let runtime = adapter::installed_runtime(state, ADAPTER_ID).ok_or_else(|| {
                invalid("install the registered static analyzer before running `analyze`")
            })?;
            adapter::execute(
                parameters,
                state,
                ModuleAdapterExecuteRequest {
                    schema: 1,
                    runtime,
                    operation: OPERATION.into(),
                    input: serde_json::to_value(peritus_plugin_sdk::ModuleSourceAnalysisRequest {
                        schema: 1,
                        source,
                        limits: ModuleSourceAnalysisLimits {
                            maximum_files: 10_000,
                            maximum_file_bytes: 2 * 1024 * 1024,
                            maximum_total_bytes: 128 * 1024 * 1024,
                        },
                    })?,
                },
            )
        }
        _ => Err(invalid("unknown static-analysis command")),
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
        || receipt.executed_by != "peritus-red-team/source-analysis@1"
    {
        return Err(invalid("static-analysis receipt has an unregistered module runtime identity"));
    }
    let observation: ModuleSourceAnalysisObservation =
        serde_json::from_value(receipt.observation.clone())?;
    validate_observation(state, &observation)?;
    let scope =
        state.scopes.last().ok_or_else(|| invalid("static analysis has no active scope"))?;
    let snapshot =
        state.active_snapshot().ok_or_else(|| invalid("static analysis has no active snapshot"))?;
    let evidence_id = RecordId::new(
        RecordKind::Evidence,
        format!("analysis-{}", &digest(observation.raw_result_digest.as_bytes())[..24]),
    )
    .map_err(invalid)?;
    let evidence = EvidenceRecord {
        schema: RECORD_SCHEMA_VERSION,
        id: evidence_id.clone(),
        campaign: state.campaign.id.clone(),
        scope_revision: scope.id.clone(),
        kind: EvidenceKind::Analysis,
        observation: format!(
            "Module-owned static analyzer set {} examined {} immutable files and emitted {} source-only leads",
            observation.analyzer_set_version,
            observation.scanned_files,
            observation.findings.len()
        ),
        artifact_digest: observation.raw_result_digest.clone(),
        dependencies: vec![snapshot.id.clone()],
    };
    if !state.analysis_evidence.iter().any(|existing| existing.id == evidence_id) {
        state.analysis_evidence.push(evidence);
    }
    if let Some(existing) = state
        .analysis_observations
        .iter_mut()
        .find(|existing| existing.raw_result_digest == observation.raw_result_digest)
    {
        *existing = observation.clone();
    } else {
        state.analysis_observations.push(observation.clone());
    }
    let advanced =
        crate::coverage::record_static_method(state, &evidence_id, &observation.source_snapshot);
    state.pending = None;
    state::save(parameters, state)?;
    Ok(reply(render(&observation, &evidence_id, advanced), profile, super::actions(state), None))
}

fn validate_observation(
    state: &state::State,
    observation: &ModuleSourceAnalysisObservation,
) -> Result<(), Error> {
    if observation.schema != 1
        || observation.analyzer_set_version.trim().is_empty()
        || observation.rule_set_version.trim().is_empty()
        || observation.advisory_dataset_version.trim().is_empty()
        || observation.raw_result_digest.len() != 64
    {
        return Err(invalid("static-analysis observation has an invalid schema or identity"));
    }
    if state.active_snapshot().map(|value| value.snapshot_digest.as_str())
        != Some(observation.source_snapshot.as_str())
    {
        return Err(invalid("static-analysis observation belongs to a different source snapshot"));
    }
    let mut ids = BTreeSet::new();
    let mut roots = BTreeSet::new();
    let mut raw_ids = BTreeSet::new();
    for finding in &observation.raw_findings {
        if finding.evidence_state != "source_lead"
            || !raw_ids.insert(finding.id.as_str())
            || finding.redacted && finding.message.contains('=')
        {
            return Err(invalid(
                "raw static-analysis findings are not unique, source-bounded, or safely redacted",
            ));
        }
    }
    for finding in &observation.findings {
        if finding.evidence_state != "source_lead"
            || !ids.insert(finding.id.as_str())
            || !roots.insert(finding.root_cause.as_str())
            || finding.redacted && finding.message.contains('=')
        {
            return Err(invalid(
                "static-analysis findings are not unique, source-bounded, or safely redacted",
            ));
        }
    }
    Ok(())
}

fn render(
    observation: &ModuleSourceAnalysisObservation,
    evidence: &RecordId,
    advanced: usize,
) -> String {
    let mut text = format!(
        "# Deterministic static analysis\n\n- Evidence: `{}`\n- Snapshot: `{}`\n- Analyzer set: `{}`\n- Rule set: `{}`\n- Advisory data: `{}`\n- Files / bytes examined: {} / {}\n- Raw matches / deduplicated source leads: {} / {}\n- SBOM components: {}\n- Manifests: {}\n- Oversized skipped: {}\n- Binary skipped: {}\n- Aggregate traversal truncated: {}\n- Coverage cells advanced: {}\n- Raw result digest: `{}`\n\nEvery result below is a **source lead**, never runtime confirmation.\n\n",
        evidence.value,
        observation.source_snapshot,
        observation.analyzer_set_version,
        observation.rule_set_version,
        observation.advisory_dataset_version,
        observation.scanned_files,
        observation.scanned_bytes,
        observation.raw_findings.len(),
        observation.findings.len(),
        observation.components.len(),
        observation.manifests.len(),
        observation.skipped_oversized_files,
        observation.skipped_binary_files,
        observation.truncated,
        advanced,
        observation.raw_result_digest,
    );
    text.push_str("## Language support observed\n\n");
    for language in &observation.languages {
        text.push_str(&format!(
            "- `{}` — {} files / {} bytes — `{}`\n",
            language.language, language.files, language.bytes, language.support
        ));
    }
    text.push_str("\n## Leads\n\n");
    if observation.findings.is_empty() {
        text.push_str(
            "No deterministic source lead matched the pinned rules. This is not a safety claim.\n",
        );
    }
    for finding in &observation.findings {
        text.push_str(&format!(
            "- `{}` · `{:?}` · `{:?}` · `{}`{} — {}{}\n",
            finding.rule_id,
            finding.severity,
            finding.reachability,
            finding.path,
            finding.line.map_or_else(String::new, |line| format!(":{line}")),
            finding.message,
            if finding.deduplicated_from > 1 {
                format!(" ({} raw matches)", finding.deduplicated_from)
            } else {
                String::new()
            },
        ));
    }
    text.push_str("\n## Explicit gaps\n\n");
    for gap in &observation.gaps {
        text.push_str(&format!("- {gap}\n"));
    }
    text
}

fn view(state: &state::State) -> String {
    let installed = adapter::installed_runtime(state, ADAPTER_ID).is_some();
    format!(
        "# Static analyzer family\n\n- Registered adapter: `{ADAPTER_ID}`\n- Operation: `{OPERATION}`\n- Installed: {installed}\n- Retained scans: {}\n\nSupported discovery: Rust, C/C++, JavaScript/TypeScript, Python, Go and Java; Cargo, npm, Python requirements, Go modules and Maven manifests; Dockerfile, YAML/Kubernetes and Terraform configuration. Pattern analysis is available for all named languages; bounded same-file source-to-sink analysis is available for Python and JavaScript/TypeScript. Secret values are redacted and fingerprinted. Dependency reachability is classified as runtime-referenced, test-only, unreachable or unknown. All observations remain source leads until a later real-interface adapter proves behavior.",
        state.analysis_observations.len()
    )
}

fn history(state: &state::State) -> String {
    let mut text = "# Static analysis history\n\n".to_owned();
    if state.analysis_observations.is_empty() {
        text.push_str("No static-analysis receipt has been admitted.\n");
        return text;
    }
    for observation in state.analysis_observations.iter().rev() {
        let runtime = observation
            .components
            .iter()
            .filter(|component| {
                component.reachability == ModuleSourceReachability::RuntimeReferenced
            })
            .count();
        text.push_str(&format!(
            "- snapshot `{}` — {} files, {} leads, {} components ({} runtime-referenced), raw `{}`\n",
            observation.source_snapshot,
            observation.scanned_files,
            observation.findings.len(),
            observation.components.len(),
            runtime,
            observation.raw_result_digest,
        ));
    }
    text
}
