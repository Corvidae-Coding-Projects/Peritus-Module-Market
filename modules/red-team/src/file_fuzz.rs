//! Phase-sixteen file, archive, parser, native-fault, and fuzz campaign coordinator.

use crate::{
    Error, adapter, digest, invalid,
    records::{EvidenceKind, EvidenceRecord, RECORD_SCHEMA_VERSION, RecordId, RecordKind},
    reply, state,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use peritus_plugin_sdk::{
    ModuleAction, ModuleAdapterExecuteRequest, ModuleAdapterExecutionReceipt,
    ModuleFileFuzzCampaignRequest, ModuleFileFuzzDisposition, ModuleFileFuzzObservation,
    ModuleHostProfile, ModuleLaboratoryPhase,
};
use serde_json::Value;
use std::collections::BTreeSet;

pub(crate) const ADAPTER_ID: &str = "peritus.file-parser";
pub(crate) const OPERATION: &str = "file-fuzz.campaign.v1";
const RECEIPT_DECODER: &str = "peritus.file-parser.decoder@1";
const PROFILE: &str = "peritus.file-parser.standard@1";

pub(crate) fn handles(command: &str) -> bool {
    matches!(
        command,
        "file-fuzz"
            | "file-fuzz-install"
            | "file-fuzz-run"
            | "file-fuzz-history"
            | "file-fuzz-status"
            | "file-fuzz-remove"
            | "file-fuzz-probe-wrong-endpoint"
            | "file-fuzz-probe-small-budget"
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
            "This Peritus host does not advertise generic isolated module workers. File, archive, parser, and native-fault testing remains blocked; no raw command fallback was attempted.",
            profile,
            super::actions(state),
            None,
        ));
    }
    match command {
        "file-fuzz" => Ok(reply(view(state), profile, super::actions(state), None)),
        "file-fuzz-install" => adapter::install(parameters, state, ADAPTER_ID),
        "file-fuzz-status" => adapter::status_for(parameters, state, ADAPTER_ID),
        "file-fuzz-remove" => adapter::remove_for(parameters, state, ADAPTER_ID),
        "file-fuzz-history" => Ok(reply(history(state), profile, super::actions(state), None)),
        "file-fuzz-run" | "file-fuzz-probe-wrong-endpoint" | "file-fuzz-probe-small-budget" => {
            let runtime = adapter::installed_runtime(state, ADAPTER_ID).ok_or_else(|| {
                invalid("install the registered file/parser adapter before `file-fuzz-run`")
            })?;
            let laboratory = state
                .laboratory_statuses
                .last()
                .filter(|status| status.phase == ModuleLaboratoryPhase::Ready)
                .ok_or_else(|| invalid("launch a ready file/parser laboratory first"))?;
            if !crate::laboratory::has_runtime_target(state, &laboratory.handle.laboratory_id) {
                return Err(invalid(
                    "the current laboratory does not expose the registered file/parser interface",
                ));
            }
            let mut input = ModuleFileFuzzCampaignRequest {
                schema: 1,
                laboratory_id: laboratory.handle.laboratory_id.clone(),
                endpoint_handle: laboratory.handle.endpoint_handle.clone(),
                profile: PROFILE.into(),
                seed: 0x5048_3136,
                maximum_cases: 64,
                maximum_input_bytes: 64 * 1024,
                maximum_response_bytes: 256 * 1024,
            };
            if command == "file-fuzz-probe-wrong-endpoint" {
                input.endpoint_handle = "0".repeat(64);
            } else if command == "file-fuzz-probe-small-budget" {
                input.maximum_cases = 8;
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
        _ => Err(invalid("unknown file/parser campaign command")),
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
        || receipt.executed_by != "peritus-red-team/file-parser@1"
    {
        return Err(invalid("file/parser receipt has an unregistered module runtime identity"));
    }
    let observation: ModuleFileFuzzObservation = serde_json::from_value(receipt.observation)?;
    validate_observation(state, &observation)?;
    let scope = state.scopes.last().ok_or_else(|| invalid("file/parser evidence has no scope"))?;
    let snapshot = state
        .active_snapshot()
        .ok_or_else(|| invalid("file/parser evidence has no source snapshot"))?;
    let evidence_id = RecordId::new(
        RecordKind::Evidence,
        format!("file-fuzz-{}", &digest(observation.campaign_digest.as_bytes())[..24]),
    )
    .map_err(invalid)?;
    let evidence = EvidenceRecord {
        schema: RECORD_SCHEMA_VERSION,
        id: evidence_id.clone(),
        campaign: state.campaign.id.clone(),
        scope_revision: scope.id.clone(),
        kind: EvidenceKind::FileFuzz,
        observation: format!(
            "Module-owned file/parser adapter executed {} bounded real operations, retained {} exact cases, and confirmed {} violations or crashes",
            observation.resources.operations,
            observation.cases.len(),
            observation.findings.len()
        ),
        artifact_digest: observation.campaign_digest.clone(),
        dependencies: vec![snapshot.id.clone()],
    };
    if !state.file_fuzz_evidence.iter().any(|existing| existing.id == evidence_id) {
        state.file_fuzz_evidence.push(evidence);
    }
    if let Some(existing) = state
        .file_fuzz_observations
        .iter_mut()
        .find(|existing| existing.campaign_digest == observation.campaign_digest)
    {
        *existing = observation.clone();
    } else {
        state.file_fuzz_observations.push(observation.clone());
    }
    let advanced = crate::coverage::record_file_fuzz_method(state, &evidence_id);
    state.pending = None;
    state::save(parameters, state)?;
    Ok(reply(render(&observation, &evidence_id, advanced), profile, super::actions(state), None))
}

fn validate_observation(
    state: &state::State,
    observation: &ModuleFileFuzzObservation,
) -> Result<(), Error> {
    if observation.schema != 1
        || observation.adapter_version != "peritus-file-parser-2026-10-24.1"
        || !matches!(
            observation.suite_version.as_str(),
            "peritus-file-parser-suite-2026-10-24.1" | "peritus-file-parser-diamond-2026-10-25.1"
        )
        || observation.corpus_digest.len() != 64
        || observation.instrumentation.coverage_digest.len() != 64
        || observation.campaign_digest.len() != 64
        || observation.resources.operations
            < u64::try_from(observation.cases.len()).unwrap_or(u64::MAX)
        || !observation.resources.laboratory_remained_ready
    {
        return Err(invalid("file/parser observation has an invalid identity or resource record"));
    }
    let laboratory = state
        .laboratory_statuses
        .iter()
        .rev()
        .find(|status| status.handle.laboratory_id == observation.laboratory_id)
        .ok_or_else(|| invalid("file/parser observation belongs to an unknown laboratory"))?;
    if laboratory.handle.source_snapshot != observation.source_snapshot {
        return Err(invalid("file/parser observation belongs to a different source snapshot"));
    }
    let mut cases = BTreeSet::new();
    let mut prior_coverage = 0;
    for case in &observation.cases {
        let decoded = BASE64
            .decode(&case.input.base64)
            .map_err(|_| invalid("file/parser case input is not canonical base64"))?;
        if !cases.insert(case.id.as_str())
            || case.input.digest != digest(&decoded)
            || case.input.bytes != u64::try_from(decoded.len()).unwrap_or(u64::MAX)
            || case.input.bytes > observation.resources.maximum_input_bytes
            || case.input.original_bytes < case.input.bytes
            || case.replay_digest.len() != 64
            || case.coverage_before != prior_coverage
            || case.coverage_after < case.coverage_before
        {
            return Err(invalid("file/parser cases are duplicated or have invalid replay data"));
        }
        prior_coverage = case.coverage_after;
    }
    if prior_coverage != observation.instrumentation.coverage_edges {
        return Err(invalid("file/parser coverage ledger does not match its controller receipt"));
    }
    let mut findings = BTreeSet::new();
    for finding in &observation.findings {
        let Some(case) = observation.cases.iter().find(|case| case.id == finding.case_id) else {
            return Err(invalid("file/parser finding has no retained executed case"));
        };
        if finding.evidence_state != "runtime_confirmed"
            || !matches!(
                case.disposition,
                ModuleFileFuzzDisposition::Violation | ModuleFileFuzzDisposition::Crash
            )
            || finding.minimized_input_digest != case.input.digest
            || finding.replay_digest != case.replay_digest
            || !findings.insert(finding.id.as_str())
        {
            return Err(invalid(
                "file/parser finding is not uniquely bound to a host-confirmed defect",
            ));
        }
    }
    Ok(())
}

fn render(observation: &ModuleFileFuzzObservation, evidence: &RecordId, advanced: usize) -> String {
    let violations = count(observation, ModuleFileFuzzDisposition::Violation);
    let crashes = count(observation, ModuleFileFuzzDisposition::Crash);
    let rejected = count(observation, ModuleFileFuzzDisposition::Rejected);
    let passed = count(observation, ModuleFileFuzzDisposition::Passed);
    let harness = count(observation, ModuleFileFuzzDisposition::HarnessFailure);
    let mut text = format!(
        "# File, archive, parser, and native-fault campaign\n\n- Evidence: `{}`\n- Laboratory: `{}`\n- Source snapshot: `{}`\n- Adapter / suite: `{}` / `{}`\n- Seed / corpus: `{}` / `{}`\n- Generated / retained cases: {} / {}\n- Passed / rejected / violations / crashes / harness failures: {passed} / {rejected} / {violations} / {crashes} / {harness}\n- Coverage model / edges: `{}` / {}\n- Native instrumentation: {}\n- Compiler sanitizer active: {}\n- Real operations / request bytes / response bytes / wall ms: {} / {} / {} / {}\n- Crash groups: {}\n- Coverage cells advanced: {advanced}\n- Campaign digest: `{}`\n- Final copied-state digest: `{}`\n\n",
        evidence.value,
        observation.laboratory_id,
        observation.source_snapshot,
        observation.adapter_version,
        observation.suite_version,
        observation.seed,
        observation.corpus_digest,
        observation.generated_cases,
        observation.cases.len(),
        observation.instrumentation.coverage_model,
        observation.instrumentation.coverage_edges,
        observation.instrumentation.native_fault_instrumentation,
        observation.instrumentation.compiler_sanitizer_active,
        observation.resources.operations,
        observation.resources.request_bytes,
        observation.resources.response_bytes,
        observation.resources.wall_millis,
        observation.crash_groups,
        observation.campaign_digest,
        observation.final_state_digest,
    );
    text.push_str("## Runtime-confirmed findings\n\n");
    if observation.findings.is_empty() {
        text.push_str("None in this pinned campaign. This is not a universal safety claim.\n");
    }
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
    text.push_str("\n## Exact case ledger\n\n");
    for case in &observation.cases {
        text.push_str(&format!(
            "- `{}` · `{:?}` · `{}` · {} bytes · edges {}→{} · boundary `{}` · signal `{}` · replay `{}` — {}\n",
            case.id,
            case.disposition,
            case.input.kind,
            case.input.bytes,
            case.coverage_before,
            case.coverage_after,
            case.boundary_effect.as_deref().unwrap_or("none"),
            case.native_signal.map_or_else(|| "none".into(), |value| value.to_string()),
            case.replay_digest,
            case.oracle,
        ));
    }
    text.push_str("\n## Explicit gaps\n\n");
    for gap in &observation.gaps {
        text.push_str(&format!("- {gap}\n"));
    }
    text
}

fn count(observation: &ModuleFileFuzzObservation, disposition: ModuleFileFuzzDisposition) -> usize {
    observation.cases.iter().filter(|case| case.disposition == disposition).count()
}

fn view(state: &state::State) -> String {
    format!(
        "# File, archive, parser, and native-fault adapter family\n\n- Registered adapter: `{ADAPTER_ID}`\n- Operation: `{OPERATION}`\n- Installed: {}\n- Retained campaigns: {}\n\nThe module owns fixed filesystem canaries, real TAR and structured inputs, deterministic generation and minimization, native child-signal observation, behavioral coverage, requested inner resource bounds, and durable replay receipts. Peritus generically enforces the outer worker resource ceiling. Arbitrary commands and compiler toolchains are not accepted from module code.",
        adapter::installed_runtime(state, ADAPTER_ID).is_some(),
        state.file_fuzz_observations.len(),
    )
}

fn history(state: &state::State) -> String {
    let mut text = "# File/parser campaign history\n\n".to_owned();
    if state.file_fuzz_observations.is_empty() {
        text.push_str("No file/parser campaign receipt has been admitted.\n");
    }
    for observation in state.file_fuzz_observations.iter().rev() {
        text.push_str(&format!(
            "- laboratory `{}` — {} operations, {} cases, {} findings, {} edges, {} crash groups, ready {}, campaign `{}`\n",
            observation.laboratory_id,
            observation.resources.operations,
            observation.cases.len(),
            observation.findings.len(),
            observation.instrumentation.coverage_edges,
            observation.crash_groups,
            observation.resources.laboratory_remained_ready,
            observation.campaign_digest,
        ));
    }
    text
}
