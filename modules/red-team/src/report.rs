//! Honest Phase-five Markdown and JSON report publication.

use crate::{
    Error, invalid,
    records::*,
    state::{ObservationState, State},
};
use peritus_plugin_sdk::ModuleAttachment;
use serde::Serialize;
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
    hypotheses: &'a [HypothesisRecord],
    observations: Vec<ObservationSummary<'a>>,
    jobs: &'a [JobRecord],
    job_evidence: &'a [EvidenceRecord],
    job_receipts: &'a [peritus_plugin_sdk::ModuleJobReceipt],
    findings: &'a [FindingRecord],
    reviews: &'a [ReviewRecord],
    investigation: &'a crate::state::InvestigationState,
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
    json_only: bool,
) -> Result<ModuleAttachment, Error> {
    let mut limitations = vec![
        "Coverage is bounded to the recorded source observations, hypotheses, inputs and host receipts; it is not a clean-codebase claim.".into(),
        "An examined family or unsuccessful probe is not evidence that the application is secure.".into(),
        "Phase five classifies findings but does not create patches or modify the original project; automatic fixes begin in Phase six.".into(),
        "The current trusted runtime adapter observes exact canary disclosure. Other interfaces remain analysis-supported, inconclusive, blocked or unexamined unless a suitable host adapter produced evidence.".into(),
    ];
    if !matches!(state.investigation.stage, crate::state::InvestigationStage::Complete) {
        limitations.push(format!(
            "This is a partial report from investigation stage `{:?}`; pending work remains durable.",
            state.investigation.stage
        ));
    }
    let snapshot = ReportSnapshot {
        schema: 1,
        phase: 5,
        campaign: &state.campaign,
        active_scope: state.scopes.last(),
        active_snapshot: state.snapshots.last(),
        coverage: &state.coverage,
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
        findings: &state.findings,
        reviews: &state.reviews,
        investigation: &state.investigation,
        limitations: limitations.clone(),
    };
    let json = serde_json::to_vec_pretty(&snapshot)?;
    let markdown = markdown(state, &limitations);
    let json_digest = digest(&json);
    let markdown_digest = digest(markdown.as_bytes());
    let reports = root.join("reports");
    let json_relative = format!("reports/{json_digest}.json");
    let markdown_relative = format!("reports/{markdown_digest}.md");
    publish_bytes(&reports.join(format!("{json_digest}.json")), &json)?;
    publish_bytes(&reports.join(format!("{markdown_digest}.md")), markdown.as_bytes())?;
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
        limitations,
        supersedes: prior,
    });
    Ok(if json_only {
        ModuleAttachment { name: "Red Team Phase 5 report (JSON)".into(), path: json_relative }
    } else {
        ModuleAttachment {
            name: "Red Team Phase 5 report (Markdown)".into(),
            path: markdown_relative,
        }
    })
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
        "# Red Team investigation report — Phase 5\n\n## Scope and source\n\n- Campaign: `{}`\n- Scope revision: `{}`\n- Source snapshot: `{}`\n- Manifest artifact: `{}`\n- Investigation stage: `{:?}`\n- Skill digest: `{}`\n- Provider routes: {}\n- Current source observations: {current}\n- Invalidated source observations: {invalidated}\n- Reused identical observations: {reused}\n- Host-owned jobs: {}\n- Trusted job receipts: {}\n- Adjudicated findings: {}\n\n",
        state.campaign.id.value,
        scope.map_or("not selected", |record| record.id.value.as_str()),
        snapshot.map_or("not captured", |record| record.snapshot_digest.as_str()),
        snapshot.map_or("not captured", |record| record.manifest_artifact.as_str()),
        state.investigation.stage,
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
        state.findings.len(),
    );
    text.push_str("## Coverage\n\nEvery supported family is reported separately. `unexamined` is a gap, not a clean result.\n\n");
    for record in &state.coverage {
        text.push_str(&format!(
            "- `{}` — `{:?}`: {}\n",
            record.family, record.state, record.reason
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
    text.push_str("\n## Host-owned jobs\n\n");
    if state.jobs.is_empty() {
        text.push_str("No dependency preparation or contained proof has been observed.\n");
    } else {
        for job in &state.jobs {
            text.push_str(&format!(
                "- `{}` — `{:?}` — `{}` — request `{}`\n",
                job.host_job_id, job.state, job.operation, job.request_digest
            ));
        }
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
                "- Probe `{}`: `{:?}`; target `{}`; changed dimension: {}; host job `{}`; {}\n",
                probe.id,
                probe.state,
                probe.target_path,
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
