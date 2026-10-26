//! Generic source-bound web application campaign with a first-class Comms/Bun profile.

use crate::{
    Error, adapter, invalid,
    records::{EvidenceKind, EvidenceRecord, RECORD_SCHEMA_VERSION, RecordId, RecordKind},
    reply, state,
};
use peritus_plugin_sdk::{
    ModuleAction, ModuleAdapterExecuteRequest, ModuleAdapterExecutionReceipt, ModuleHostProfile,
    ModuleLaboratoryPhase,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub(crate) const ADAPTER_ID: &str = "peritus.generic-web-application";
pub(crate) const OPERATION: &str = "application.generic-web-campaign.v1";
const RECEIPT_DECODER: &str = "peritus.generic-web-application.decoder@1";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApplicationAttackCase {
    pub(crate) id: String,
    pub(crate) class: String,
    pub(crate) operation: String,
    pub(crate) disposition: String,
    pub(crate) response_status: Option<u16>,
    pub(crate) request_digest: String,
    pub(crate) response_digest: String,
    pub(crate) oracle: String,
    pub(crate) replay_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApplicationFinding {
    pub(crate) id: String,
    pub(crate) case_id: String,
    pub(crate) class: String,
    pub(crate) severity: String,
    pub(crate) message: String,
    pub(crate) evidence_state: String,
    pub(crate) replay_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApplicationCampaign {
    pub(crate) schema: u16,
    pub(crate) profile: String,
    pub(crate) laboratory_id: String,
    pub(crate) source_snapshot: String,
    pub(crate) runtime: String,
    pub(crate) entrypoint: String,
    pub(crate) launch_attempted: bool,
    pub(crate) ready: bool,
    pub(crate) dependency_preparation: String,
    pub(crate) cases: Vec<ApplicationAttackCase>,
    pub(crate) browser_cases: Vec<ApplicationAttackCase>,
    pub(crate) findings: Vec<ApplicationFinding>,
    pub(crate) operations_executed: u64,
    pub(crate) requests_executed: u64,
    pub(crate) traffic_digest: String,
    pub(crate) final_state_digest: String,
    pub(crate) process_cleanup_complete: bool,
    pub(crate) off_scope_requests_blocked: u64,
    pub(crate) gaps: Vec<String>,
    #[serde(default)]
    pub(crate) surfaces_exercised: Vec<String>,
}

pub(crate) fn handles(command: &str) -> bool {
    matches!(
        command,
        "application"
            | "application-install"
            | "application-run"
            | "application-status"
            | "application-remove"
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
            "This Peritus host does not advertise generic isolated module workers. The generic application campaign is blocked; no ambient endpoint or process fallback was attempted.",
            profile,
            super::actions(state),
            None,
        ));
    }
    match command {
        "application" => Ok(reply(view(state), profile, super::actions(state), None)),
        "application-install" => adapter::install(parameters, state, ADAPTER_ID),
        "application-status" => adapter::status_for(parameters, state, ADAPTER_ID),
        "application-remove" => adapter::remove_for(parameters, state, ADAPTER_ID),
        "application-run" => execute(parameters, state),
        _ => Err(invalid("unknown generic application binding command")),
    }
}

pub(crate) fn execute(parameters: &Value, state: &mut state::State) -> Result<ModuleAction, Error> {
    let runtime = adapter::installed_runtime(state, ADAPTER_ID).ok_or_else(|| {
        invalid("install the generic application binding before running its campaign")
    })?;
    let laboratory = state
        .laboratory_statuses
        .iter()
        .rev()
        .find(|status| status.phase == ModuleLaboratoryPhase::Ready)
        .ok_or_else(|| {
            invalid("launch a ready disposable complete-source laboratory before application-run")
        })?;
    let hypotheses = state
        .investigation
        .hypothesis_plans
        .iter()
        .filter_map(|plan| {
            state.hypotheses.iter().find(|item| item.id.value == plan.hypothesis_id).map(
                |hypothesis| {
                    json!({
                        "id": plan.hypothesis_id,
                        "family": plan.family,
                        "entry_point": hypothesis.entry_point,
                        "falsifiable_observation": hypothesis.falsifiable_observation,
                    })
                },
            )
        })
        .collect::<Vec<_>>();
    adapter::execute(
        parameters,
        state,
        ModuleAdapterExecuteRequest {
            schema: 1,
            runtime,
            operation: OPERATION.into(),
            input: json!({
                "schema": 1,
                "profile": runtime_profile(state),
                "laboratory_id": laboratory.handle.laboratory_id,
                "source_snapshot": laboratory.handle.source_snapshot,
                "hypotheses": hypotheses,
            }),
        },
    )
}

pub(crate) fn admit(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
    receipt: ModuleAdapterExecutionReceipt,
) -> Result<ModuleAction, Error> {
    if receipt.operation != OPERATION
        || receipt.receipt_decoder != RECEIPT_DECODER
        || receipt.executed_by != "peritus-red-team/generic-web-application@1"
    {
        return Err(invalid(
            "generic application receipt has an unregistered module runtime identity",
        ));
    }
    let observation: ApplicationCampaign = serde_json::from_value(receipt.observation)?;
    validate(state, &observation)?;
    let scope = state.scopes.last().ok_or_else(|| invalid("application evidence has no scope"))?;
    let snapshot = state
        .active_snapshot()
        .ok_or_else(|| invalid("application evidence has no source snapshot"))?;
    let evidence_id = RecordId::new(
        RecordKind::Evidence,
        format!("application-{}", &observation.traffic_digest[..24]),
    )
    .map_err(invalid)?;
    let evidence = EvidenceRecord {
        schema: RECORD_SCHEMA_VERSION,
        id: evidence_id.clone(),
        campaign: state.campaign.id.clone(),
        scope_revision: scope.id.clone(),
        kind: EvidenceKind::HttpApi,
        observation: format!(
            "Generic application binding launched {} with {}, exercised {} common surfaces through {} real operations, and retained {} runtime-confirmed violations",
            observation.profile,
            observation.runtime,
            observation.surfaces_exercised.len(),
            observation.operations_executed,
            observation.findings.len()
        ),
        artifact_digest: observation.traffic_digest.clone(),
        dependencies: vec![snapshot.id.clone()],
    };
    if !state.application_evidence.iter().any(|item| item.id == evidence_id) {
        state.application_evidence.push(evidence);
    }
    if let Some(existing) = state
        .application_observations
        .iter_mut()
        .find(|item| item.traffic_digest == observation.traffic_digest)
    {
        *existing = observation.clone();
    } else {
        state.application_observations.push(observation.clone());
    }
    bind_investigation_probes(state, &observation, &evidence_id);
    state.pending = None;
    let continue_investigation = state.application_campaign_pending
        && state.investigation.stage == state::InvestigationStage::Probing;
    state.application_campaign_pending = false;
    state::save(parameters, state)?;
    if continue_investigation {
        return crate::investigation::next(parameters, profile, state);
    }
    Ok(reply(render(&observation, &evidence_id), profile, super::actions(state), None))
}

fn validate(state: &state::State, observation: &ApplicationCampaign) -> Result<(), Error> {
    if observation.schema != 1
        || observation.traffic_digest.len() != 64
        || observation.final_state_digest.len() != 64
        || !observation.launch_attempted
        || observation.cases.iter().chain(&observation.browser_cases).any(|item| {
            item.request_digest.len() != 64
                || item.response_digest.len() != 64
                || item.replay_digest.len() != 64
        })
    {
        return Err(invalid("generic application observation has an invalid evidence identity"));
    }
    let expected_surfaces = [
        "attack_graph",
        "boundary_authority",
        "browser_client",
        "file_parser",
        "http_api",
        "identity_access",
        "workflow_state",
    ];
    if observation.ready
        && (observation.operations_executed == 0
            || !observation.process_cleanup_complete
            || observation.surfaces_exercised != expected_surfaces)
    {
        return Err(invalid(
            "a ready generic application campaign requires all seven common surfaces, real operations, and confirmed cleanup",
        ));
    }
    let laboratory = state
        .laboratory_statuses
        .iter()
        .rev()
        .find(|status| status.handle.laboratory_id == observation.laboratory_id)
        .ok_or_else(|| {
            invalid("generic application observation belongs to an unknown laboratory")
        })?;
    if laboratory.handle.source_snapshot != observation.source_snapshot {
        return Err(invalid(
            "generic application observation belongs to a different source snapshot",
        ));
    }
    for finding in &observation.findings {
        let case = observation
            .cases
            .iter()
            .chain(&observation.browser_cases)
            .find(|item| item.id == finding.case_id)
            .ok_or_else(|| invalid("generic application finding has no executed case"))?;
        if finding.evidence_state != "runtime_confirmed"
            || case.disposition != "violation"
            || finding.replay_digest != case.replay_digest
        {
            return Err(invalid(
                "generic application finding is not bound to a runtime-confirmed violation",
            ));
        }
    }
    Ok(())
}

fn bind_investigation_probes(
    state: &mut state::State,
    observation: &ApplicationCampaign,
    evidence: &RecordId,
) {
    let plans = state
        .investigation
        .hypothesis_plans
        .iter()
        .filter(|plan| plan.target_path.is_none())
        .cloned()
        .collect::<Vec<_>>();
    for plan in plans {
        if state.investigation.probes.iter().any(|probe| probe.hypothesis_id == plan.hypothesis_id)
        {
            continue;
        }
        let state_value = if observation.ready {
            state::ProbeState::Completed
        } else {
            state::ProbeState::Blocked
        };
        state.investigation.probes.push(state::ProbeAttempt {
            id: format!("application-probe-{}", state.investigation.probes.len() + 1),
            hypothesis_id: plan.hypothesis_id.clone(),
            target_path: observation.entrypoint.clone(),
            arguments: Vec::new(),
            stdin_digest: None,
            environment_digests: Default::default(),
            attacker_input: "generic HTTP/browser attack campaign".into(),
            changed_dimension: plan.changed_dimension,
            state: state_value,
            host_job_id: Some(format!("application-{}", &observation.traffic_digest[..24])),
            evidence: Some(evidence.clone()),
            detail: if observation.ready {
                format!(
                    "generic application campaign attempted {} real operations; correlate this bounded evidence with the hypothesis before classification",
                    observation.operations_executed
                )
            } else {
                format!(
                    "generic application launch was attempted but blocked: {}",
                    observation.gaps.join("; ")
                )
            },
        });
        if let Some(hypothesis) =
            state.hypotheses.iter_mut().find(|item| item.id.value == plan.hypothesis_id)
        {
            hypothesis.state = crate::records::HypothesisState::Investigating;
        }
    }
}

pub(crate) fn runtime_profile(state: &state::State) -> &'static str {
    let paths = state
        .investigation
        .manifest_entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if ["package.json", "bun.lock", "server/index.ts", "server/app.ts"]
        .iter()
        .all(|path| paths.contains(path))
    {
        "comms-bun.v1"
    } else if paths.contains("package.json") && paths.contains("bun.lock") {
        "generic-bun-web.v1"
    } else if paths.contains("package.json") {
        "generic-node-web.v1"
    } else {
        "generic-web.v1"
    }
}

pub(crate) fn source_observed(state: &state::State) -> bool {
    state.investigation.manifest_entries.iter().any(|entry| entry.path == "package.json")
}

fn render(observation: &ApplicationCampaign, evidence: &RecordId) -> String {
    let mut text = format!(
        "# Generic application attack campaign\n\n- Evidence: `{}`\n- Profile: `{}`\n- Runtime / entry point: `{}` / `{}`\n- Launch attempted / ready: {} / {}\n- Dependency preparation: {}\n- Common surfaces exercised: {}\n- HTTP / browser cases: {} / {}\n- Real operations / requests: {} / {}\n- Runtime-confirmed violations: {}\n- Cleanup confirmed: {}\n- Traffic / final state: `{}` / `{}`\n\n",
        evidence.value,
        observation.profile,
        observation.runtime,
        observation.entrypoint,
        observation.launch_attempted,
        observation.ready,
        observation.dependency_preparation,
        observation.surfaces_exercised.join(", "),
        observation.cases.len(),
        observation.browser_cases.len(),
        observation.operations_executed,
        observation.requests_executed,
        observation.findings.len(),
        observation.process_cleanup_complete,
        observation.traffic_digest,
        observation.final_state_digest,
    );
    for finding in &observation.findings {
        text.push_str(&format!(
            "- `{}` · `{}` · case `{}` — {}\n",
            finding.severity, finding.class, finding.case_id, finding.message
        ));
    }
    if observation.findings.is_empty() {
        text.push_str("No violation was confirmed by these bounded attacks; this is not a clean-application claim.\n");
    }
    for gap in &observation.gaps {
        text.push_str(&format!("- Gap: {gap}\n"));
    }
    text
}

fn view(state: &state::State) -> String {
    let latest = state.application_observations.last();
    format!(
        "# Generic web application binding\n\n- Registered adapter: `{ADAPTER_ID}`\n- Operation: `{OPERATION}`\n- Installed: {}\n- Retained campaigns: {}\n- Latest profile: `{}`\n\nThis binding attempts a contained real application launch and generic HTTP/browser attacks for compatible web source. The Comms/Bun profile supplies its safe fake-provider configuration and application-specific authentication, origin, webhook, body-limit, and browser probes.",
        adapter::installed_runtime(state, ADAPTER_ID).is_some(),
        state.application_observations.len(),
        latest.map_or("none", |item| item.profile.as_str()),
    )
}
