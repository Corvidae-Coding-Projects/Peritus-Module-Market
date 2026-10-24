//! Phase-five campaign coordination over exact scoped source and host-owned proof receipts.

use crate::{
    Error, digest, invalid,
    records::{
        CoverageState, FindingClassification, FindingRecord, HypothesisRecord, HypothesisState,
        RECORD_SCHEMA_VERSION, RecordId, RecordKind, ReviewDecision, ReviewRecord,
    },
    state::{
        FamilyRoute, HypothesisOrigin, HypothesisPlan, InventoryRecord, InvestigationStage,
        PendingRequest, ProbeAttempt, ProbeState, ProviderRouteRecord, QueuedRead, State,
        security_families,
    },
};
use peritus_plugin_sdk::{
    HOST_CAPABILITY_OWNED_JOBS, HOST_CAPABILITY_SCOPED_SOURCE, ModuleAction, ModuleAgentRequest,
    ModuleCyberAccessProgram, ModuleFunction, ModuleHostProfile, ModuleHostRequest,
    ModuleJobLimits, ModuleJobPhase, ModuleJobRequest, ModuleJobStatus, ModuleJobStatusRequest,
    ModuleJobVerdict, ModuleMenuAction, ScopedSourceManifestRequest, ScopedSourceReadRequest,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs};

const SKILL: &str = include_str!("../skills/red-team/SKILL.md");
const EVIDENCE_STATES: &str = include_str!("../skills/red-team/references/evidence-states.md");
const MAX_SOURCE_PAGE: u64 = 1024 * 1024;
const MAX_BATCH_SOURCE_BYTES: u64 = 512 * 1024;
const MAX_BATCH_SOURCE_RANGES: usize = 32;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryInput {
    surfaces: Vec<String>,
    threat_boundaries: Vec<String>,
    routes: Vec<RouteInput>,
    source_evidence: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteInput {
    family: String,
    state: String,
    reason: String,
    surfaces: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HypothesisInput {
    family: String,
    origin: String,
    attacker: String,
    entry_point: String,
    prerequisites: Vec<String>,
    security_property: String,
    falsifiable_observation: String,
    source_evidence: Vec<String>,
    target_path: Option<String>,
    attacker_input: Option<String>,
    changed_dimension: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdjudicationInput {
    hypothesis_id: String,
    classification: String,
    evidence: Vec<String>,
    reachability: String,
    prerequisites: String,
    oracle: String,
    impact: String,
    target_identity: String,
    counterevidence: String,
    detail: String,
}

pub(crate) fn start(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut State,
) -> Result<ModuleAction, Error> {
    if state.active_snapshot().is_none() {
        return Ok(reply(
            "Select the explicit application source with `scope` before starting investigation.",
            profile,
            actions(state),
        ));
    }
    if matches!(state.investigation.stage, InvestigationStage::NotStarted) {
        state.investigation.stage = InvestigationStage::Inventory;
        state.investigation.skill_digest = digest(SKILL.as_bytes());
        state.investigation.provider_routes = provider_routes(parameters);
        state.investigation.feedback = "Begin the single bounded inventory and threat-boundary pass. Reuse retained source observations; do not read the whole repository recursively.".into();
        state.investigation.round = 1;
        state.campaign.state = crate::records::CampaignState::Active;
        crate::state::save(parameters, state)?;
    } else {
        // A repeated `start` is how the product-level retry path re-enters a native
        // module after a provider interruption. Advance the role-context identity so
        // a failed or bloated provider transcript cannot be inherited. Durable module
        // state, not provider chat history, is the recovery authority.
        state.investigation.round = state
            .investigation
            .round
            .checked_add(1)
            .ok_or_else(|| invalid("investigation round overflow"))?;
        crate::state::save(parameters, state)?;
    }
    if !state.investigation.manifest_complete {
        return request_manifest(parameters, state, None);
    }
    next(parameters, profile, state)
}

pub(crate) fn pause(parameters: &Value, state: &mut State) -> Result<ModuleAction, Error> {
    state.investigation.paused = true;
    state.campaign.state = crate::records::CampaignState::Paused;
    crate::state::save(parameters, state)?;
    Ok(reply(
        "Red Team investigation is paused. Exact source observations, hypotheses, receipts, decisions, and pending-stage identity remain durable. An already submitted host job remains host-owned; use jobs or job-cancel for its exact identity.",
        &profile(parameters),
        actions(state),
    ))
}

pub(crate) fn resume(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut State,
) -> Result<ModuleAction, Error> {
    state.investigation.paused = false;
    state.campaign.state = crate::records::CampaignState::Active;
    state.investigation.round = state
        .investigation
        .round
        .checked_add(1)
        .ok_or_else(|| invalid("investigation round overflow"))?;
    crate::state::save(parameters, state)?;
    if let Some(pending) = &state.pending {
        return crate::resume_pending(pending);
    }
    next(parameters, profile, state)
}

pub(crate) fn steer(
    parameters: &Value,
    state: &mut State,
    direction: &str,
) -> Result<ModuleAction, Error> {
    let direction = direction.trim();
    if direction.is_empty() || direction.len() > 8192 || direction.contains('\0') {
        return Err(invalid("steering must be 1..8192 bytes of text"));
    }
    state.investigation.steering.push(direction.into());
    if state.investigation.steering.len() > 32 {
        state.investigation.steering.remove(0);
    }
    state.investigation.feedback = format!("Current user steering: {direction}");
    crate::state::save(parameters, state)?;
    Ok(reply(
        "Steering was retained for the current and later investigation roles. It cannot expand the selected source or host authority.",
        &profile(parameters),
        actions(state),
    ))
}

pub(crate) fn request_manifest(
    parameters: &Value,
    state: &mut State,
    after: Option<String>,
) -> Result<ModuleAction, Error> {
    let authority = state
        .active_handle()
        .ok_or_else(|| invalid("source authority is unavailable for inventory"))?;
    let key =
        format!("red-team-investigation-manifest-{}", state.investigation.reuse.manifest_pages + 1);
    state.pending = Some(PendingRequest::Manifest {
        key: key.clone(),
        authority: authority.clone(),
        after: after.clone(),
        maximum_entries: 500,
    });
    crate::state::save(parameters, state)?;
    Ok(ModuleAction::HostService {
        request: ModuleHostRequest {
            key,
            capability: HOST_CAPABILITY_SCOPED_SOURCE.into(),
            version: 1,
            operation: "manifest".into(),
            input: serde_json::to_value(ScopedSourceManifestRequest {
                schema: 1,
                authority,
                after,
                maximum_entries: 500,
            })?,
        },
    })
}

pub(crate) fn admit_manifest_page(
    state: &mut State,
    entries: Vec<peritus_plugin_sdk::ScopedSourceEntry>,
    next_after: Option<String>,
) -> Option<String> {
    let existing = state
        .investigation
        .manifest_entries
        .iter()
        .map(|entry| entry.path.clone())
        .collect::<BTreeSet<_>>();
    state
        .investigation
        .manifest_entries
        .extend(entries.into_iter().filter(|entry| !existing.contains(&entry.path)));
    state.investigation.manifest_entries.sort_by(|a, b| a.path.cmp(&b.path));
    state.investigation.reuse.manifest_pages =
        state.investigation.reuse.manifest_pages.saturating_add(1);
    state.investigation.manifest_complete = next_after.is_none();
    next_after
}

pub(crate) fn next(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut State,
) -> Result<ModuleAction, Error> {
    if state.investigation.paused {
        return Ok(reply(
            "Red Team investigation is paused with its current phase and evidence retained.",
            profile,
            actions(state),
        ));
    }
    match state.investigation.stage {
        InvestigationStage::NotStarted => start(parameters, profile, state),
        InvestigationStage::Inventory => model(state, "inventory"),
        InvestigationStage::Discovery => model(state, "discovery"),
        InvestigationStage::Probing => schedule_probe(parameters, profile, state),
        InvestigationStage::Skeptic => model(state, "skeptic"),
        InvestigationStage::Complete => Ok(reply(
            "Phase-five investigation is complete for the bounded recorded hypotheses. Use report or report-json for the evidence-backed result; coverage gaps remain explicit.",
            profile,
            actions(state),
        )),
    }
}

fn model(state: &State, role: &str) -> Result<ModuleAction, Error> {
    let (model_role, status, role_guidance) = match role {
        "inventory" => (
            "writer",
            "Red Team · bounded inventory",
            "Perform exactly one bounded inventory and threat-boundary pass. Start with red_team_inspect(kind=inventory) once. When more than one small source page is needed, make one red_team_observe_many call instead of separate observations; its host reads complete before your next turn. Request only pages needed to identify concrete surfaces and boundaries. After requested source pages are delivered in coordinator feedback, treat them as retained: do not inspect or request those unchanged ranges again in this role. Route all supported families; unexamined and blocked are honest results. Finish promptly with red_team_inventory_commit.",
        ),
        "discovery" => (
            "writer",
            "Red Team · hypothesis discovery",
            "Inspect the committed inventory and retained hypothesis index exactly once, then commit missing small falsifiable hypotheses with red_team_discovery_commit in batches of at most six. Set complete=false while another batch remains and complete=true on the final batch. Every accepted batch ends the provider request and is durable before the next fresh turn, so on recovery add only missing work. The inventory view is already compact and authoritative; do not request coverage or source again unless one specific missing fact is necessary. Do not rediscover the repository or reread an unchanged range within this role. Distinguish known-description reproduction from unknown discovery. Every executable probe must name an immutable target path, literal attacker input, and changed dimension. Prefer the transactional batch commit over one-at-a-time registration.",
        ),
        "skeptic" => (
            "reviewer",
            "Red Team · independent skeptical adjudication",
            "You have a separate reviewer context. Inspect the hypothesis index once, then call red_team_inspect(kind=evidence) once for the next exact bundle of at most six unadjudicated hypotheses. Challenge reachability, prerequisites, oracle, impact, target identity and counterevidence. An unsuccessful attempt is not a refutation. Save decisions with red_team_review_commit, setting complete=false while another bundle remains and complete=true on the final batch. Every accepted batch ends the provider request and is durable before the next fresh turn. On recovery, adjudicate only hypotheses without a retained finding.",
        ),
        _ => return Err(invalid("unknown investigation role")),
    };
    let steering = state
        .investigation
        .steering
        .last()
        .map(|value| format!("\nCurrent user steering within the accepted scope:\n{value}\n"))
        .unwrap_or_default();
    let evidence_reference =
        if role == "skeptic" { format!("\n\n{EVIDENCE_STATES}") } else { String::new() };
    Ok(ModuleAction::Model {
        request: ModuleAgentRequest {
            key: request_key(state, role),
            role: model_role.into(),
            status: status.into(),
            system: format!(
                "{SKILL}\n\nRole boundary:\n{role_guidance}\nThe Rust coordinator's private records are the durable working memory for this role. Do not use context_read or context_update; use only the declared red_team_* functions and advance the current stage.{evidence_reference}"
            ),
            prompt: format!(
                "Campaign `{}`; source snapshot `{}`; stage `{role}`; round {}. Retained stage counts: observations={}, hypotheses={}, probes={}, findings={}. The Rust coordinator owns source authority, execution, evidence admission and classifications. Use only the declared red_team_* functions. Do not write unit tests, patches, or fixes in Phase five.{}\nCoordinator feedback: {}",
                state.campaign.id.value,
                state
                    .active_snapshot()
                    .map_or("none", |snapshot| snapshot.snapshot_digest.as_str()),
                state.investigation.round,
                state.current_observations().count(),
                state.hypotheses.len(),
                state.investigation.probes.len(),
                state.findings.len(),
                steering,
                state.investigation.feedback,
            ),
            cyber_access_program: Some(ModuleCyberAccessProgram::DaybreakBlue),
            tools: vec![],
            functions: functions(role),
        },
    })
}

fn functions(role: &str) -> Vec<ModuleFunction> {
    let mut values = vec![function(
        "red_team_inspect",
        "Read bounded retained campaign data. kind is inventory, source, hypotheses, evidence, or coverage. Evidence may be narrowed to one hypothesis_id. This never reads ambient files.",
        json!({"type":"object","additionalProperties":false,"properties":{"kind":{"type":"string","enum":["inventory","source","hypotheses","evidence","coverage"]},"path":{"type":["string","null"],"maxLength":4096},"hypothesis_id":{"type":["string","null"],"maxLength":128}},"required":["kind"]}),
    )];
    if matches!(role, "inventory" | "discovery") {
        values.push(function(
            "red_team_observe",
            "Retrieve an exact retained source range, or yield to the Rust coordinator so it can request that range through the revocable scoped-source service. A newly admitted range is delivered directly in the next coordinator prompt; do not request it a second time in the same role.",
            json!({"type":"object","additionalProperties":false,"properties":{"path":{"type":"string","minLength":1,"maxLength":4096},"offset":{"type":"integer","minimum":0},"max_bytes":{"type":"integer","minimum":1,"maximum":1048576},"reason":{"type":"string","minLength":1,"maxLength":4096}},"required":["path","offset","max_bytes","reason"]}),
        ));
        values.push(function(
            "red_team_observe_many",
            "Request 1..32 exact source ranges in one bounded handoff. The combined maximum is 512 KiB. The Rust coordinator reads them sequentially through scoped-source authority and delivers all admitted bytes together on the next role turn.",
            json!({"type":"object","additionalProperties":false,"properties":{"requests":{"type":"array","minItems":1,"maxItems":32,"items":{"type":"object","additionalProperties":false,"properties":{"path":{"type":"string","minLength":1,"maxLength":4096},"offset":{"type":"integer","minimum":0},"max_bytes":{"type":"integer","minimum":1,"maximum":524288},"reason":{"type":"string","minLength":1,"maxLength":4096}},"required":["path","offset","max_bytes","reason"]}}},"required":["requests"]}),
        ));
    }
    if role == "inventory" {
        values.push(function(
            "red_team_inventory_commit",
            "Commit the one bounded inventory, threat boundaries, all family routes and exact source evidence used. source_evidence values are the evidence_id strings returned by source observations; unique source or artifact digests are also accepted as safe aliases.",
            json!({"type":"object","additionalProperties":false,"properties":{"surfaces":{"type":"array","minItems":1,"maxItems":512,"items":{"type":"string","minLength":1,"maxLength":4096}},"threat_boundaries":{"type":"array","minItems":1,"maxItems":128,"items":{"type":"string","minLength":1,"maxLength":4096}},"routes":{"type":"array","minItems":15,"maxItems":15,"items":{"type":"object","additionalProperties":false,"properties":{"family":{"type":"string","minLength":1,"maxLength":128},"state":{"type":"string","enum":["unexamined","examined","not_applicable","blocked"]},"reason":{"type":"string","minLength":1,"maxLength":4096},"surfaces":{"type":"array","minItems":1,"maxItems":512,"items":{"type":"string","minLength":1,"maxLength":4096}}},"required":["family","state","reason","surfaces"]}},"source_evidence":{"type":"array","minItems":1,"maxItems":512,"items":{"type":"string","minLength":1,"maxLength":128}}},"required":["surfaces","threat_boundaries","routes","source_evidence"]}),
        ));
    } else if role == "discovery" {
        values.extend([
            function(
                "red_team_discovery_commit",
                "Atomically register at most six missing falsifiable hypotheses. Existing identical hypotheses are reused. Set complete=false if another batch remains, or complete=true to finish discovery and schedule probes. The whole batch either validates or leaves durable state unchanged, and every accepted batch ends this provider request.",
                json!({"type":"object","additionalProperties":false,"properties":{"hypotheses":{"type":"array","minItems":1,"maxItems":6,"items":hypothesis_schema()},"complete":{"type":"boolean"}} ,"required":["hypotheses","complete"]}),
            ),
            function(
                "red_team_hypothesis_register",
                "Compatibility path for registering one falsifiable hypothesis before execution. Prefer red_team_discovery_commit. A null target_path records analysis-only or blocked work; it cannot become runtime-confirmed.",
                hypothesis_schema(),
            ),
            function(
                "red_team_discovery_complete",
                "Finish bounded discovery after concrete hypotheses are registered. This schedules their genuine interface probes; it makes no finding claim.",
                json!({"type":"object","additionalProperties":false,"properties":{}}),
            ),
        ]);
    } else if role == "skeptic" {
        values.extend([
            function(
                "red_team_review_commit",
                "Atomically save at most six missing evidence-bounded independent decisions. Existing adjudications are retained. Set complete=false if another evidence bundle remains, or complete=true to finish review. The whole batch either validates or leaves durable state unchanged, and every accepted batch ends this provider request.",
                json!({"type":"object","additionalProperties":false,"properties":{"decisions":{"type":"array","minItems":1,"maxItems":6,"items":adjudication_schema()},"complete":{"type":"boolean"}} ,"required":["decisions","complete"]}),
            ),
            function(
                "red_team_adjudicate",
                "Compatibility path for saving one evidence-bounded independent review. Prefer red_team_review_commit. The coordinator rejects classifications unsupported by trusted receipts.",
                adjudication_schema(),
            ),
            function(
                "red_team_review_complete",
                "Finish skeptical review only after every registered hypothesis has one retained independent decision.",
                json!({"type":"object","additionalProperties":false,"properties":{}}),
            ),
        ]);
    }
    values
}

fn function(name: &str, description: &str, schema: Value) -> ModuleFunction {
    ModuleFunction { name: name.into(), description: description.into(), schema }
}

fn hypothesis_schema() -> Value {
    json!({"type":"object","additionalProperties":false,"properties":{"family":{"type":"string","minLength":1,"maxLength":128},"origin":{"type":"string","enum":["known_description","unknown_discovery"]},"attacker":{"type":"string","minLength":1,"maxLength":4096},"entry_point":{"type":"string","minLength":1,"maxLength":4096},"prerequisites":{"type":"array","maxItems":64,"items":{"type":"string","minLength":1,"maxLength":4096}},"security_property":{"type":"string","minLength":1,"maxLength":4096},"falsifiable_observation":{"type":"string","minLength":1,"maxLength":4096},"source_evidence":{"type":"array","minItems":1,"maxItems":128,"items":{"type":"string","minLength":1,"maxLength":128}},"target_path":{"type":["string","null"],"maxLength":4096},"attacker_input":{"type":["string","null"],"maxLength":16384},"changed_dimension":{"type":"string","minLength":1,"maxLength":4096}},"required":["family","origin","attacker","entry_point","prerequisites","security_property","falsifiable_observation","source_evidence","target_path","attacker_input","changed_dimension"]})
}

fn adjudication_schema() -> Value {
    json!({"type":"object","additionalProperties":false,"properties":{"hypothesis_id":{"type":"string","minLength":1,"maxLength":128},"classification":{"type":"string","enum":["confirmed","analysis_supported","refuted","not_reproduced","inconclusive","blocked"]},"evidence":{"type":"array","maxItems":256,"items":{"type":"string","minLength":1,"maxLength":128}},"reachability":{"type":"string","minLength":1,"maxLength":8192},"prerequisites":{"type":"string","minLength":1,"maxLength":8192},"oracle":{"type":"string","minLength":1,"maxLength":8192},"impact":{"type":"string","minLength":1,"maxLength":8192},"target_identity":{"type":"string","minLength":1,"maxLength":8192},"counterevidence":{"type":"string","maxLength":8192},"detail":{"type":"string","minLength":1,"maxLength":8192}},"required":["hypothesis_id","classification","evidence","reachability","prerequisites","oracle","impact","target_identity","counterevidence","detail"]})
}

pub(crate) fn tool(parameters: &Value) -> Result<Value, Error> {
    let mut state = crate::state::load(parameters)?;
    let key = required(parameters, "key")?;
    let role = role_for_key(&state, key)?;
    let name = required(parameters, "name")?;
    let arguments: Value = serde_json::from_str(required(parameters, "arguments_json")?)?;
    let result = match name {
        "red_team_inspect" => inspect(&state, &arguments, role),
        "red_team_observe" if matches!(role, "inventory" | "discovery") => {
            observe(parameters, &mut state, &arguments)
        }
        "red_team_observe_many" if matches!(role, "inventory" | "discovery") => {
            observe_many(&mut state, &arguments)
        }
        "red_team_inventory_commit" if role == "inventory" => {
            commit_inventory(&mut state, &arguments)
        }
        "red_team_hypothesis_register" if role == "discovery" => {
            register_hypothesis(&mut state, &arguments)
        }
        "red_team_discovery_commit" if role == "discovery" => {
            discovery_commit(&mut state, &arguments)
        }
        "red_team_discovery_complete" if role == "discovery" => discovery_complete(&mut state),
        "red_team_adjudicate" if role == "skeptic" => adjudicate(&mut state, &arguments),
        "red_team_review_commit" if role == "skeptic" => review_commit(&mut state, &arguments),
        "red_team_review_complete" if role == "skeptic" => review_complete(&mut state),
        _ => Err(invalid("function is unavailable to the current investigation role")),
    }?;
    crate::state::save(parameters, &state)?;
    Ok(result)
}

pub(crate) fn model_result(parameters: &Value) -> Result<ModuleAction, Error> {
    let mut state = crate::state::load(parameters)?;
    let key = required(parameters, "key")?;
    validate_model_result_key(&state, key)?;
    if let Some(action) = request_next_source_read(parameters, &mut state)? {
        return Ok(action);
    }
    state.investigation.round = state
        .investigation
        .round
        .checked_add(1)
        .ok_or_else(|| invalid("investigation round overflow"))?;
    crate::state::save(parameters, &state)?;
    next(parameters, &profile(parameters), &mut state)
}

pub(crate) fn request_next_source_read(
    parameters: &Value,
    state: &mut State,
) -> Result<Option<ModuleAction>, Error> {
    let read = state.investigation.queued_read.take().or_else(|| {
        (!state.investigation.queued_reads.is_empty())
            .then(|| state.investigation.queued_reads.remove(0))
    });
    let Some(read) = read else {
        return Ok(None);
    };
    let authority = state
        .active_handle()
        .ok_or_else(|| invalid("source authority was revoked before requested observation"))?;
    let key = format!(
        "red-team-investigation-read-{}",
        state.investigation.reuse.source_reads_requested + 1
    );
    state.investigation.reuse.source_reads_requested =
        state.investigation.reuse.source_reads_requested.saturating_add(1);
    state.pending = Some(PendingRequest::Read {
        key: key.clone(),
        authority: authority.clone(),
        path: read.path.clone(),
        offset: read.offset,
        maximum_bytes: read.maximum_bytes,
    });
    if !state.investigation.batch_read_active {
        state.investigation.feedback = format!(
            "Scoped source observation is in progress for `{}` because: {}.",
            read.path, read.reason
        );
    }
    crate::state::save(parameters, state)?;
    Ok(Some(ModuleAction::HostService {
        request: ModuleHostRequest {
            key,
            capability: HOST_CAPABILITY_SCOPED_SOURCE.into(),
            version: 1,
            operation: "read".into(),
            input: serde_json::to_value(ScopedSourceReadRequest {
                schema: 1,
                authority,
                path: read.path,
                offset: read.offset,
                maximum_bytes: read.maximum_bytes,
            })?,
        },
    }))
}

fn inspect(state: &State, arguments: &Value, role: &str) -> Result<Value, Error> {
    match required(arguments, "kind")? {
        "inventory" if role == "inventory" => Ok(json!({
            "campaign":state.campaign.id.value,
            "snapshot":state.active_snapshot().map(|value|value.snapshot_digest.clone()),
            "manifest_entries":state.investigation.manifest_entries,
            "manifest_complete":state.investigation.manifest_complete,
            "retained_observations":state.current_observations().map(observation_summary).collect::<Vec<_>>(),
            "supported_families":security_families(),
        })),
        "inventory" => Ok(json!({
            "campaign":state.campaign.id.value,
            "snapshot":state.active_snapshot().map(|value|value.snapshot_digest.clone()),
            "manifest_entry_count":state.investigation.manifest_entries.len(),
            "retained_observations":state.current_observations().map(observation_summary).collect::<Vec<_>>(),
            "committed_inventory":state.investigation.inventory,
        })),
        "source" => {
            let path = arguments["path"].as_str();
            Ok(
                json!({"observations":state.current_observations().filter(|item|path.is_none_or(|path|item.path==path)).map(observation_summary).collect::<Vec<_>>()}),
            )
        }
        "hypotheses" => Ok(json!({
            "hypotheses":state.hypotheses,
            "plans":state.investigation.hypothesis_plans,
        })),
        "evidence" => inspect_evidence(state, arguments),
        "coverage" => Ok(json!({
            "coverage":state.coverage.iter().map(|record|json!({
                "family":record.family,
                "surface":record.surface,
                "state":record.state,
                "reason":record.reason,
            })).collect::<Vec<_>>()
        })),
        _ => Err(invalid("unknown red_team_inspect kind")),
    }
}

fn inspect_evidence(state: &State, arguments: &Value) -> Result<Value, Error> {
    let Some(hypothesis_id) = arguments["hypothesis_id"].as_str() else {
        let adjudicated = state
            .findings
            .iter()
            .map(|finding| finding.hypothesis_id.as_str())
            .collect::<BTreeSet<_>>();
        let pending = state
            .hypotheses
            .iter()
            .filter(|hypothesis| !adjudicated.contains(hypothesis.id.value.as_str()))
            .take(6)
            .map(|hypothesis| evidence_bundle(state, &hypothesis.id.value))
            .collect::<Result<Vec<_>, Error>>()?;
        let pending_total = state.hypotheses.len().saturating_sub(adjudicated.len());
        return Ok(json!({
            "evidence_bundles":pending,
            "pending_total":pending_total,
            "bundle_limit":6,
            "remaining_after_bundle":pending_total.saturating_sub(6),
            "adjudicated_hypotheses":state.findings.iter().map(|finding|finding.hypothesis_id.clone()).collect::<Vec<_>>(),
        }));
    };
    evidence_bundle(state, hypothesis_id)
}

fn evidence_bundle(state: &State, hypothesis_id: &str) -> Result<Value, Error> {
    if !state.hypotheses.iter().any(|record| record.id.value == hypothesis_id) {
        return Err(invalid("evidence inspection names an unknown hypothesis"));
    }
    let plan = state
        .investigation
        .hypothesis_plans
        .iter()
        .find(|plan| plan.hypothesis_id == hypothesis_id);
    let source_ids = plan
        .map(|plan| {
            plan.source_evidence.iter().map(|id| id.value.as_str()).collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let probes = state
        .investigation
        .probes
        .iter()
        .filter(|probe| probe.hypothesis_id == hypothesis_id)
        .collect::<Vec<_>>();
    let job_ids =
        probes.iter().filter_map(|probe| probe.host_job_id.as_deref()).collect::<BTreeSet<_>>();
    Ok(json!({
        "hypothesis":state.hypotheses.iter().find(|record|record.id.value==hypothesis_id),
        "plan":plan,
        "source":state.current_observations().filter(|observation|source_ids.contains(observation.record.id.value.as_str())).map(observation_summary).collect::<Vec<_>>(),
        "probes":probes,
        "receipts":state.job_receipts.iter().filter(|receipt|job_ids.contains(receipt.job_id.as_str())).collect::<Vec<_>>(),
        "finding":state.findings.iter().find(|finding|finding.hypothesis_id==hypothesis_id),
        "reviews":state.reviews.iter().filter(|review|state.findings.iter().any(|finding|finding.hypothesis_id==hypothesis_id && review.subject==finding.id)).collect::<Vec<_>>(),
    }))
}

fn observation_summary(observation: &crate::state::SourceObservation) -> Value {
    json!({
        "id":observation.record.id.value,
        "path":observation.path,
        "source_digest":observation.source_digest,
        "source_bytes":observation.source_bytes,
        "range_start":observation.range_start,
        "range_end":observation.range_end,
        "artifact_digest":observation.record.artifact_digest,
        "reuse_count":observation.reuse_count,
    })
}

fn observe(parameters: &Value, state: &mut State, arguments: &Value) -> Result<Value, Error> {
    let path = required(arguments, "path")?.to_owned();
    let offset = arguments["offset"].as_u64().ok_or_else(|| invalid("missing offset"))?;
    let maximum_bytes = arguments["max_bytes"]
        .as_u64()
        .ok_or_else(|| invalid("missing max_bytes"))?
        .clamp(1, MAX_SOURCE_PAGE);
    let reason = required(arguments, "reason")?.to_owned();
    if !state.investigation.manifest_entries.iter().any(|entry| entry.path == path) {
        return Err(invalid("requested path is not in the exact captured source manifest"));
    }
    if let Some(index) = state.observations.iter().position(|observation| {
        observation.state == crate::state::ObservationState::Current
            && observation.path == path
            && observation.range_start <= offset
            && observation.range_end
                >= offset.saturating_add(maximum_bytes).min(observation.source_bytes)
    }) {
        let observation = &mut state.observations[index];
        observation.reuse_count = observation.reuse_count.saturating_add(1);
        let range_start = observation.range_start;
        let range_end = observation.range_end;
        let evidence_id = observation.record.id.value.clone();
        let retained = observation.retained_path.clone().ok_or_else(|| {
            invalid("legacy observation has no retained source bytes; request it once")
        })?;
        state.investigation.reuse.source_reads_reused =
            state.investigation.reuse.source_reads_reused.saturating_add(1);
        let bytes = fs::read(crate::state::private_root(parameters)?.join(retained))?;
        return Ok(json!({
            "retained":true,
            "reused":true,
            "path":path,
            "range_start":range_start,
            "range_end":range_end,
            "evidence_id":evidence_id,
            "text":String::from_utf8_lossy(&bytes),
        }));
    }
    state.investigation.queued_read = Some(QueuedRead { path, offset, maximum_bytes, reason });
    Ok(
        json!({"retained":false,"request_complete":true,"handoff":"The Rust coordinator will request this exact range through the scoped-source service, then resume the same role context."}),
    )
}

fn observe_many(state: &mut State, arguments: &Value) -> Result<Value, Error> {
    let requests =
        arguments["requests"].as_array().ok_or_else(|| invalid("missing batch source requests"))?;
    if requests.is_empty() || requests.len() > MAX_BATCH_SOURCE_RANGES {
        return Err(invalid("batch source requests must contain 1..32 ranges"));
    }
    if state.investigation.queued_read.is_some() || !state.investigation.queued_reads.is_empty() {
        return Err(invalid("another source observation handoff is already pending"));
    }
    let mut total = 0_u64;
    let mut seen = BTreeSet::new();
    let mut queued = Vec::new();
    let mut retained = Vec::new();
    for request in requests {
        let path = required(request, "path")?.to_owned();
        let offset = request["offset"].as_u64().ok_or_else(|| invalid("missing offset"))?;
        let maximum_bytes = request["max_bytes"]
            .as_u64()
            .ok_or_else(|| invalid("missing max_bytes"))?
            .clamp(1, MAX_BATCH_SOURCE_BYTES);
        let reason = required(request, "reason")?.to_owned();
        if !state.investigation.manifest_entries.iter().any(|entry| entry.path == path) {
            return Err(invalid(format!(
                "batch requested path `{path}` is not in the exact captured source manifest"
            )));
        }
        if !seen.insert((path.clone(), offset, maximum_bytes)) {
            return Err(invalid("batch source requests contain a duplicate range"));
        }
        total = total
            .checked_add(maximum_bytes)
            .ok_or_else(|| invalid("batch source byte total overflow"))?;
        if total > MAX_BATCH_SOURCE_BYTES {
            return Err(invalid("batch source requests exceed the 512 KiB combined maximum"));
        }
        if let Some(observation) = state.current_observations().find(|observation| {
            observation.path == path
                && observation.range_start <= offset
                && observation.range_end
                    >= offset.saturating_add(maximum_bytes).min(observation.source_bytes)
        }) {
            retained.push(json!({"path":path,"evidence_id":observation.record.id.value}));
        } else {
            queued.push(QueuedRead { path, offset, maximum_bytes, reason });
        }
    }
    if queued.is_empty() {
        return Ok(json!({
            "retained":retained,
            "queued":0,
            "request_complete":false,
            "instruction":"Every requested range is already retained. Use red_team_observe only if this role genuinely needs the exact bytes again."
        }));
    }
    state.investigation.queued_reads = queued;
    state.investigation.batch_read_active = true;
    state.investigation.feedback =
        "# Bounded source observation batch\n\nThe Rust coordinator is collecting the requested exact ranges. No target code is being executed."
            .into();
    Ok(json!({
        "retained":retained,
        "queued":state.investigation.queued_reads.len(),
        "request_complete":true,
        "handoff":"The Rust coordinator will read every queued range through scoped-source authority and resume this role once with the combined retained bytes."
    }))
}

fn commit_inventory(state: &mut State, arguments: &Value) -> Result<Value, Error> {
    let input: InventoryInput = serde_json::from_value(arguments.clone())?;
    nonempty_list(&input.surfaces, "inventory surfaces")?;
    nonempty_list(&input.threat_boundaries, "threat boundaries")?;
    if input.routes.len() != security_families().len() {
        return Err(invalid("inventory must route every supported security family exactly once"));
    }
    let expected = security_families().into_iter().collect::<BTreeSet<_>>();
    let actual = input.routes.iter().map(|route| route.family.as_str()).collect::<BTreeSet<_>>();
    if actual != expected || actual.len() != input.routes.len() {
        return Err(invalid("inventory family routes are missing, duplicated, or unknown"));
    }
    let evidence = evidence_ids(state, &input.source_evidence)?;
    if evidence.is_empty() {
        return Err(invalid("inventory must bind at least one exact retained source observation"));
    }
    let routes = input
        .routes
        .into_iter()
        .map(|route| {
            if route.reason.trim().is_empty() || route.surfaces.is_empty() {
                return Err(invalid("every family route needs a reason and at least one surface"));
            }
            Ok(FamilyRoute {
                family: route.family,
                state: coverage_state(&route.state)?,
                reason: route.reason,
                surfaces: route.surfaces,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    for coverage in &mut state.coverage {
        let route = routes
            .iter()
            .find(|route| route.family == coverage.family)
            .expect("validated complete routes");
        coverage.state = route.state;
        coverage.surface = route.surfaces.join(", ");
        coverage.reason = route.reason.clone();
        coverage.evidence = evidence.clone();
    }
    state.investigation.inventory = Some(InventoryRecord {
        surfaces: input.surfaces,
        threat_boundaries: input.threat_boundaries,
        routes,
        source_observations: evidence,
    });
    state.investigation.stage = InvestigationStage::Discovery;
    state.investigation.feedback =
        "The bounded inventory is committed. Reuse it; investigate small falsifiable hypotheses without another repository-wide pass."
            .into();
    Ok(json!({"saved":true,"request_complete":true,"next_stage":"discovery"}))
}

fn register_hypothesis(state: &mut State, arguments: &Value) -> Result<Value, Error> {
    let input: HypothesisInput = serde_json::from_value(arguments.clone())?;
    if !security_families().contains(&input.family.as_str()) {
        return Err(invalid("hypothesis names an unsupported security family"));
    }
    for value in [
        &input.attacker,
        &input.entry_point,
        &input.security_property,
        &input.falsifiable_observation,
        &input.changed_dimension,
    ] {
        if value.trim().is_empty() {
            return Err(invalid("hypothesis fields and changed dimension must be nonempty"));
        }
    }
    let evidence = evidence_ids(state, &input.source_evidence)?;
    if evidence.is_empty() {
        return Err(invalid("hypothesis requires exact retained source evidence"));
    }
    if input.target_path.is_some() != input.attacker_input.is_some() {
        return Err(invalid("target_path and attacker_input must both be present or both be null"));
    }
    if let Some(path) = &input.target_path
        && !state.investigation.manifest_entries.iter().any(|entry| entry.path == *path)
    {
        return Err(invalid("probe target is not in the captured source manifest"));
    }
    let origin = match input.origin.as_str() {
        "known_description" => HypothesisOrigin::KnownDescription,
        "unknown_discovery" => HypothesisOrigin::UnknownDiscovery,
        _ => return Err(invalid("unknown hypothesis origin")),
    };
    if let Some(existing) = state.investigation.hypothesis_plans.iter().find(|plan| {
        plan.family == input.family
            && plan.origin == origin
            && plan.source_evidence == evidence
            && plan.target_path == input.target_path
            && plan.attacker_input == input.attacker_input
            && plan.changed_dimension == input.changed_dimension
            && state.hypotheses.iter().any(|hypothesis| {
                hypothesis.id.value == plan.hypothesis_id
                    && hypothesis.attacker == input.attacker
                    && hypothesis.entry_point == input.entry_point
                    && hypothesis.prerequisites == input.prerequisites
                    && hypothesis.security_property == input.security_property
                    && hypothesis.falsifiable_observation == input.falsifiable_observation
            })
    }) {
        return Ok(json!({
            "saved":true,
            "reused":true,
            "hypothesis_id":existing.hypothesis_id,
            "request_complete":false
        }));
    }
    let number = state.hypotheses.len() + 1;
    if number > 128 {
        return Err(invalid("bounded campaign hypothesis limit reached"));
    }
    let id =
        RecordId::new(RecordKind::Hypothesis, format!("hypothesis-{number}")).map_err(invalid)?;
    let snapshot = state
        .active_snapshot()
        .ok_or_else(|| invalid("hypothesis has no active source snapshot"))?
        .id
        .clone();
    state.hypotheses.push(HypothesisRecord {
        schema: RECORD_SCHEMA_VERSION,
        id: id.clone(),
        campaign: state.campaign.id.clone(),
        source_snapshot: snapshot,
        attacker: input.attacker,
        entry_point: input.entry_point,
        prerequisites: input.prerequisites,
        security_property: input.security_property,
        falsifiable_observation: input.falsifiable_observation,
        state: HypothesisState::Proposed,
        supersedes: None,
    });
    state.investigation.hypothesis_plans.push(HypothesisPlan {
        hypothesis_id: id.value.clone(),
        family: input.family,
        origin,
        source_evidence: evidence,
        target_path: input.target_path,
        attacker_input: input.attacker_input,
        changed_dimension: input.changed_dimension,
    });
    Ok(json!({"saved":true,"hypothesis_id":id.value,"request_complete":false}))
}

fn discovery_commit(state: &mut State, arguments: &Value) -> Result<Value, Error> {
    let hypotheses = arguments["hypotheses"]
        .as_array()
        .ok_or_else(|| invalid("discovery commit requires a hypotheses array"))?;
    if hypotheses.is_empty() || hypotheses.len() > 6 {
        return Err(invalid("discovery commit requires one to six hypotheses"));
    }
    let complete = arguments["complete"]
        .as_bool()
        .ok_or_else(|| invalid("discovery commit requires a complete boolean"))?;
    let mut candidate = state.clone();
    let mut retained = Vec::with_capacity(hypotheses.len());
    for hypothesis in hypotheses {
        let result = register_hypothesis(&mut candidate, hypothesis)?;
        retained.push(json!({
            "hypothesis_id":result["hypothesis_id"],
            "reused":result["reused"].as_bool().unwrap_or(false),
        }));
    }
    if complete {
        discovery_complete(&mut candidate)?;
    } else {
        candidate.investigation.feedback = format!(
            "A transactional discovery batch retained {} hypothesis entries. Start a fresh provider turn and add only missing hypotheses; do not repeat source discovery.",
            retained.len()
        );
    }
    *state = candidate;
    Ok(json!({
        "saved":true,
        "hypotheses":retained,
        "request_complete":true,
        "next_stage":if complete { "probing" } else { "discovery" }
    }))
}

fn discovery_complete(state: &mut State) -> Result<Value, Error> {
    if state.hypotheses.is_empty() {
        return Err(invalid("bounded discovery must retain at least one falsifiable hypothesis"));
    }
    state.investigation.stage = InvestigationStage::Probing;
    state.investigation.feedback =
        "Discovery is committed. The Rust coordinator is scheduling only registered contained probes."
            .into();
    Ok(json!({"saved":true,"request_complete":true,"next_stage":"probing"}))
}

fn schedule_probe(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut State,
) -> Result<ModuleAction, Error> {
    if let Some(pending) = &state.pending {
        return crate::resume_pending(pending);
    }
    let next_plan = state.investigation.hypothesis_plans.iter().find(|plan| {
        plan.target_path.is_some()
            && !state
                .investigation
                .probes
                .iter()
                .any(|probe| probe.hypothesis_id == plan.hypothesis_id)
    });
    let Some(plan) = next_plan.cloned() else {
        state.investigation.stage = InvestigationStage::Skeptic;
        state.investigation.feedback = "All scheduled proof cases reached a retained terminal or blocked state. Review raw receipts independently; do not inherit discovery conclusions.".into();
        state.investigation.round = state.investigation.round.saturating_add(1);
        crate::state::save(parameters, state)?;
        return next(parameters, profile, state);
    };
    let authority = state
        .active_handle()
        .ok_or_else(|| invalid("source authority is unavailable for contained probe"))?;
    let target_path = plan.target_path.expect("filtered target");
    let attacker_input = plan.attacker_input.expect("paired input");
    let attempt_number = state.investigation.probes.len() + 1;
    let id = format!("probe-{attempt_number}");
    let request = ModuleJobRequest {
        schema: 1,
        source_handle: authority.handle,
        scope_revision: authority.scope_revision,
        operation: "linux.canary-disclosure.v1".into(),
        specification: json!({"target_path":target_path,"attacker_input":attacker_input}),
        limits: ModuleJobLimits {
            memory_bytes: 128 * 1024 * 1024,
            storage_bytes: 16 * 1024 * 1024,
            cpu_millis: 2_000,
            wall_millis: 20_000,
            processes: 8,
        },
    };
    let key = format!("red-team-investigation-submit-{attempt_number}");
    state.investigation.probes.push(ProbeAttempt {
        id,
        hypothesis_id: plan.hypothesis_id.clone(),
        target_path,
        attacker_input,
        changed_dimension: plan.changed_dimension,
        state: ProbeState::Planned,
        host_job_id: None,
        evidence: None,
        detail: "registered before host execution".into(),
    });
    if let Some(hypothesis) =
        state.hypotheses.iter_mut().find(|hypothesis| hypothesis.id.value == plan.hypothesis_id)
    {
        hypothesis.state = HypothesisState::Investigating;
    }
    state.pending = Some(PendingRequest::JobSubmit { key: key.clone(), request: request.clone() });
    crate::state::save(parameters, state)?;
    Ok(ModuleAction::HostService {
        request: ModuleHostRequest {
            key,
            capability: HOST_CAPABILITY_OWNED_JOBS.into(),
            version: 1,
            operation: "submit".into(),
            input: serde_json::to_value(request)?,
        },
    })
}

pub(crate) fn job_submitted(state: &mut State, job_id: &str) {
    if let Some(probe) = state
        .investigation
        .probes
        .iter_mut()
        .rev()
        .find(|probe| probe.host_job_id.is_none() && probe.state == ProbeState::Planned)
    {
        probe.host_job_id = Some(job_id.into());
        probe.state = ProbeState::Running;
        probe.detail = "host accepted the exact contained proof request".into();
    }
}

pub(crate) fn job_status(state: &mut State, status: &ModuleJobStatus) -> bool {
    let Some(probe) = state
        .investigation
        .probes
        .iter_mut()
        .find(|probe| probe.host_job_id.as_deref() == Some(status.job_id.as_str()))
    else {
        return false;
    };
    match status.phase {
        ModuleJobPhase::Queued | ModuleJobPhase::Running => {
            probe.state = ProbeState::Running;
            probe.detail = status.detail.clone();
            false
        }
        ModuleJobPhase::Completed | ModuleJobPhase::Failed | ModuleJobPhase::Cancelled => {
            probe.state = ProbeState::Completed;
            probe.detail = status.detail.clone();
            probe.evidence = status.receipt.as_ref().and_then(|receipt| {
                let receipt_digest = digest(&serde_json::to_vec(receipt).ok()?);
                RecordId::new(RecordKind::Evidence, format!("execution-{}", &receipt_digest[..24]))
                    .ok()
            });
            true
        }
        ModuleJobPhase::Indeterminate => {
            probe.state = ProbeState::Blocked;
            probe.detail = status.detail.clone();
            true
        }
    }
}

pub(crate) fn host_failure(state: &mut State, pending: &PendingRequest, detail: &str) {
    if matches!(pending, PendingRequest::JobSubmit { .. } | PendingRequest::JobPoll { .. })
        && let Some(probe) = state
            .investigation
            .probes
            .iter_mut()
            .rev()
            .find(|probe| matches!(probe.state, ProbeState::Planned | ProbeState::Running))
    {
        probe.state = ProbeState::Blocked;
        probe.detail = detail.into();
    }
    state.investigation.feedback = format!(
        "A host operation did not complete and was retained as blocked evidence: {detail}. Continue other bounded work without weakening the required interface."
    );
}

pub(crate) fn poll_action(state: &mut State, job_id: String) -> Result<ModuleAction, Error> {
    let key = format!("red-team-investigation-poll-{}", &job_id[..job_id.len().min(16)]);
    let request = ModuleJobStatusRequest { schema: 1, job_id, wait_millis: 750 };
    state.pending = Some(PendingRequest::JobPoll { key: key.clone(), request: request.clone() });
    Ok(ModuleAction::HostService {
        request: ModuleHostRequest {
            key,
            capability: HOST_CAPABILITY_OWNED_JOBS.into(),
            version: 1,
            operation: "poll".into(),
            input: serde_json::to_value(request)?,
        },
    })
}

fn adjudicate(state: &mut State, arguments: &Value) -> Result<Value, Error> {
    let input: AdjudicationInput = serde_json::from_value(arguments.clone())?;
    let hypothesis = state
        .hypotheses
        .iter()
        .find(|hypothesis| hypothesis.id.value == input.hypothesis_id)
        .ok_or_else(|| invalid("review names an unknown hypothesis"))?;
    if state.findings.iter().any(|finding| finding.hypothesis_id == input.hypothesis_id) {
        return Err(invalid("hypothesis already has an adjudicated finding revision"));
    }
    for value in [
        &input.reachability,
        &input.prerequisites,
        &input.oracle,
        &input.impact,
        &input.target_identity,
        &input.detail,
    ] {
        if value.trim().is_empty() {
            return Err(invalid("skeptical review must address every required challenge"));
        }
    }
    let classification = finding_classification(&input.classification)?;
    let mut evidence = evidence_ids(state, &input.evidence)?;
    let receipts = receipts_for(state, &input.hypothesis_id);
    let violation = receipts
        .iter()
        .any(|receipt| matches!(receipt.verdict, ModuleJobVerdict::ViolationObserved));
    let held = receipts
        .iter()
        .any(|receipt| matches!(receipt.verdict, ModuleJobVerdict::PropertyHeldForCase));
    match classification {
        FindingClassification::Confirmed if !violation => {
            return Err(invalid("confirmed requires a trusted violation-observed receipt"));
        }
        FindingClassification::Refuted
            if input.counterevidence.trim().is_empty() || evidence.is_empty() =>
        {
            return Err(invalid(
                "refuted requires concrete counterevidence bound to retained evidence",
            ));
        }
        FindingClassification::NotReproduced if !held => {
            return Err(invalid(
                "not_reproduced requires at least one trusted property-held-for-case receipt",
            ));
        }
        FindingClassification::AnalysisSupported if evidence.is_empty() => {
            return Err(invalid("analysis_supported requires retained source evidence"));
        }
        _ => {}
    }
    for probe in
        state.investigation.probes.iter().filter(|probe| probe.hypothesis_id == input.hypothesis_id)
    {
        if let Some(id) = &probe.evidence
            && !evidence.contains(id)
        {
            evidence.push(id.clone());
        }
    }
    let number = state.findings.len() + 1;
    let finding_id =
        RecordId::new(RecordKind::Finding, format!("finding-{number}")).map_err(invalid)?;
    let review_id =
        RecordId::new(RecordKind::Review, format!("review-{number}")).map_err(invalid)?;
    let detail = format!(
        "Reachability: {}\nPrerequisites: {}\nOracle: {}\nImpact: {}\nTarget identity: {}\nCounterevidence: {}\nDecision: {}",
        input.reachability,
        input.prerequisites,
        input.oracle,
        input.impact,
        input.target_identity,
        if input.counterevidence.trim().is_empty() {
            "none retained"
        } else {
            input.counterevidence.as_str()
        },
        input.detail,
    );
    state.reviews.push(ReviewRecord {
        schema: RECORD_SCHEMA_VERSION,
        id: review_id.clone(),
        campaign: state.campaign.id.clone(),
        subject: finding_id.clone(),
        decision: ReviewDecision::Accepted,
        evidence: evidence.clone(),
        detail,
        supersedes: None,
    });
    state.findings.push(FindingRecord {
        schema: RECORD_SCHEMA_VERSION,
        id: finding_id,
        campaign: state.campaign.id.clone(),
        source_snapshot: hypothesis.source_snapshot.clone(),
        hypothesis_id: input.hypothesis_id.clone(),
        classification,
        evidence,
        review: Some(review_id),
        supersedes: None,
    });
    if let Some(hypothesis) =
        state.hypotheses.iter_mut().find(|hypothesis| hypothesis.id.value == input.hypothesis_id)
    {
        hypothesis.state = HypothesisState::Adjudicated;
    }
    Ok(json!({"saved":true,"finding":format!("finding-{number}"),"request_complete":false}))
}

fn review_commit(state: &mut State, arguments: &Value) -> Result<Value, Error> {
    let decisions = arguments["decisions"]
        .as_array()
        .ok_or_else(|| invalid("review commit requires a decisions array"))?;
    if decisions.is_empty() || decisions.len() > 6 {
        return Err(invalid("review commit requires one to six decisions"));
    }
    let complete = arguments["complete"]
        .as_bool()
        .ok_or_else(|| invalid("review commit requires a complete boolean"))?;
    let mut candidate = state.clone();
    let mut retained = Vec::with_capacity(decisions.len());
    for decision in decisions {
        let hypothesis_id = required(decision, "hypothesis_id")?;
        if let Some(existing) =
            candidate.findings.iter().find(|finding| finding.hypothesis_id == hypothesis_id)
        {
            retained.push(json!({
                "hypothesis_id":hypothesis_id,
                "finding":existing.id.value,
                "reused":true,
            }));
            continue;
        }
        let result = adjudicate(&mut candidate, decision)?;
        retained.push(json!({
            "hypothesis_id":hypothesis_id,
            "finding":result["finding"],
            "reused":false,
        }));
    }
    if complete {
        review_complete(&mut candidate)?;
    } else {
        candidate.investigation.feedback = format!(
            "A transactional skeptical-review batch retained {} decisions. Start a fresh reviewer turn for only the remaining unadjudicated hypotheses.",
            retained.len()
        );
    }
    *state = candidate;
    Ok(json!({
        "saved":true,
        "decisions":retained,
        "request_complete":true,
        "next_stage":if complete { "complete" } else { "skeptic" }
    }))
}

fn review_complete(state: &mut State) -> Result<Value, Error> {
    if state.findings.len() != state.hypotheses.len() {
        return Err(invalid(
            "skeptical review is incomplete; every hypothesis needs one retained decision",
        ));
    }
    state.investigation.stage = InvestigationStage::Complete;
    state.campaign.state = crate::records::CampaignState::Completed;
    state.investigation.feedback = "Independent skeptical adjudication completed. Report only the bounded retained findings and explicit coverage gaps.".into();
    Ok(json!({"saved":true,"request_complete":true,"next_stage":"complete"}))
}

fn evidence_ids(state: &State, values: &[String]) -> Result<Vec<RecordId>, Error> {
    let mut result = Vec::new();
    for value in values {
        let exact_source = state
            .observations
            .iter()
            .filter(|item| item.state == crate::state::ObservationState::Current)
            .find(|item| item.record.id.value == *value)
            .map(|item| item.record.id.clone());
        let exact_job = state
            .job_evidence
            .iter()
            .find(|item| item.id.value == *value)
            .map(|item| item.id.clone());
        let mut aliases = state
            .observations
            .iter()
            .filter(|item| item.state == crate::state::ObservationState::Current)
            .filter(|item| item.source_digest == *value || item.record.artifact_digest == *value)
            .map(|item| item.record.id.clone())
            .collect::<Vec<_>>();
        aliases.sort_by(|left, right| left.value.cmp(&right.value));
        aliases.dedup();
        let id = match (exact_source.or(exact_job), aliases.as_slice()) {
            (Some(id), _) => id,
            (None, [id]) => id.clone(),
            (None, []) => {
                return Err(invalid(format!(
                    "unknown retained evidence identity or unique digest `{value}`; use an evidence_id returned by red_team_inspect or the source-observation handoff"
                )));
            }
            (None, _) => {
                return Err(invalid(format!(
                    "ambiguous retained evidence digest `{value}`; use the exact evidence_id returned for the intended source range"
                )));
            }
        };
        if !result.contains(&id) {
            result.push(id);
        }
    }
    Ok(result)
}

fn receipts_for<'a>(
    state: &'a State,
    hypothesis_id: &str,
) -> Vec<&'a peritus_plugin_sdk::ModuleJobReceipt> {
    let ids = state
        .investigation
        .probes
        .iter()
        .filter(|probe| probe.hypothesis_id == hypothesis_id)
        .filter_map(|probe| probe.host_job_id.as_deref())
        .collect::<BTreeSet<_>>();
    state.job_receipts.iter().filter(|receipt| ids.contains(receipt.job_id.as_str())).collect()
}

fn role_for_key<'a>(state: &State, key: &'a str) -> Result<&'a str, Error> {
    let role = match state.investigation.stage {
        InvestigationStage::Inventory => "inventory",
        InvestigationStage::Discovery => "discovery",
        InvestigationStage::Skeptic => "skeptic",
        _ => return Err(invalid("no model role is active for this investigation stage")),
    };
    if request_key(state, role) != key {
        return Err(invalid(
            "request belongs to another investigation role, source snapshot, or campaign",
        ));
    }
    Ok(role)
}

fn validate_model_result_key(state: &State, key: &str) -> Result<(), Error> {
    let roles: &[&str] = match state.investigation.stage {
        InvestigationStage::Inventory => &["inventory"],
        InvestigationStage::Discovery => &["inventory", "discovery"],
        InvestigationStage::Probing => &["discovery"],
        InvestigationStage::Skeptic => &["skeptic"],
        InvestigationStage::Complete => &["skeptic"],
        InvestigationStage::NotStarted => &[],
    };
    if roles.iter().any(|role| request_key(state, role) == key) {
        Ok(())
    } else {
        Err(invalid(
            "model result belongs to another investigation role, source snapshot, or campaign",
        ))
    }
}

fn request_key(state: &State, role: &str) -> String {
    let snapshot =
        state.active_snapshot().map_or("none", |snapshot| &snapshot.snapshot_digest[..16]);
    format!("red-team-{role}-{snapshot}-r{}", state.investigation.round)
}

fn coverage_state(value: &str) -> Result<CoverageState, Error> {
    match value {
        "unexamined" => Ok(CoverageState::Unexamined),
        "examined" => Ok(CoverageState::Examined),
        "not_applicable" => Ok(CoverageState::NotApplicable),
        "blocked" => Ok(CoverageState::Blocked),
        _ => Err(invalid("unknown coverage state")),
    }
}

fn finding_classification(value: &str) -> Result<FindingClassification, Error> {
    match value {
        "confirmed" => Ok(FindingClassification::Confirmed),
        "analysis_supported" => Ok(FindingClassification::AnalysisSupported),
        "refuted" => Ok(FindingClassification::Refuted),
        "not_reproduced" => Ok(FindingClassification::NotReproduced),
        "inconclusive" => Ok(FindingClassification::Inconclusive),
        "blocked" => Ok(FindingClassification::Blocked),
        _ => Err(invalid("unknown finding classification")),
    }
}

fn nonempty_list(values: &[String], label: &str) -> Result<(), Error> {
    if values.is_empty() || values.iter().any(|value| value.trim().is_empty()) {
        return Err(invalid(format!("{label} must contain nonempty values")));
    }
    Ok(())
}

fn provider_routes(parameters: &Value) -> Vec<ProviderRouteRecord> {
    parameters["provider_routes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|value| serde_json::from_value(value.clone()).ok())
        .collect()
}

fn required<'a>(value: &'a Value, key: &str) -> Result<&'a str, Error> {
    value[key].as_str().ok_or_else(|| invalid(format!("missing {key}")))
}

fn profile(parameters: &Value) -> Option<ModuleHostProfile> {
    serde_json::from_value(parameters.get("host_profile")?.clone()).ok()
}

fn reply(
    text: impl Into<String>,
    profile: &Option<ModuleHostProfile>,
    actions: Vec<ModuleMenuAction>,
) -> ModuleAction {
    let mut text = text.into();
    if let Some(profile) = profile {
        text.push_str(&format!("\n\nHost profile v{} retained.", profile.schema));
    }
    ModuleAction::Reply { text, actions, attachment: None }
}

pub(crate) fn actions(state: &State) -> Vec<ModuleMenuAction> {
    let mut actions = vec![action("Investigation status", "status", true)];
    match state.investigation.stage {
        InvestigationStage::NotStarted => {
            actions.push(action("Start investigation", "start", true))
        }
        InvestigationStage::Complete => {}
        _ if state.investigation.paused => {
            actions.push(action("Resume investigation", "resume", true))
        }
        _ => {
            actions.push(action("Pause investigation", "pause", true));
            actions.push(action("Steer investigation", "steer ", false));
        }
    }
    actions.extend([
        action("Coverage ledger", "coverage", true),
        action("Report now", "report", true),
        action("Contained jobs", "jobs", true),
    ]);
    actions
}

fn action(label: &str, arguments: &str, submit: bool) -> ModuleMenuAction {
    ModuleMenuAction { label: label.into(), arguments: arguments.into(), submit }
}
