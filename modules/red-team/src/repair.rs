//! Phase-six automatic copy-only repair, replay, review, and original-byte verification.

use crate::{
    Error, digest, invalid,
    records::{
        CampaignState, FindingClassification, PatchRecord, PatchState, RECORD_SCHEMA_VERSION,
        RecordId, RecordKind, ReviewDecision, ReviewRecord,
    },
    state::{
        PatchCaseCategory, PatchCasePlan, PatchCaseState, PatchPlan, PendingRequest, RepairStage,
        State,
    },
};
use peritus_plugin_sdk::{
    HOST_CAPABILITY_OWNED_JOBS, HOST_CAPABILITY_SCOPED_SOURCE, ModuleAction, ModuleAgentRequest,
    ModuleCyberAccessProgram, ModuleFunction, ModuleHostProfile, ModuleHostRequest,
    ModuleJobLimits, ModuleJobPhase, ModuleJobRequest, ModuleJobStatus, ModuleJobStatusRequest,
    ModuleJobVerdict, ModuleMenuAction, ScopedSourceVerification, ScopedSourceVerifyRequest,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;

const SKILL: &str = include_str!("../skills/red-team/SKILL.md");
const PATCH_OPERATION: &str = "linux.patched-canary-replay.v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchInput {
    finding_id: String,
    root_cause: String,
    target_path: String,
    expected_source_digest: String,
    replacement: String,
    prerequisites: Vec<String>,
    dependencies: Vec<String>,
    cases: Vec<PatchCaseInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchCaseInput {
    id: String,
    category: String,
    attacker_input: String,
    expected_stdout_fragment: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewInput {
    finding_id: String,
    decision: String,
    detail: String,
}

pub(crate) fn owns_key(parameters: &Value) -> bool {
    parameters["key"].as_str().is_some_and(|key| {
        key.starts_with("red-team-fixer-") || key.starts_with("red-team-patch-reviewer-")
    })
}

pub(crate) fn start(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut State,
) -> Result<ModuleAction, Error> {
    if !matches!(state.investigation.stage, crate::state::InvestigationStage::Complete) {
        return Err(invalid("automatic repair starts only after independent finding adjudication"));
    }
    if matches!(state.repair.stage, RepairStage::NotStarted) {
        state.repair.stage = RepairStage::Planning;
        state.repair.round = 1;
        state.repair.feedback = "Develop a root-cause patch for the next confirmed finding. Use the retained finding, exact source observations and trusted original-violation receipt; do not rediscover the repository.".into();
        state.campaign.state = CampaignState::Active;
        crate::state::save(parameters, state)?;
    }
    next(parameters, profile, state)
}

pub(crate) fn next(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut State,
) -> Result<ModuleAction, Error> {
    if state.investigation.paused {
        return Ok(reply(
            "Red Team repair is paused. Proposed patches, replay cases and completed receipts remain durable.",
            profile,
            crate::investigation::actions(state),
        ));
    }
    match state.repair.stage {
        RepairStage::NotStarted => start(parameters, profile, state),
        RepairStage::Planning => {
            let Some(finding) = next_confirmed_finding(state) else {
                state.repair.stage = RepairStage::VerifyingOriginal;
                crate::state::save(parameters, state)?;
                return request_original_verification(parameters, state);
            };
            state.repair.active_finding = Some(finding);
            crate::state::save(parameters, state)?;
            model(state, "fixer")
        }
        RepairStage::Replaying => schedule_case(parameters, profile, state),
        RepairStage::Reviewing => model(state, "reviewer"),
        RepairStage::VerifyingOriginal => request_original_verification(parameters, state),
        RepairStage::Complete => Ok(reply(
            "Phase-six copy-only repair is complete for the retained confirmed findings. Reports and replay bundles retain exact diffs, case receipts, reviewer decisions, limitations, and the original-workspace byte comparison.",
            profile,
            crate::investigation::actions(state),
        )),
    }
}

fn next_confirmed_finding(state: &State) -> Option<String> {
    state
        .findings
        .iter()
        .filter(|finding| finding.classification == FindingClassification::Confirmed)
        .find(|finding| {
            !state.patches.iter().any(|patch| {
                patch.findings.contains(&finding.id)
                    && patch.state == PatchState::ValidatedForRecordedCases
            })
        })
        .map(|finding| finding.id.value.clone())
}

fn model(state: &State, role: &str) -> Result<ModuleAction, Error> {
    let finding = state
        .repair
        .active_finding
        .as_deref()
        .ok_or_else(|| invalid("repair model has no active confirmed finding"))?;
    let (model_role, status, guidance) = match role {
        "fixer" => (
            "writer",
            "Red Team · copy-only root-cause fix",
            "Inspect the exact retained repair bundle once. Propose a root-cause replacement for the named target file with red_team_patch_commit. Preserve legitimate behavior. Supply attack, legitimate, malformed and adjacent replay cases with independently meaningful expected stdout. Do not write tests, edit the original checkout, weaken the oracle, suppress the detector, or disable the feature.",
        ),
        "reviewer" => (
            "reviewer",
            "Red Team · independent patch review",
            "Inspect the exact diff and every host-authored replay receipt once. Accept only a root-cause fix whose attack, legitimate, malformed and adjacent cases all passed through the fixed host oracle. Reject hollow implementations, feature disabling, detector suppression, hard-coded case handling, changed proof requirements, unrelated edits and unaddressed prerequisites.",
        ),
        _ => return Err(invalid("unknown repair role")),
    };
    let steering = state
        .investigation
        .steering
        .last()
        .map(|value| format!(" Current user steering within the accepted scope: {value}"))
        .unwrap_or_default();
    Ok(ModuleAction::Model {
        request: ModuleAgentRequest {
            key: request_key(state, role),
            role: model_role.into(),
            status: status.into(),
            system: format!(
                "{SKILL}\n\nPhase-six role boundary:\n{guidance}\nThe Rust coordinator and host own source authority, patch materialization, execution, evidence admission and durable state. Use only the declared red_team_patch_* functions."
            ),
            prompt: format!(
                "Campaign `{}`; source `{}`; confirmed finding `{finding}`; repair round {}. Retained patch plans: {}. The original checkout must remain byte-for-byte unchanged. Coordinator feedback: {}{}",
                state.campaign.id.value,
                state
                    .active_snapshot()
                    .map_or("none", |snapshot| snapshot.snapshot_digest.as_str()),
                state.repair.round,
                state.repair.plans.len(),
                state.repair.feedback,
                steering,
            ),
            cyber_access_program: Some(ModuleCyberAccessProgram::DaybreakBlue),
            tools: vec![],
            functions: functions(role),
        },
    })
}

fn functions(role: &str) -> Vec<ModuleFunction> {
    let mut functions = vec![function(
        "red_team_patch_inspect",
        "Read the exact retained finding, source observations, proposed diff, replay matrix and receipts for the active repair. This never reads ambient files.",
        json!({"type":"object","additionalProperties":false,"properties":{}}),
    )];
    if role == "fixer" {
        functions.push(function(
            "red_team_patch_commit",
            "Commit one exact-preimage copy-only replacement and a four-category replay matrix. The host, not this role, creates the diff and executes the replacement in disposable storage.",
            json!({"type":"object","additionalProperties":false,"properties":{
                "finding_id":{"type":"string","minLength":1,"maxLength":128},
                "root_cause":{"type":"string","minLength":1,"maxLength":16384},
                "target_path":{"type":"string","minLength":1,"maxLength":4096},
                "expected_source_digest":{"type":"string","minLength":64,"maxLength":64},
                "replacement":{"type":"string","maxLength":1048576},
                "prerequisites":{"type":"array","maxItems":128,"items":{"type":"string","minLength":1,"maxLength":4096}},
                "dependencies":{"type":"array","maxItems":128,"items":{"type":"string","minLength":1,"maxLength":128}},
                "cases":{"type":"array","minItems":4,"maxItems":32,"items":{"type":"object","additionalProperties":false,"properties":{
                    "id":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[A-Za-z0-9_.-]+$"},
                    "category":{"type":"string","enum":["attack","legitimate","malformed","adjacent"]},
                    "attacker_input":{"type":"string","maxLength":4096},
                    "expected_stdout_fragment":{"type":"string","minLength":1,"maxLength":4096}
                },"required":["id","category","attacker_input","expected_stdout_fragment"]}}
            },"required":["finding_id","root_cause","target_path","expected_source_digest","replacement","prerequisites","dependencies","cases"]}),
        ));
    } else {
        functions.push(function(
            "red_team_patch_review",
            "Save the independent decision for the exact proposed diff and completed replay matrix.",
            json!({"type":"object","additionalProperties":false,"properties":{
                "finding_id":{"type":"string","minLength":1,"maxLength":128},
                "decision":{"type":"string","enum":["accepted","rejected","blocked"]},
                "detail":{"type":"string","minLength":1,"maxLength":16384}
            },"required":["finding_id","decision","detail"]}),
        ));
    }
    functions
}

pub(crate) fn tool(parameters: &Value) -> Result<Value, Error> {
    let mut state = crate::state::load(parameters)?;
    let key = required(parameters, "key")?;
    let role = role_for_key(&state, key)?;
    let name = required(parameters, "name")?;
    let arguments: Value = serde_json::from_str(required(parameters, "arguments_json")?)?;
    let result = match name {
        "red_team_patch_inspect" => inspect(&state),
        "red_team_patch_commit"
            if role == "fixer" && state.repair.stage == RepairStage::Planning =>
        {
            commit_patch(&mut state, &arguments)
        }
        "red_team_patch_review"
            if role == "reviewer" && state.repair.stage == RepairStage::Reviewing =>
        {
            review_patch(&mut state, &arguments)
        }
        _ => Err(invalid("function is unavailable to the current repair role")),
    }?;
    crate::state::save(parameters, &state)?;
    Ok(result)
}

pub(crate) fn model_result(parameters: &Value) -> Result<ModuleAction, Error> {
    let mut state = crate::state::load(parameters)?;
    let key = required(parameters, "key")?;
    role_for_key(&state, key)?;
    state.repair.round =
        state.repair.round.checked_add(1).ok_or_else(|| invalid("repair round overflow"))?;
    crate::state::save(parameters, &state)?;
    next(parameters, &profile(parameters), &mut state)
}

fn inspect(state: &State) -> Result<Value, Error> {
    let finding_id = state
        .repair
        .active_finding
        .as_deref()
        .ok_or_else(|| invalid("repair inspection has no active finding"))?;
    let finding = state
        .findings
        .iter()
        .find(|finding| finding.id.value == finding_id)
        .ok_or_else(|| invalid("active repair finding is unavailable"))?;
    let hypothesis =
        state.hypotheses.iter().find(|hypothesis| hypothesis.id.value == finding.hypothesis_id);
    let plan = state
        .investigation
        .hypothesis_plans
        .iter()
        .find(|plan| plan.hypothesis_id == finding.hypothesis_id);
    let source_ids = plan
        .map(|plan| {
            plan.source_evidence.iter().map(|id| id.value.as_str()).collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let patch = state.repair.plans.iter().rev().find(|plan| plan.finding_id == finding_id);
    let job_ids = patch
        .into_iter()
        .flat_map(|patch| patch.cases.iter().filter_map(|case| case.host_job_id.as_deref()))
        .collect::<BTreeSet<_>>();
    Ok(json!({
        "finding":finding,
        "hypothesis":hypothesis,
        "execution_plan":plan,
        "source_observations":state.current_observations().filter(|observation|source_ids.contains(observation.record.id.value.as_str())).map(|observation|json!({
            "evidence_id":observation.record.id.value,
            "path":observation.path,
            "source_digest":observation.source_digest,
            "range_start":observation.range_start,
            "range_end":observation.range_end,
            "retained_path":observation.retained_path,
        })).collect::<Vec<_>>(),
        "patch_plan":patch,
        "receipts":state.job_receipts.iter().filter(|receipt|job_ids.contains(receipt.job_id.as_str())).collect::<Vec<_>>(),
    }))
}

fn commit_patch(state: &mut State, arguments: &Value) -> Result<Value, Error> {
    let input: PatchInput = serde_json::from_value(arguments.clone())?;
    if state.repair.active_finding.as_deref() != Some(input.finding_id.as_str()) {
        return Err(invalid("patch does not address the active confirmed finding"));
    }
    if !state.findings.iter().any(|finding| {
        finding.id.value == input.finding_id
            && finding.classification == FindingClassification::Confirmed
    }) {
        return Err(invalid("copy-only patches require a confirmed finding"));
    }
    if input.root_cause.trim().is_empty() || input.replacement.len() > 1024 * 1024 {
        return Err(invalid("patch root cause and bounded replacement are required"));
    }
    let manifest = state
        .investigation
        .manifest_entries
        .iter()
        .find(|entry| entry.path == input.target_path)
        .ok_or_else(|| invalid("patch target is absent from the immutable source manifest"))?;
    if manifest.digest != input.expected_source_digest {
        return Err(invalid("patch expected_source_digest does not match the source manifest"));
    }
    if input.cases.len() < 4 || input.cases.len() > 32 {
        return Err(invalid("patch replay requires four to thirty-two cases"));
    }
    let mut ids = BTreeSet::new();
    let mut categories = BTreeSet::new();
    let cases = input
        .cases
        .into_iter()
        .map(|case| {
            if case.id.is_empty()
                || !case
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
                || !ids.insert(case.id.clone())
                || case.attacker_input.len() > 4096
                || case.expected_stdout_fragment.is_empty()
                || case.expected_stdout_fragment.len() > 4096
            {
                return Err(invalid("patch cases require unique stable IDs and bounded literals"));
            }
            let category = match case.category.as_str() {
                "attack" => PatchCaseCategory::Attack,
                "legitimate" => PatchCaseCategory::Legitimate,
                "malformed" => PatchCaseCategory::Malformed,
                "adjacent" => PatchCaseCategory::Adjacent,
                _ => return Err(invalid("unknown patch case category")),
            };
            categories.insert(case.category);
            Ok(PatchCasePlan {
                id: case.id,
                category,
                attacker_input: case.attacker_input,
                expected_stdout_fragment: case.expected_stdout_fragment,
                state: PatchCaseState::Planned,
                host_job_id: None,
                evidence: None,
                detail: "registered before copy-only execution".into(),
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    if categories
        != BTreeSet::from([
            "attack".to_owned(),
            "legitimate".to_owned(),
            "malformed".to_owned(),
            "adjacent".to_owned(),
        ])
    {
        return Err(invalid(
            "patch replay must include attack, legitimate, malformed and adjacent cases",
        ));
    }
    for dependency in &input.dependencies {
        if !state.patches.iter().any(|patch| {
            patch.state == PatchState::ValidatedForRecordedCases
                && patch.diff_artifact == *dependency
        }) {
            return Err(invalid("patch dependency is not a validated earlier patch identity"));
        }
    }
    let order = u32::try_from(state.repair.plans.len())
        .map_err(|_| invalid("patch plan order overflow"))?
        .checked_add(1)
        .ok_or_else(|| invalid("patch plan order overflow"))?;
    state.repair.plans.push(PatchPlan {
        finding_id: input.finding_id,
        root_cause: input.root_cause,
        target_path: input.target_path,
        expected_source_digest: input.expected_source_digest,
        replacement: input.replacement,
        prerequisites: input.prerequisites,
        dependencies: input.dependencies,
        order,
        cases,
        patch_digest: None,
        diff_artifact: None,
        diff_bytes: None,
        review_id: None,
    });
    state.repair.stage = RepairStage::Replaying;
    state.repair.feedback = "The exact-preimage proposal is durable. The Rust coordinator will now execute every replay case through the host-owned copy-only adapter without another approval prompt.".into();
    Ok(json!({"saved":true,"request_complete":true,"next_stage":"replaying"}))
}

fn schedule_case(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut State,
) -> Result<ModuleAction, Error> {
    if let Some(pending) = &state.pending {
        return crate::resume_pending(pending);
    }
    if !profile.as_ref().is_some_and(|profile| profile.supports(HOST_CAPABILITY_OWNED_JOBS, 1)) {
        return Ok(reply(
            "This host cannot execute the required copy-only replay adapter. The patch remains proposed and blocked; no ambient fallback was attempted.",
            profile,
            crate::investigation::actions(state),
        ));
    }
    let finding = state
        .repair
        .active_finding
        .clone()
        .ok_or_else(|| invalid("repair replay has no active finding"))?;
    let plan_index = state
        .repair
        .plans
        .iter()
        .rposition(|plan| plan.finding_id == finding)
        .ok_or_else(|| invalid("repair replay has no proposed patch"))?;
    let Some(case_index) = state.repair.plans[plan_index]
        .cases
        .iter()
        .position(|case| case.state == PatchCaseState::Planned)
    else {
        state.repair.stage = RepairStage::Reviewing;
        state.repair.round = state.repair.round.saturating_add(1);
        state.repair.feedback = "Every replay case reached a retained terminal or blocked state. Independently review the exact diff and host-authored receipts now.".into();
        crate::state::save(parameters, state)?;
        return next(parameters, profile, state);
    };
    let authority = state
        .active_handle()
        .ok_or_else(|| invalid("source authority is unavailable for copy-only replay"))?;
    let plan = &state.repair.plans[plan_index];
    let case = &plan.cases[case_index];
    let request = ModuleJobRequest {
        schema: 1,
        source_handle: authority.handle,
        scope_revision: authority.scope_revision,
        operation: PATCH_OPERATION.into(),
        specification: json!({
            "target_path":plan.target_path,
            "attacker_input":case.attacker_input,
            "patch":{
                "expected_source_digest":plan.expected_source_digest,
                "replacement":plan.replacement,
                "case_id":case.id,
                "expected_stdout_fragment":case.expected_stdout_fragment,
                "findings":[plan.finding_id],
                "prerequisites":plan.prerequisites,
                "order":plan.order,
                "dependencies":plan.dependencies,
            }
        }),
        limits: ModuleJobLimits {
            memory_bytes: 128 * 1024 * 1024,
            storage_bytes: 16 * 1024 * 1024,
            cpu_millis: 2_000,
            wall_millis: 20_000,
            processes: 8,
        },
    };
    let key = format!("red-team-repair-submit-{}-{}", plan.order, case_index + 1);
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
    if let Some(plan) = state.repair.plans.last_mut()
        && let Some(case) = plan
            .cases
            .iter_mut()
            .find(|case| case.state == PatchCaseState::Planned && case.host_job_id.is_none())
    {
        case.state = PatchCaseState::Running;
        case.host_job_id = Some(job_id.into());
        case.detail = "host accepted the exact copy-only replay request".into();
    }
}

pub(crate) fn job_status(state: &mut State, status: &ModuleJobStatus) -> Result<bool, Error> {
    let Some(plan_index) = state.repair.plans.iter().rposition(|plan| {
        plan.cases.iter().any(|case| case.host_job_id.as_deref() == Some(status.job_id.as_str()))
    }) else {
        return Ok(false);
    };
    let case_index = state.repair.plans[plan_index]
        .cases
        .iter()
        .position(|case| case.host_job_id.as_deref() == Some(status.job_id.as_str()))
        .expect("matched case");
    if matches!(status.phase, ModuleJobPhase::Queued | ModuleJobPhase::Running) {
        state.repair.plans[plan_index].cases[case_index].state = PatchCaseState::Running;
        state.repair.plans[plan_index].cases[case_index].detail = status.detail.clone();
        return Ok(false);
    }
    let receipt = status.receipt.as_ref();
    let patch = receipt.and_then(|receipt| receipt.patch.as_ref());
    if let (Some(receipt), Some(patch)) = (receipt, patch) {
        validate_patch_receipt(
            state,
            &state.repair.plans[plan_index],
            &state.repair.plans[plan_index].cases[case_index],
            status,
            receipt,
            patch,
        )?;
    }
    let passed = matches!(status.phase, ModuleJobPhase::Completed)
        && receipt.is_some_and(|receipt| receipt.verdict == ModuleJobVerdict::PropertyHeldForCase)
        && patch.is_some_and(|patch| digest(&patch.diff_bytes) == patch.diff_artifact);
    let case = &mut state.repair.plans[plan_index].cases[case_index];
    case.state = if passed {
        PatchCaseState::Passed
    } else if matches!(status.phase, ModuleJobPhase::Indeterminate | ModuleJobPhase::Cancelled) {
        PatchCaseState::Blocked
    } else {
        PatchCaseState::Failed
    };
    case.detail = status.detail.clone();
    case.evidence = receipt.and_then(|receipt| {
        let receipt_digest = digest(&serde_json::to_vec(receipt).ok()?);
        RecordId::new(RecordKind::Evidence, format!("execution-{}", &receipt_digest[..24])).ok()
    });
    if let Some(patch) = patch {
        let plan = &mut state.repair.plans[plan_index];
        if let Some(existing) = &plan.patch_digest
            && existing != &patch.patch_digest
        {
            return Err(invalid("replay cases produced inconsistent patch identities"));
        }
        plan.patch_digest = Some(patch.patch_digest.clone());
        plan.diff_artifact = Some(patch.diff_artifact.clone());
        plan.diff_bytes = Some(patch.diff_bytes.clone());
        if !state.patch_receipts.contains(patch) {
            state.patch_receipts.push(patch.clone());
        }
        record_patch_revision(
            state,
            plan_index,
            if passed { PatchState::AppliedToCopy } else { PatchState::Failed },
        )?;
    }
    Ok(true)
}

fn validate_patch_receipt(
    state: &State,
    plan: &PatchPlan,
    case: &PatchCasePlan,
    status: &ModuleJobStatus,
    receipt: &peritus_plugin_sdk::ModuleJobReceipt,
    patch: &peritus_plugin_sdk::ModulePatchReceipt,
) -> Result<(), Error> {
    let snapshot = state
        .active_snapshot()
        .ok_or_else(|| invalid("patch receipt has no active source snapshot"))?;
    let authority = state
        .active_handle()
        .ok_or_else(|| invalid("patch receipt has no active source authority"))?;
    let patched_digest = digest(plan.replacement.as_bytes());
    let patch_identity = serde_json::to_vec(&(
        "peritus-copy-patch-v1",
        &snapshot.snapshot_digest,
        &plan.target_path,
        &plan.expected_source_digest,
        &patched_digest,
        vec![plan.finding_id.clone()],
        &plan.prerequisites,
        plan.order,
        &plan.dependencies,
    ))?;
    let expected_patch_digest = digest(&patch_identity);
    let exact = status.operation == PATCH_OPERATION
        && receipt.operation == PATCH_OPERATION
        && receipt.source_handle == authority.handle
        && receipt.scope_revision == authority.scope_revision
        && receipt.snapshot_digest == snapshot.snapshot_digest
        && receipt.target_digest == patched_digest
        && receipt.cleanup_complete
        && receipt.network_policy == "deny_all"
        && patch.patch_digest == expected_patch_digest
        && patch.source_path == plan.target_path
        && patch.original_digest == plan.expected_source_digest
        && patch.patched_digest == patched_digest
        && patch.diff_artifact == digest(&patch.diff_bytes)
        && patch.case_id == case.id
        && patch.findings == [plan.finding_id.clone()]
        && patch.prerequisites == plan.prerequisites
        && patch.order == plan.order
        && patch.dependencies == plan.dependencies;
    if exact {
        Ok(())
    } else {
        Err(invalid(
            "copy-only replay receipt does not match the retained source, patch, case, cleanup, or host policy",
        ))
    }
}

pub(crate) fn host_failure(state: &mut State, detail: &str) {
    if state.repair.stage == RepairStage::VerifyingOriginal {
        state.repair.stage = RepairStage::Complete;
        state.campaign.state = CampaignState::Paused;
        state.repair.feedback = format!(
            "Final original-workspace byte verification was blocked: {detail}. Patch and replay artifacts remain retained, but the campaign cannot claim unchanged-original proof."
        );
        return;
    }
    if let Some(case) = state.repair.plans.last_mut().and_then(|plan| {
        plan.cases
            .iter_mut()
            .find(|case| matches!(case.state, PatchCaseState::Planned | PatchCaseState::Running))
    }) {
        case.state = PatchCaseState::Blocked;
        case.detail = detail.into();
    }
    state.repair.feedback = format!(
        "A copy-only replay operation was retained as blocked: {detail}. Continue to independent review without weakening the required proof."
    );
}

fn review_patch(state: &mut State, arguments: &Value) -> Result<Value, Error> {
    let input: ReviewInput = serde_json::from_value(arguments.clone())?;
    if state.repair.active_finding.as_deref() != Some(input.finding_id.as_str()) {
        return Err(invalid("patch review does not name the active finding"));
    }
    if input.detail.trim().is_empty() {
        return Err(invalid("patch review requires concrete reasoning"));
    }
    let plan_index = state
        .repair
        .plans
        .iter()
        .rposition(|plan| plan.finding_id == input.finding_id)
        .ok_or_else(|| invalid("patch review has no exact proposal"))?;
    let all_passed = state.repair.plans[plan_index]
        .cases
        .iter()
        .all(|case| case.state == PatchCaseState::Passed);
    let decision = match input.decision.as_str() {
        "accepted" if all_passed => ReviewDecision::Accepted,
        "accepted" => {
            return Err(invalid(
                "a patch cannot be accepted while any attack or legitimate replay case failed or is blocked",
            ));
        }
        "rejected" => ReviewDecision::Rejected,
        "blocked" => ReviewDecision::Blocked,
        _ => return Err(invalid("unknown patch review decision")),
    };
    let subject = latest_patch_record(state, plan_index)?.id.clone();
    let evidence = state.repair.plans[plan_index]
        .cases
        .iter()
        .filter_map(|case| case.evidence.clone())
        .collect::<Vec<_>>();
    let review_id =
        RecordId::new(RecordKind::Review, format!("patch-review-{}", state.reviews.len() + 1))
            .map_err(invalid)?;
    state.reviews.push(ReviewRecord {
        schema: RECORD_SCHEMA_VERSION,
        id: review_id.clone(),
        campaign: state.campaign.id.clone(),
        subject,
        decision,
        evidence,
        detail: input.detail,
        supersedes: None,
    });
    state.repair.plans[plan_index].review_id = Some(review_id);
    if decision == ReviewDecision::Accepted {
        record_patch_revision(state, plan_index, PatchState::ValidatedForRecordedCases)?;
        state.repair.active_finding = None;
        state.repair.stage = RepairStage::Planning;
        state.repair.feedback = "The exact diff passed every recorded case and independent review. Continue automatically to the next confirmed finding or final original-byte verification.".into();
    } else {
        record_patch_revision(
            state,
            plan_index,
            if decision == ReviewDecision::Blocked {
                PatchState::Blocked
            } else {
                PatchState::Failed
            },
        )?;
        state.repair.stage = RepairStage::Planning;
        state.repair.feedback = "The independent reviewer did not accept this patch. Develop a new root-cause revision for the same finding; do not loosen the replay matrix or oracle.".into();
    }
    Ok(
        json!({"saved":true,"request_complete":true,"decision":input.decision,"next_stage":"planning"}),
    )
}

fn record_patch_revision(
    state: &mut State,
    plan_index: usize,
    patch_state: PatchState,
) -> Result<(), Error> {
    let plan = &state.repair.plans[plan_index];
    let diff_artifact = plan
        .diff_artifact
        .clone()
        .ok_or_else(|| invalid("patch revision has no host-authored diff"))?;
    let finding = state
        .findings
        .iter()
        .find(|finding| finding.id.value == plan.finding_id)
        .ok_or_else(|| invalid("patch revision finding is unavailable"))?
        .id
        .clone();
    let prior = state
        .patches
        .iter()
        .rev()
        .find(|patch| patch.diff_artifact == diff_artifact && patch.findings.contains(&finding))
        .map(|patch| patch.id.clone());
    let revision =
        state.patches.iter().filter(|patch| patch.diff_artifact == diff_artifact).count() + 1;
    let id = RecordId::new(
        RecordKind::Patch,
        format!("patch-{}-r{revision}", &diff_artifact[..diff_artifact.len().min(16)]),
    )
    .map_err(invalid)?;
    state.patches.push(PatchRecord {
        schema: RECORD_SCHEMA_VERSION,
        id,
        campaign: state.campaign.id.clone(),
        source_snapshot: state
            .active_snapshot()
            .ok_or_else(|| invalid("patch revision has no active source snapshot"))?
            .id
            .clone(),
        findings: vec![finding],
        diff_artifact,
        state: patch_state,
        validations: plan.cases.iter().filter_map(|case| case.evidence.clone()).collect(),
        supersedes: prior,
    });
    Ok(())
}

fn latest_patch_record(state: &State, plan_index: usize) -> Result<&PatchRecord, Error> {
    let diff = state.repair.plans[plan_index]
        .diff_artifact
        .as_deref()
        .ok_or_else(|| invalid("patch review has no host-authored diff"))?;
    state
        .patches
        .iter()
        .rev()
        .find(|patch| patch.diff_artifact == diff)
        .ok_or_else(|| invalid("patch review has no retained patch revision"))
}

fn request_original_verification(
    parameters: &Value,
    state: &mut State,
) -> Result<ModuleAction, Error> {
    if let Some(pending) = &state.pending {
        return crate::resume_pending(pending);
    }
    let authority = state
        .active_handle()
        .ok_or_else(|| invalid("source authority is unavailable for final byte verification"))?;
    let request = ScopedSourceVerifyRequest { schema: 1, authority };
    let key = "red-team-repair-verify-original".to_owned();
    state.pending =
        Some(PendingRequest::SourceVerify { key: key.clone(), request: request.clone() });
    crate::state::save(parameters, state)?;
    Ok(ModuleAction::HostService {
        request: ModuleHostRequest {
            key,
            capability: HOST_CAPABILITY_SCOPED_SOURCE.into(),
            version: 1,
            operation: "verify".into(),
            input: serde_json::to_value(request)?,
        },
    })
}

pub(crate) fn original_verified(state: &mut State, result: ScopedSourceVerification) {
    state.original_verification = Some(result.clone());
    state.repair.stage = RepairStage::Complete;
    state.campaign.state =
        if result.unchanged { CampaignState::Completed } else { CampaignState::Paused };
    state.repair.feedback = if result.unchanged {
        "The host re-read every included original-project file and observed the starting bytes and executable bits unchanged.".into()
    } else {
        "The original workspace differs from the starting snapshot. Copy-only repair results remain retained, but the campaign cannot claim unchanged-original proof.".into()
    };
}

pub(crate) fn poll_action(state: &mut State, job_id: String) -> Result<ModuleAction, Error> {
    let key = format!("red-team-repair-poll-{}", &job_id[..job_id.len().min(16)]);
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

fn role_for_key<'a>(state: &State, key: &'a str) -> Result<&'a str, Error> {
    let role = if key.starts_with("red-team-fixer-") {
        "fixer"
    } else if key.starts_with("red-team-patch-reviewer-") {
        "reviewer"
    } else {
        return Err(invalid("model result does not belong to a repair role"));
    };
    if request_key(state, role) == key {
        Ok(role)
    } else {
        Err(invalid("model result belongs to another repair revision or source snapshot"))
    }
}

fn request_key(state: &State, role: &str) -> String {
    let snapshot = state.active_snapshot().map_or("none", |snapshot| {
        &snapshot.snapshot_digest[..snapshot.snapshot_digest.len().min(16)]
    });
    format!(
        "red-team-{}-{snapshot}-r{}",
        if role == "fixer" { "fixer" } else { "patch-reviewer" },
        state.repair.round
    )
}

fn function(name: &str, description: &str, schema: Value) -> ModuleFunction {
    ModuleFunction { name: name.into(), description: description.into(), schema }
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
