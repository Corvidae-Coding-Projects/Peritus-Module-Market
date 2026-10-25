//! Module-owned stateful workflow and deterministic concurrency campaign.
//!
//! The module chooses only this registered campaign. It fixes documented and proposed
//! invariants, action sequences, schedules, copied-state reads, finding admission, and replay data.

use super::{
    runtime_http_api::{Exchange, WireRequest},
    runtime_laboratory::WorkflowLaboratorySession,
};
use peritus_plugin_sdk::{
    ModuleSourceSeverity, ModuleWorkflowActionObservation, ModuleWorkflowCampaignRequest,
    ModuleWorkflowFindingObservation, ModuleWorkflowInvariantDisposition,
    ModuleWorkflowInvariantObservation, ModuleWorkflowInvariantOrigin,
    ModuleWorkflowNondeterminismObservation, ModuleWorkflowObservation,
    ModuleWorkflowScheduleObservation, ModuleWorkflowSequenceDisposition,
    ModuleWorkflowSequenceObservation,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, fs, path::Path, time::Instant};

pub(super) const PROFILE: &str = "peritus.workflow-state.standard@1";
pub(super) const ADAPTER_VERSION: &str = "peritus-workflow-state-2026-10-24.1";
pub(super) const SUITE_VERSION: &str = "peritus-workflow-state-suite-2026-10-24.1";

const MINIMUM_SEQUENCES: u32 = 9;
const MINIMUM_ACTIONS: u32 = 43;
const RACE_SCHEDULE: [&str; 4] = ["read-a", "read-b", "write-a", "write-b"];

#[derive(Clone, Debug, Deserialize)]
struct BusinessRequest {
    amount: i64,
    status: String,
    processed: bool,
}

#[derive(Clone, Debug)]
struct StateSnapshot {
    digest: String,
    balance: i64,
    spent: i64,
    quota_used: u64,
    recoveries: u64,
    requests: BTreeMap<String, BusinessRequest>,
}

#[derive(Clone, Copy)]
struct ActionSpec<'a> {
    operation: &'a str,
    request_id: &'a str,
    actor: &'a str,
    amount: i64,
    schedule_slot: Option<&'a str>,
}

#[derive(Clone, Copy)]
enum SequenceOracle {
    Legitimate,
    Approval,
    Duplicate,
    Retry,
    Cancellation,
    Quota,
    CrashRecovery,
    Race,
    ProposedCancellation,
}

struct SequenceSpec<'a> {
    id: &'a str,
    category: &'a str,
    invariant_ids: &'a [&'a str],
    actions: Vec<ActionSpec<'a>>,
    oracle: SequenceOracle,
    schedule_id: Option<&'a str>,
}

struct SequenceRun {
    observation: ModuleWorkflowSequenceObservation,
    violation: Option<(&'static str, &'static str, ModuleSourceSeverity, &'static [&'static str])>,
}

type InvariantViolation =
    (&'static str, &'static str, ModuleSourceSeverity, &'static [&'static str]);
type Evaluation = (bool, String, Option<InvariantViolation>);

/// Executes the pinned suite through a module-owned exchange and copied-state reader.
pub(super) fn execute(
    request: ModuleWorkflowCampaignRequest,
    session: &WorkflowLaboratorySession,
    mut exchange: impl FnMut(&WireRequest) -> Result<Exchange, String>,
) -> Result<ModuleWorkflowObservation, String> {
    validate(&request)?;
    let mut campaign = Sha256::new();
    campaign.update(b"peritus-workflow-state-campaign-v1\0");
    campaign.update(request.seed.to_be_bytes());
    let mut sequences = Vec::new();
    let mut findings = Vec::new();
    let mut actions_executed = 0_u64;
    let mut excluded_harness_failures = 0_u64;

    for specification in suite() {
        let run = run_sequence(
            &request,
            &session.state_path,
            &specification,
            &mut exchange,
            &mut actions_executed,
        )?;
        campaign.update(run.observation.replay_digest.as_bytes());
        if run.observation.disposition == ModuleWorkflowSequenceDisposition::HarnessFailure {
            excluded_harness_failures = excluded_harness_failures.saturating_add(1);
        }
        if let Some((invariant, message, severity, standards)) = run.violation {
            let replay_digest = run.observation.replay_digest.clone();
            findings.push(ModuleWorkflowFindingObservation {
                id: digest(
                    format!(
                        "workflow-finding\0{}\0{invariant}\0{replay_digest}",
                        run.observation.id
                    )
                    .as_bytes(),
                ),
                sequence_id: run.observation.id.clone(),
                invariant_id: invariant.into(),
                severity,
                message: message.into(),
                evidence_state: "runtime_confirmed".into(),
                standards: standards.iter().map(|value| (*value).into()).collect(),
                replay_digest,
            });
        }
        sequences.push(run.observation);
    }

    let primary_race = sequences
        .iter()
        .find(|sequence| sequence.id == "wf-08-concurrent-double-commit")
        .ok_or_else(|| "pinned race sequence is absent".to_string())?;
    let primary_digest = primary_race.final_state_digest.clone();
    let primary_status = primary_race.actions.last().and_then(|action| action.response_status);
    let mut matching_replays = 1_u32;
    for replay in 1..3 {
        let specification = race_spec();
        let run = run_sequence(
            &request,
            &session.state_path,
            &specification,
            &mut exchange,
            &mut actions_executed,
        )?;
        if run.observation.final_state_digest == primary_digest
            && run.observation.actions.last().and_then(|action| action.response_status)
                == primary_status
        {
            matching_replays = matching_replays.saturating_add(1);
        }
        campaign.update(
            format!("race-replay-{replay}\0{}\u{0}", run.observation.replay_digest).as_bytes(),
        );
    }

    let schedules = vec![ModuleWorkflowScheduleObservation {
        id: "schedule-read-read-write-write".into(),
        steps: RACE_SCHEDULE.iter().map(|step| (*step).into()).collect(),
        replay_count: 3,
        matching_replays,
        schedule_digest: digest(RACE_SCHEDULE.join("\0").as_bytes()),
    }];
    let divergent_replays = u64::from(3_u32.saturating_sub(matching_replays));
    let invariants = invariant_observations(&sequences);
    let final_state_digest = read_snapshot(&session.state_path)?.digest;
    campaign.update(final_state_digest.as_bytes());
    campaign.update(serde_json::to_vec(&sequences).map_err(|error| error.to_string())?);
    campaign.update(serde_json::to_vec(&schedules).map_err(|error| error.to_string())?);

    Ok(ModuleWorkflowObservation {
        schema: 1,
        laboratory_id: request.laboratory_id,
        source_snapshot: session.source_snapshot.clone(),
        adapter_version: ADAPTER_VERSION.into(),
        suite_version: SUITE_VERSION.into(),
        seed: request.seed,
        invariants,
        sequences,
        findings,
        nondeterminism: ModuleWorkflowNondeterminismObservation {
            schedules,
            replays: 3,
            divergent_replays,
            excluded_harness_failures,
            notes: vec![
                "The fixed two-worker schedule is replayed three times; arbitrary scheduler interleavings are outside this profile.".into(),
                "Transport or controller failures are classified separately and cannot establish a domain invariant violation.".into(),
            ],
        },
        actions_executed,
        campaign_digest: hex(campaign.finalize()),
        final_state_digest,
        gaps: vec![
            "The pinned suite covers one approval/accounting domain; application-specific invariants require an explicit contract before they may support findings.".into(),
            "The concurrency controller retains one deterministic two-worker schedule rather than claiming exhaustive schedule exploration.".into(),
            "Distributed consensus, external queues, databases not represented in copied state, and non-Linux runtimes require separate adapters.".into(),
        ],
    })
}

fn validate(request: &ModuleWorkflowCampaignRequest) -> Result<(), String> {
    if request.schema != 1 {
        return Err("workflow campaign request schema is unsupported".into());
    }
    if request.profile != PROFILE {
        return Err("workflow campaign profile is not registered".into());
    }
    if request.maximum_sequences < MINIMUM_SEQUENCES || request.maximum_sequences > 32 {
        return Err(format!(
            "workflow campaign requires at least {MINIMUM_SEQUENCES} sequences and admits at most 32"
        ));
    }
    if request.maximum_actions < MINIMUM_ACTIONS || request.maximum_actions > 256 {
        return Err(format!(
            "workflow campaign requires at least {MINIMUM_ACTIONS} actions and admits at most 256"
        ));
    }
    if !(1024..=512 * 1024).contains(&request.maximum_response_bytes) {
        return Err("workflow campaign response bound must be from 1 KiB through 512 KiB".into());
    }
    Ok(())
}

fn run_sequence(
    request: &ModuleWorkflowCampaignRequest,
    state_path: &Path,
    specification: &SequenceSpec<'_>,
    exchange: &mut impl FnMut(&WireRequest) -> Result<Exchange, String>,
    actions_executed: &mut u64,
) -> Result<SequenceRun, String> {
    let reset = ActionSpec {
        operation: "reset",
        request_id: "sequence-setup",
        actor: "host-controller",
        amount: 1,
        schedule_slot: None,
    };
    let reset_result = issue(request, reset, exchange);
    *actions_executed = actions_executed.saturating_add(1);
    if let Err(detail) = reset_result {
        let snapshot = read_snapshot(state_path)?;
        return Ok(harness_failure(
            specification,
            snapshot.digest,
            format!("sequence reset failed: {detail}"),
        ));
    }
    let starting = read_snapshot(state_path)?;
    let mut actions = Vec::with_capacity(specification.actions.len());
    let mut harness_failure = None;
    for (position, action) in specification.actions.iter().copied().enumerate() {
        let before = read_snapshot(state_path)?;
        let started = Instant::now();
        let result = issue(request, action, exchange);
        *actions_executed = actions_executed.saturating_add(1);
        let after = read_snapshot(state_path)?;
        let (status, request_digest, outcome) = match result {
            Ok(observation) => (
                Some(observation.response_status),
                observation.request_digest,
                format!(
                    "HTTP {}; copied state keys changed: {}",
                    observation.response_status,
                    observation.changed_state_keys.join(",")
                ),
            ),
            Err(detail) => {
                harness_failure = Some(detail.clone());
                (
                    None,
                    digest(
                        format!(
                            "{}\0{}\0{}\0{}",
                            action.operation, action.request_id, action.actor, action.amount
                        )
                        .as_bytes(),
                    ),
                    format!("transport failure: {detail}"),
                )
            }
        };
        actions.push(ModuleWorkflowActionObservation {
            id: format!("{}-{:02}", specification.id, position + 1),
            position: u32::try_from(position).map_err(|_| "workflow action position overflow")?,
            actor: action.actor.into(),
            operation: action.operation.into(),
            request_id: action.request_id.into(),
            schedule_slot: action.schedule_slot.map(Into::into),
            request_digest,
            response_status: status,
            state_before_digest: before.digest,
            state_after_digest: after.digest,
            elapsed_millis: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            outcome,
        });
        if harness_failure.is_some() {
            break;
        }
    }
    let final_state = read_snapshot(state_path)?;
    if let Some(detail) = harness_failure {
        let replay_digest =
            replay_digest(specification, &starting.digest, &final_state.digest, &actions);
        return Ok(SequenceRun {
            observation: ModuleWorkflowSequenceObservation {
                id: specification.id.into(),
                category: specification.category.into(),
                identities: identities(&actions),
                starting_snapshot_digest: starting.digest,
                actions,
                final_state_digest: final_state.digest,
                invariant_ids: specification
                    .invariant_ids
                    .iter()
                    .map(|value| (*value).into())
                    .collect(),
                disposition: ModuleWorkflowSequenceDisposition::HarnessFailure,
                oracle: format!("excluded controller or transport failure: {detail}"),
                schedule_id: specification.schedule_id.map(Into::into),
                replay_digest,
            },
            violation: None,
        });
    }
    let (held, detail, violation) = evaluate(specification.oracle, &final_state, &actions);
    let disposition = if held {
        ModuleWorkflowSequenceDisposition::Passed
    } else {
        ModuleWorkflowSequenceDisposition::Violation
    };
    let replay_digest =
        replay_digest(specification, &starting.digest, &final_state.digest, &actions);
    Ok(SequenceRun {
        observation: ModuleWorkflowSequenceObservation {
            id: specification.id.into(),
            category: specification.category.into(),
            identities: identities(&actions),
            starting_snapshot_digest: starting.digest,
            actions,
            final_state_digest: final_state.digest,
            invariant_ids: specification
                .invariant_ids
                .iter()
                .map(|value| (*value).into())
                .collect(),
            disposition,
            oracle: detail,
            schedule_id: specification.schedule_id.map(Into::into),
            replay_digest,
        },
        violation,
    })
}

fn issue(
    request: &ModuleWorkflowCampaignRequest,
    action: ActionSpec<'_>,
    exchange: &mut impl FnMut(&WireRequest) -> Result<Exchange, String>,
) -> Result<Exchange, String> {
    let body = serde_json::to_string(&json!({
        "op": action.operation,
        "request_id": action.request_id,
        "actor": action.actor,
        "amount": action.amount,
        "schedule": action.schedule_slot,
    }))
    .map_err(|error| error.to_string())?;
    exchange(&WireRequest {
        method: "POST".into(),
        target: "/phase17/action".into(),
        headers: vec![
            ("host".into(), "laboratory.invalid".into()),
            ("content-type".into(), "application/json".into()),
            ("content-length".into(), body.len().to_string()),
        ],
        body,
        websocket_message: None,
        maximum_request_bytes: 64 * 1024,
        maximum_response_bytes: request.maximum_response_bytes,
    })
}

fn read_snapshot(path: &Path) -> Result<StateSnapshot, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("could not read copied workflow state: {error}"))?;
    let values: BTreeMap<String, String> = serde_json::from_slice(&bytes)
        .map_err(|error| format!("copied workflow state is not a string map: {error}"))?;
    let number = |key: &str, default: &str| {
        values
            .get(key)
            .map_or(default, String::as_str)
            .parse::<i64>()
            .map_err(|error| format!("copied workflow state has invalid {key}: {error}"))
    };
    let balance = number("balance", "100")?;
    let spent = number("spent", "0")?;
    let quota_used = u64::try_from(number("quota_used", "0")?)
        .map_err(|_| "copied workflow quota is negative".to_string())?;
    let recoveries = u64::try_from(number("recoveries", "0")?)
        .map_err(|_| "copied workflow recovery count is negative".to_string())?;
    let requests = serde_json::from_str(values.get("requests").map_or("{}", String::as_str))
        .map_err(|error| format!("copied workflow request ledger is invalid: {error}"))?;
    Ok(StateSnapshot { digest: digest(&bytes), balance, spent, quota_used, recoveries, requests })
}

fn evaluate(
    oracle: SequenceOracle,
    state: &StateSnapshot,
    actions: &[ModuleWorkflowActionObservation],
) -> Evaluation {
    let accounting = state.balance.saturating_add(state.spent) == 100;
    match oracle {
        SequenceOracle::Legitimate => {
            let held = accounting
                && state.balance == 70
                && state.spent == 30
                && state.quota_used == 1
                && request_status(state, "legit-1") == Some("charged");
            (
                held,
                format!(
                    "legitimate create/approve/charge ended balance={} spent={} quota={}",
                    state.balance, state.spent, state.quota_used
                ),
                None,
            )
        }
        SequenceOracle::Approval => result(
            accounting && state.balance == 100 && state.spent == 0 && state.quota_used == 0,
            "inv-approval-required",
            "A charge without approval changed copied accounting state.",
            ModuleSourceSeverity::High,
            &["CWE-841"],
            state,
        ),
        SequenceOracle::Duplicate => result(
            accounting && state.balance == 70 && state.spent == 30 && state.quota_used == 1,
            "inv-idempotent-request",
            "Duplicate or replayed request identity produced a second business effect.",
            ModuleSourceSeverity::High,
            &["CWE-841", "CWE-362"],
            state,
        ),
        SequenceOracle::Retry => result(
            accounting && state.balance == 70 && state.spent == 30 && state.quota_used == 1,
            "inv-retry-idempotent",
            "Retry after an ambiguous committed response produced a duplicate effect.",
            ModuleSourceSeverity::High,
            &["CWE-841"],
            state,
        ),
        SequenceOracle::Cancellation => result(
            accounting
                && state.balance == 100
                && state.spent == 0
                && state.quota_used == 0
                && request_status(state, "cancel-1") == Some("cancelled"),
            "inv-cancellation-terminal",
            "A cancelled request was approved or charged after its terminal transition.",
            ModuleSourceSeverity::High,
            &["CWE-841"],
            state,
        ),
        SequenceOracle::Quota => result(
            accounting && state.balance == 40 && state.spent == 60 && state.quota_used == 2,
            "inv-quota-two",
            "Three effects committed despite the documented two-charge quota.",
            ModuleSourceSeverity::Medium,
            &["CWE-770", "CWE-841"],
            state,
        ),
        SequenceOracle::CrashRecovery => result(
            accounting
                && state.balance == 100
                && state.spent == 0
                && state.quota_used == 0
                && state.recoveries == 1,
            "inv-crash-atomicity",
            "A crashed worker left a partial accounting effect after recovery.",
            ModuleSourceSeverity::High,
            &["CWE-703", "CWE-682"],
            state,
        ),
        SequenceOracle::Race => result(
            accounting && state.balance == 40 && state.spent == 60 && state.quota_used == 1,
            "inv-concurrent-single-commit",
            "The retained two-worker schedule committed one request more than once.",
            ModuleSourceSeverity::High,
            &["CWE-362", "CWE-367"],
            state,
        ),
        SequenceOracle::ProposedCancellation => {
            let refuted = request_status(state, "proposal-1") == Some("cancelled")
                && actions.last().and_then(|action| action.response_status) == Some(200);
            (
                true,
                if refuted {
                    "model-proposed approval irreversibility was refuted by a legal cancel action; it does not support a finding".into()
                } else {
                    "model-proposed approval irreversibility was not decided; it does not support a finding".into()
                },
                None,
            )
        }
    }
}

fn result(
    held: bool,
    invariant: &'static str,
    message: &'static str,
    severity: ModuleSourceSeverity,
    standards: &'static [&'static str],
    state: &StateSnapshot,
) -> Evaluation {
    let detail = format!(
        "host snapshot balance={} spent={} quota={} recoveries={} accounting_conserved={}",
        state.balance,
        state.spent,
        state.quota_used,
        state.recoveries,
        state.balance.saturating_add(state.spent) == 100,
    );
    (held, detail, (!held).then_some((invariant, message, severity, standards)))
}

fn request_status<'a>(state: &'a StateSnapshot, id: &str) -> Option<&'a str> {
    state.requests.get(id).map(|request| {
        let _ = (request.amount, request.processed);
        request.status.as_str()
    })
}

fn invariant_observations(
    sequences: &[ModuleWorkflowSequenceObservation],
) -> Vec<ModuleWorkflowInvariantObservation> {
    let specifications = [
        (
            "inv-accounting-conservation",
            ModuleWorkflowInvariantOrigin::Documented,
            "Balance plus spent remains 100 after every completed action sequence.",
            "host-state/accounting-conservation@1",
        ),
        (
            "inv-approval-required",
            ModuleWorkflowInvariantOrigin::Documented,
            "A request cannot charge before approval.",
            "host-state/approval-transition@1",
        ),
        (
            "inv-idempotent-request",
            ModuleWorkflowInvariantOrigin::Documented,
            "One request identity produces at most one charge effect across duplicate and replay.",
            "host-state/idempotency-ledger@1",
        ),
        (
            "inv-retry-idempotent",
            ModuleWorkflowInvariantOrigin::Documented,
            "Retry after an ambiguous response does not repeat a committed effect.",
            "host-state/retry-ledger@1",
        ),
        (
            "inv-cancellation-terminal",
            ModuleWorkflowInvariantOrigin::Documented,
            "Cancellation is terminal and forbids later approval or charge.",
            "host-state/terminal-transition@1",
        ),
        (
            "inv-quota-two",
            ModuleWorkflowInvariantOrigin::Documented,
            "At most two charges may commit in one quota window.",
            "host-state/quota@1",
        ),
        (
            "inv-crash-atomicity",
            ModuleWorkflowInvariantOrigin::Documented,
            "Worker crash and recovery leave either the complete effect or no effect.",
            "host-state/crash-atomicity@1",
        ),
        (
            "inv-concurrent-single-commit",
            ModuleWorkflowInvariantOrigin::Documented,
            "Concurrent workers commit a request identity at most once.",
            "host-state/deterministic-schedule@1",
        ),
        (
            "candidate-approval-irreversible",
            ModuleWorkflowInvariantOrigin::ModelProposed,
            "An approved request cannot later be cancelled.",
            "host-state/candidate-transition@1",
        ),
    ];
    specifications
        .into_iter()
        .map(|(id, origin, statement, oracle)| {
            let related = sequences
                .iter()
                .filter(|sequence| sequence.invariant_ids.iter().any(|candidate| candidate == id))
                .collect::<Vec<_>>();
            let disposition = if origin == ModuleWorkflowInvariantOrigin::ModelProposed {
                if related.iter().any(|sequence| sequence.oracle.contains("refuted")) {
                    ModuleWorkflowInvariantDisposition::Refuted
                } else {
                    ModuleWorkflowInvariantDisposition::Inconclusive
                }
            } else if related.iter().any(|sequence| {
                sequence.disposition == ModuleWorkflowSequenceDisposition::Violation
            }) {
                ModuleWorkflowInvariantDisposition::Violated
            } else if related.iter().any(|sequence| {
                sequence.disposition == ModuleWorkflowSequenceDisposition::HarnessFailure
            }) {
                ModuleWorkflowInvariantDisposition::Inconclusive
            } else {
                ModuleWorkflowInvariantDisposition::Held
            };
            ModuleWorkflowInvariantObservation {
                id: id.into(),
                origin,
                statement: statement.into(),
                oracle: oracle.into(),
                disposition,
                sequence_ids: related.iter().map(|sequence| sequence.id.clone()).collect(),
            }
        })
        .collect()
}

fn replay_digest(
    specification: &SequenceSpec<'_>,
    starting: &str,
    final_state: &str,
    actions: &[ModuleWorkflowActionObservation],
) -> String {
    let mut value = Sha256::new();
    value.update(b"peritus-workflow-sequence-v1\0");
    value.update(specification.id.as_bytes());
    value.update(starting.as_bytes());
    value.update(final_state.as_bytes());
    value.update(serde_json::to_vec(actions).unwrap_or_default());
    if let Some(schedule) = specification.schedule_id {
        value.update(schedule.as_bytes());
    }
    hex(value.finalize())
}

fn identities(actions: &[ModuleWorkflowActionObservation]) -> Vec<String> {
    actions
        .iter()
        .map(|action| action.actor.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn harness_failure(specification: &SequenceSpec<'_>, state: String, detail: String) -> SequenceRun {
    SequenceRun {
        observation: ModuleWorkflowSequenceObservation {
            id: specification.id.into(),
            category: specification.category.into(),
            identities: Vec::new(),
            starting_snapshot_digest: state.clone(),
            actions: Vec::new(),
            final_state_digest: state,
            invariant_ids: specification
                .invariant_ids
                .iter()
                .map(|value| (*value).into())
                .collect(),
            disposition: ModuleWorkflowSequenceDisposition::HarnessFailure,
            oracle: detail,
            schedule_id: specification.schedule_id.map(Into::into),
            replay_digest: digest(format!("harness\0{}", specification.id).as_bytes()),
        },
        violation: None,
    }
}

fn suite() -> Vec<SequenceSpec<'static>> {
    let mut sequences = vec![
        SequenceSpec {
            id: "wf-01-legitimate-charge",
            category: "legitimate",
            invariant_ids: &["inv-accounting-conservation", "inv-approval-required"],
            actions: vec![
                action("create", "legit-1", 30),
                action("approve", "legit-1", 30),
                action("charge", "legit-1", 30),
            ],
            oracle: SequenceOracle::Legitimate,
            schedule_id: None,
        },
        SequenceSpec {
            id: "wf-02-approval-bypass",
            category: "approval",
            invariant_ids: &["inv-accounting-conservation", "inv-approval-required"],
            actions: vec![action("create", "approval-1", 30), action("charge", "approval-1", 30)],
            oracle: SequenceOracle::Approval,
            schedule_id: None,
        },
        SequenceSpec {
            id: "wf-03-duplicate-replay",
            category: "duplication_replay",
            invariant_ids: &["inv-accounting-conservation", "inv-idempotent-request"],
            actions: vec![
                action("create", "duplicate-1", 30),
                action("approve", "duplicate-1", 30),
                action("charge", "duplicate-1", 30),
                action("charge", "duplicate-1", 30),
            ],
            oracle: SequenceOracle::Duplicate,
            schedule_id: None,
        },
        SequenceSpec {
            id: "wf-04-ambiguous-retry",
            category: "retry",
            invariant_ids: &["inv-accounting-conservation", "inv-retry-idempotent"],
            actions: vec![
                action("create", "retry-1", 30),
                action("approve", "retry-1", 30),
                action("retry_commit", "retry-1", 30),
                action("retry_commit", "retry-1", 30),
            ],
            oracle: SequenceOracle::Retry,
            schedule_id: None,
        },
        SequenceSpec {
            id: "wf-05-cancel-terminal",
            category: "cancellation",
            invariant_ids: &["inv-accounting-conservation", "inv-cancellation-terminal"],
            actions: vec![
                action("create", "cancel-1", 30),
                action("cancel", "cancel-1", 30),
                action("approve", "cancel-1", 30),
                action("charge", "cancel-1", 30),
            ],
            oracle: SequenceOracle::Cancellation,
            schedule_id: None,
        },
        SequenceSpec {
            id: "wf-06-quota-overflow",
            category: "quota",
            invariant_ids: &["inv-accounting-conservation", "inv-quota-two"],
            actions: quota_actions(),
            oracle: SequenceOracle::Quota,
            schedule_id: None,
        },
        SequenceSpec {
            id: "wf-07-crash-recovery",
            category: "crash_restart",
            invariant_ids: &["inv-accounting-conservation", "inv-crash-atomicity"],
            actions: vec![action("crash_recover", "crash-1", 30)],
            oracle: SequenceOracle::CrashRecovery,
            schedule_id: None,
        },
        race_spec(),
        SequenceSpec {
            id: "wf-09-proposed-invariant",
            category: "candidate_invariant",
            invariant_ids: &["candidate-approval-irreversible"],
            actions: vec![
                action("create", "proposal-1", 30),
                action("approve", "proposal-1", 30),
                action("cancel", "proposal-1", 30),
            ],
            oracle: SequenceOracle::ProposedCancellation,
            schedule_id: None,
        },
    ];
    sequences.shrink_to_fit();
    sequences
}

fn race_spec() -> SequenceSpec<'static> {
    SequenceSpec {
        id: "wf-08-concurrent-double-commit",
        category: "deterministic_concurrency",
        invariant_ids: &["inv-accounting-conservation", "inv-concurrent-single-commit"],
        actions: vec![
            action("create", "race-1", 60),
            action("approve", "race-1", 60),
            ActionSpec {
                operation: "race",
                request_id: "race-1",
                actor: "worker-a+worker-b",
                amount: 60,
                schedule_slot: Some("read-a,read-b,write-a,write-b"),
            },
        ],
        oracle: SequenceOracle::Race,
        schedule_id: Some("schedule-read-read-write-write"),
    }
}

fn quota_actions() -> Vec<ActionSpec<'static>> {
    let mut actions = Vec::new();
    for id in ["quota-1", "quota-2", "quota-3"] {
        actions.extend([
            action("create", id, 30),
            action("approve", id, 30),
            action("charge", id, 30),
        ]);
    }
    actions
}

const fn action(
    operation: &'static str,
    request_id: &'static str,
    amount: i64,
) -> ActionSpec<'static> {
    ActionSpec { operation, request_id, actor: "user-a", amount, schedule_slot: None }
}

fn digest(bytes: &[u8]) -> String {
    hex(Sha256::digest(bytes))
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    let mut output = String::with_capacity(bytes.as_ref().len() * 2);
    for byte in bytes.as_ref() {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}
