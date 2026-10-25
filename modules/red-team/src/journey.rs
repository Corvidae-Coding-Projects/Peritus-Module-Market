//! Phase-twenty durable operator journey over every supported adapter profile.

use crate::{Error, invalid, reply, state, state::JourneyStepState};
use peritus_plugin_sdk::{
    HOST_CAPABILITY_APPLICATION_LABORATORY, HOST_CAPABILITY_SCOPED_SOURCE, HOST_CAPABILITY_WORKER,
    ModuleAction, ModuleHostProfile, ModuleLaboratoryPhase, ModuleMenuAction,
};
use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) fn handles(command: &str) -> bool {
    matches!(
        command,
        "campaign"
            | "campaign-plan"
            | "campaign-start"
            | "campaign-next"
            | "campaign-pause"
            | "campaign-resume"
            | "campaign-retry"
            | "campaign-skip"
            | "campaign-abort"
    ) || command.starts_with("campaign-steer ")
}

pub(crate) fn command(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
    command: &str,
) -> Result<ModuleAction, Error> {
    match command {
        "campaign" => Ok(reply(view(state), profile, super::actions(state), None)),
        "campaign-plan" => Ok(reply(plan_text(), profile, plan_actions(), None)),
        "campaign-start" => start(parameters, profile, state),
        "campaign-next" => next(parameters, profile, state),
        "campaign-pause" => pause(parameters, profile, state),
        "campaign-resume" => resume(parameters, profile, state),
        "campaign-retry" => retry(parameters, profile, state),
        "campaign-skip" => skip(parameters, profile, state),
        "campaign-abort" => abort(parameters, profile, state),
        _ => steer(parameters, profile, state, command),
    }
}

pub(crate) fn actions(state: &state::State) -> Vec<ModuleMenuAction> {
    use state::JourneyStage;
    match state.journey.stage {
        JourneyStage::Inactive => plan_actions(),
        JourneyStage::Running | JourneyStage::CleaningUp => vec![
            action("Continue bounded campaign", "campaign-next", true),
            action("Pause campaign", "campaign-pause", true),
            action("Steer campaign", "campaign-steer ", false),
            action("Export partial report", "report", true),
            action("Abort and clean up", "campaign-abort", true),
        ],
        JourneyStage::Paused => vec![
            action("Resume campaign", "campaign-resume", true),
            action("Steer campaign", "campaign-steer ", false),
            action("Export partial report", "report", true),
            action("Abort and clean up", "campaign-abort", true),
        ],
        JourneyStage::Blocked => vec![
            action("Retry blocked step", "campaign-retry", true),
            action("Skip with recorded gap", "campaign-skip", true),
            action("Steer campaign", "campaign-steer ", false),
            action("Export partial report", "report", true),
            action("Abort and clean up", "campaign-abort", true),
        ],
        JourneyStage::Complete => vec![
            action("Campaign results", "campaign", true),
            action("Export Markdown", "report", true),
            action("Export JSON", "report-json", true),
            action("Export SARIF", "sarif", true),
            action("Export replay bundle", "bundle", true),
        ],
    }
}

fn plan_actions() -> Vec<ModuleMenuAction> {
    vec![
        action("View complete campaign plan", "campaign-plan", true),
        action("Start complete campaign", "campaign-start", true),
    ]
}

fn action(label: &str, arguments: &str, submit: bool) -> ModuleMenuAction {
    ModuleMenuAction { label: label.into(), arguments: arguments.into(), submit }
}

fn start(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
) -> Result<ModuleAction, Error> {
    let snapshot = state
        .active_snapshot()
        .ok_or_else(|| invalid("scope the explicit application source before starting a campaign"))?
        .snapshot_digest
        .clone();
    let missing = [
        HOST_CAPABILITY_SCOPED_SOURCE,
        HOST_CAPABILITY_WORKER,
        HOST_CAPABILITY_APPLICATION_LABORATORY,
    ]
    .into_iter()
    .filter(|capability| !profile.as_ref().is_some_and(|p| p.supports(capability, 1)))
    .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Ok(reply(
            format!(
                "The complete campaign is blocked before preparation because this host is missing: {}. Update Peritus and retry; no ambient fallback was attempted.",
                missing.join(", ")
            ),
            profile,
            plan_actions(),
            None,
        ));
    }
    state.journey = state::JourneyState {
        schema: 1,
        stage: state::JourneyStage::Running,
        source_snapshot: snapshot,
        cursor: 0,
        steps: plan(),
        laboratories: Vec::new(),
        steering: Vec::new(),
        failures: Vec::new(),
    };
    state::save(parameters, state)?;
    Ok(reply(
        "The Phase 20 campaign is ready. It will run one module-owned operation at a time, preserving live pause, steering, partial export, restart recovery, explicit gaps, and cleanup controls. Select Continue to begin.",
        profile,
        super::actions(state),
        None,
    ))
}

fn next(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
) -> Result<ModuleAction, Error> {
    use state::JourneyStage;
    match state.journey.stage {
        JourneyStage::Inactive => return start(parameters, profile, state),
        JourneyStage::Paused => {
            return Ok(reply(
                "The campaign is paused. Resume it before advancing.",
                profile,
                super::actions(state),
                None,
            ));
        }
        JourneyStage::Blocked => {
            return Ok(reply(
                "The current step is blocked. Retry it, skip it with an explicit coverage gap, or abort into cleanup.",
                profile,
                super::actions(state),
                None,
            ));
        }
        JourneyStage::Complete => {
            return Ok(reply(view(state), profile, super::actions(state), None));
        }
        JourneyStage::Running | JourneyStage::CleaningUp => {}
    }
    if state.pending.is_some() {
        return Ok(reply(
            "The current host operation is still retained. Resume that request before advancing; the campaign did not duplicate it.",
            profile,
            super::actions(state),
            None,
        ));
    }
    reconcile(state)?;
    if state.journey.stage == JourneyStage::Blocked {
        state::save(parameters, state)?;
        return Ok(reply(view(state), profile, super::actions(state), None));
    }
    if state.journey.cursor >= state.journey.steps.len() {
        state.journey.stage = JourneyStage::Complete;
        state.campaign.state = crate::records::CampaignState::Completed;
        state::save(parameters, state)?;
        return Ok(reply(
            "The complete supported-profile journey finished. The retained reports distinguish evidence-backed results, skipped or blocked work, and residual gaps; no expert-parity or universal-coverage claim is made.",
            profile,
            super::actions(state),
            None,
        ));
    }
    dispatch_current(parameters, profile, state)
}

fn dispatch_current(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
) -> Result<ModuleAction, Error> {
    let cursor = state.journey.cursor;
    let command = resolve_command(state, &state.journey.steps[cursor].command)?;
    let baseline = counters(state);
    let step = &mut state.journey.steps[cursor];
    step.state = JourneyStepState::Waiting;
    step.baseline = baseline;
    step.detail = format!("Dispatched `{command}` as the only active campaign operation.");
    state::save(parameters, state)?;
    super::route_component_command(parameters, profile, state, &command)
}

fn reconcile(state: &mut state::State) -> Result<(), Error> {
    let cursor = state.journey.cursor;
    let Some(step) = state.journey.steps.get(cursor).cloned() else {
        return Ok(());
    };
    if step.state != JourneyStepState::Waiting {
        return Ok(());
    }
    let now = counters(state);
    if now.adapter_errors > step.baseline.adapter_errors
        || now.laboratory_errors > step.baseline.laboratory_errors
    {
        if now.adapter_errors > step.baseline.adapter_errors
            && laboratory_recovery_needed(state, &step)
        {
            schedule_laboratory_recovery(state, cursor);
            return Ok(());
        }
        let detail = format!("Step `{}` produced a retained host error.", step.label);
        state.journey.steps[cursor].state = JourneyStepState::Blocked;
        state.journey.steps[cursor].detail = detail.clone();
        state.journey.failures.push(detail);
        state.journey.stage = state::JourneyStage::Blocked;
        return Ok(());
    }
    if !satisfied(state, &step, &now)? {
        let detail = format!(
            "Step `{}` returned without the required receipt or terminal state; it was not counted as complete.",
            step.label
        );
        state.journey.steps[cursor].state = JourneyStepState::Blocked;
        state.journey.steps[cursor].detail = detail.clone();
        state.journey.failures.push(detail);
        state.journey.stage = state::JourneyStage::Blocked;
        return Ok(());
    }
    if let Some(alias) = &step.laboratory_alias {
        let status = state
            .laboratory_statuses
            .last()
            .ok_or_else(|| invalid("completed laboratory creation has no retained status"))?;
        state.journey.laboratories.retain(|record| record.alias != *alias);
        state.journey.laboratories.push(state::JourneyLaboratory {
            alias: alias.clone(),
            laboratory_id: status.handle.laboratory_id.clone(),
        });
    }
    state.journey.steps[cursor].state = JourneyStepState::Complete;
    state.journey.steps[cursor].detail = "Required module-authored evidence was retained.".into();
    state.journey.cursor += 1;
    Ok(())
}

fn satisfied(
    state: &state::State,
    step: &state::JourneyStep,
    now: &state::JourneyCounters,
) -> Result<bool, Error> {
    let command = step.command.as_str();
    if let Some(adapter_id) = install_adapter_id(command) {
        return Ok(crate::adapter::installed_runtime(state, adapter_id).is_some());
    }
    let observed = match command {
        "analyze" => state.analysis_observations.len(),
        "api-run" => state.api_observations.len(),
        "browser-run" => state.browser_observations.len(),
        "identity-run" => state.identity_observations.len(),
        "file-fuzz-run" => state.file_fuzz_observations.len(),
        "workflow-run" => state.workflow_observations.len(),
        "boundary-run" => state.boundary_observations.len(),
        "graph-run" => state.attack_graph_observations.len(),
        _ => 0,
    };
    if matches!(
        command,
        "analyze"
            | "api-run"
            | "browser-run"
            | "identity-run"
            | "file-fuzz-run"
            | "workflow-run"
            | "boundary-run"
            | "graph-run"
    ) {
        return Ok(now.observations > step.baseline.observations && observed > 0);
    }
    if command == "lab-run-auto" {
        return Ok(now.laboratory_receipts > step.baseline.laboratory_receipts
            && latest_phase(state) == Some(ModuleLaboratoryPhase::Ready));
    }
    if command.starts_with("lab-create ") {
        return Ok(now.laboratory_statuses > step.baseline.laboratory_statuses
            && latest_phase(state) == Some(ModuleLaboratoryPhase::Created));
    }
    let phase = match command {
        "lab-prepare" => Some(ModuleLaboratoryPhase::Prepared),
        "lab-launch" => Some(ModuleLaboratoryPhase::Ready),
        "lab-stop" => Some(ModuleLaboratoryPhase::Stopped),
        "lab-teardown" => Some(ModuleLaboratoryPhase::TornDown),
        _ => None,
    };
    if let Some(phase) = phase {
        return Ok(now.laboratory_receipts > step.baseline.laboratory_receipts
            && latest_phase(state) == Some(phase)
            && (phase != ModuleLaboratoryPhase::TornDown
                || state
                    .laboratory_statuses
                    .last()
                    .is_some_and(|status| status.cleanup_complete)));
    }
    if command == "lab-status" {
        return Ok(now.laboratory_statuses > step.baseline.laboratory_statuses);
    }
    if command.starts_with("$select ") {
        let resolved = resolve_command(state, command)?;
        let id = resolved.trim_start_matches("lab-select ");
        return Ok(now.laboratory_statuses > step.baseline.laboratory_statuses
            && state
                .laboratory_statuses
                .last()
                .is_some_and(|status| status.handle.laboratory_id == id));
    }
    if matches!(command, "report" | "report-json" | "sarif" | "bundle") {
        return Ok(now.reports > step.baseline.reports);
    }
    Ok(false)
}

fn retry(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
) -> Result<ModuleAction, Error> {
    if state.journey.stage != state::JourneyStage::Blocked {
        return Ok(reply("No campaign step is blocked.", profile, super::actions(state), None));
    }
    let cursor = state.journey.cursor;
    let current_step = state
        .journey
        .steps
        .get(cursor)
        .ok_or_else(|| invalid("blocked journey has no current step"))?;
    let recover_laboratory = laboratory_recovery_needed(state, current_step);
    let cleaning_up = current_step.id.starts_with("cleanup-");
    state.journey.steps[cursor].state = JourneyStepState::Planned;
    state.journey.steps[cursor].detail =
        "Explicit retry requested; current identities will be revalidated.".into();
    if recover_laboratory {
        schedule_laboratory_recovery(state, cursor);
    }
    state.journey.stage =
        if cleaning_up { state::JourneyStage::CleaningUp } else { state::JourneyStage::Running };
    state::save(parameters, state)?;
    dispatch_current(parameters, profile, state)
}

fn laboratory_recovery_needed(state: &state::State, step: &state::JourneyStep) -> bool {
    state
        .adapter_errors
        .last()
        .is_some_and(|error| error.contains("laboratory_phase") && error.contains("not ready"))
        && matches!(
            step.command.as_str(),
            "api-run"
                | "browser-run"
                | "identity-run"
                | "file-fuzz-run"
                | "workflow-run"
                | "boundary-run"
                | "graph-run"
        )
}

fn schedule_laboratory_recovery(state: &mut state::State, cursor: usize) {
    state.journey.steps[cursor].state = JourneyStepState::Planned;
    state.journey.steps[cursor].detail =
        "Waiting behind exact laboratory restart reconciliation and relaunch.".into();
    state.journey.steps.splice(
        cursor..cursor,
        [
            step(
                &format!("restart-recovery-{cursor}-status"),
                "Reconcile the exact laboratory after daemon restart",
                "lab-status",
                None,
            ),
            step(
                &format!("restart-recovery-{cursor}-launch"),
                "Relaunch the exact cleanly stopped laboratory",
                "lab-launch",
                None,
            ),
        ],
    );
    state.journey.failures.push(
        "The daemon stopped a live laboratory; the exact retained identity was scheduled for status reconciliation and relaunch before retrying the interrupted adapter step."
            .into(),
    );
    state.journey.stage = state::JourneyStage::Running;
}

fn skip(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
) -> Result<ModuleAction, Error> {
    if state.journey.stage != state::JourneyStage::Blocked {
        return Ok(reply(
            "No blocked step is available to skip.",
            profile,
            super::actions(state),
            None,
        ));
    }
    let step = state
        .journey
        .steps
        .get_mut(state.journey.cursor)
        .ok_or_else(|| invalid("blocked journey has no current step"))?;
    step.state = JourneyStepState::Skipped;
    step.detail = "Explicitly skipped by the operator; this remains a coverage gap.".into();
    state.journey.cursor += 1;
    state.journey.stage = state::JourneyStage::Running;
    state::save(parameters, state)?;
    Ok(reply(
        "The blocked step was skipped and remains an explicit coverage gap. Continue advances the next independent step.",
        profile,
        super::actions(state),
        None,
    ))
}

fn pause(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
) -> Result<ModuleAction, Error> {
    if state.pending.is_some() {
        return Ok(reply(
            "A host operation is already in flight. Its durable result must settle before the journey can pause; no second operation was started.",
            profile,
            super::actions(state),
            None,
        ));
    }
    state.journey.stage = state::JourneyStage::Paused;
    state::save(parameters, state)?;
    Ok(reply(
        "The campaign is durably paused between operations.",
        profile,
        super::actions(state),
        None,
    ))
}

fn resume(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
) -> Result<ModuleAction, Error> {
    if state.journey.stage == state::JourneyStage::Paused {
        state.journey.stage = state::JourneyStage::Running;
        state::save(parameters, state)?;
    }
    next(parameters, profile, state)
}

fn steer(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
    command: &str,
) -> Result<ModuleAction, Error> {
    let direction = command.trim_start_matches("campaign-steer ").trim();
    if direction.is_empty() {
        return Err(invalid("campaign-steer requires a nonempty instruction"));
    }
    state.journey.steering.push(direction.into());
    state::save(parameters, state)?;
    Ok(reply(
        "The steering note is retained for operator visibility. It cannot widen source, host, network, credential, or adapter authority.",
        profile,
        super::actions(state),
        None,
    ))
}

fn abort(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
) -> Result<ModuleAction, Error> {
    if state.pending.is_some() {
        return Ok(reply(
            "The current host operation must settle before abort cleanup can begin. Resume it, then request abort again; no cleanup was guessed while ownership was unresolved.",
            profile,
            super::actions(state),
            None,
        ));
    }
    let latest = latest_laboratories(state);
    let mut steps = Vec::new();
    for (index, laboratory) in state.journey.laboratories.iter().rev().enumerate() {
        let Some(status) = latest.get(&laboratory.laboratory_id) else {
            continue;
        };
        if status.phase == ModuleLaboratoryPhase::TornDown {
            continue;
        }
        steps.push(step(
            &format!("cleanup-{index}-select"),
            &format!("Select {} for cleanup", laboratory.alias),
            &format!("$select {}", laboratory.alias),
            None,
        ));
        if status.phase == ModuleLaboratoryPhase::Ready {
            steps.push(step(
                &format!("cleanup-{index}-stop"),
                &format!("Stop {}", laboratory.alias),
                "lab-stop",
                None,
            ));
        }
        steps.push(step(
            &format!("cleanup-{index}-teardown"),
            &format!("Tear down {}", laboratory.alias),
            "lab-teardown",
            None,
        ));
    }
    state.journey.steps = steps;
    state.journey.cursor = 0;
    state.journey.stage = if state.journey.steps.is_empty() {
        state::JourneyStage::Complete
    } else {
        state::JourneyStage::CleaningUp
    };
    state.journey.failures.push("Operator aborted the campaign; unfinished coverage is retained as a gap and cleanup was scheduled.".into());
    state::save(parameters, state)?;
    Ok(reply(
        "The campaign is aborted. Remaining live laboratories were converted into an explicit one-at-a-time cleanup plan; select Continue until cleanup completes.",
        profile,
        super::actions(state),
        None,
    ))
}

fn counters(state: &state::State) -> state::JourneyCounters {
    state::JourneyCounters {
        scopes: state.scopes.len(),
        adapter_statuses: state.adapter_statuses.len(),
        adapter_receipts: state.adapter_receipts.len(),
        adapter_errors: state.adapter_errors.len(),
        observations: state.analysis_observations.len()
            + state.api_observations.len()
            + state.browser_observations.len()
            + state.identity_observations.len()
            + state.file_fuzz_observations.len()
            + state.workflow_observations.len()
            + state.boundary_observations.len()
            + state.attack_graph_observations.len(),
        laboratory_statuses: state.laboratory_statuses.len(),
        laboratory_receipts: state.laboratory_receipts.len(),
        laboratory_errors: state.laboratory_errors.len(),
        reports: state.reports.len(),
    }
}

fn latest_phase(state: &state::State) -> Option<ModuleLaboratoryPhase> {
    state.laboratory_statuses.last().map(|status| status.phase)
}

fn latest_laboratories(
    state: &state::State,
) -> BTreeMap<String, &peritus_plugin_sdk::ModuleLaboratoryStatus> {
    let mut latest = BTreeMap::new();
    for status in &state.laboratory_statuses {
        latest.insert(status.handle.laboratory_id.clone(), status);
    }
    latest
}

fn resolve_command(state: &state::State, command: &str) -> Result<String, Error> {
    let Some(alias) = command.strip_prefix("$select ") else {
        return Ok(command.into());
    };
    let laboratory =
        state.journey.laboratories.iter().find(|record| record.alias == alias).ok_or_else(
            || invalid(format!("campaign has no retained laboratory alias `{alias}`")),
        )?;
    Ok(format!("lab-select {}", laboratory.laboratory_id))
}

fn install_adapter_id(command: &str) -> Option<&'static str> {
    match command {
        "analyzer-install" => Some(crate::source_analysis::ADAPTER_ID),
        "api-install" => Some(crate::http_api::ADAPTER_ID),
        "browser-install" => Some(crate::browser_client::ADAPTER_ID),
        "identity-install" => Some(crate::identity_access::ADAPTER_ID),
        "file-fuzz-install" => Some(crate::file_fuzz::ADAPTER_ID),
        "workflow-install" => Some(crate::workflow_state::ADAPTER_ID),
        "boundary-install" => Some(crate::boundary_authority::ADAPTER_ID),
        "graph-install" => Some(crate::attack_graph::ADAPTER_ID),
        _ => None,
    }
}

fn step(
    id: &str,
    label: &str,
    command: &str,
    laboratory_alias: Option<&str>,
) -> state::JourneyStep {
    state::JourneyStep {
        id: id.into(),
        label: label.into(),
        command: command.into(),
        state: JourneyStepState::Planned,
        laboratory_alias: laboratory_alias.map(Into::into),
        baseline: state::JourneyCounters::default(),
        detail: String::new(),
    }
}

fn plan() -> Vec<state::JourneyStep> {
    let mut steps = Vec::new();
    for (id, label, command) in [
        ("install-source", "Install source analyzer", "analyzer-install"),
        ("analyze", "Analyze immutable scoped source", "analyze"),
    ] {
        steps.push(step(id, label, command, None));
    }
    add_open_lab(&mut steps, "source", "lab-create source");
    steps.push(step(
        "source-process",
        "Execute the best discovered real source entry point",
        "lab-run-auto",
        None,
    ));
    steps.push(step("source-snapshot", "Snapshot disposable source effects", "lab-snapshot", None));
    steps.push(step("source-stop", "Stop source laboratory", "lab-stop", None));
    steps.push(step(
        "source-teardown",
        "Tear down source laboratory and verify original bytes",
        "lab-teardown",
        None,
    ));
    for (id, label, command) in [
        ("export-markdown", "Export Markdown report", "report"),
        ("export-json", "Export JSON report", "report-json"),
        ("export-sarif", "Export SARIF projection", "sarif"),
        ("export-replay", "Export replay bundle", "bundle"),
    ] {
        steps.push(step(id, label, command, None));
    }
    steps
}

fn add_open_lab(steps: &mut Vec<state::JourneyStep>, alias: &str, create: &str) {
    steps.push(step(
        &format!("{alias}-create"),
        &format!("Create {alias} laboratory"),
        create,
        Some(alias),
    ));
    steps.push(step(
        &format!("{alias}-prepare"),
        &format!("Prepare {alias} laboratory"),
        "lab-prepare",
        None,
    ));
    steps.push(step(
        &format!("{alias}-launch"),
        &format!("Launch {alias} laboratory"),
        "lab-launch",
        None,
    ));
}

fn plan_text() -> String {
    let steps = plan();
    let mut text = format!(
        "# Source-bound Red Team campaign\n\n{} sequential steps; at most one host operation is active. The journey scans the exact immutable source, copies the complete tree, executes a discovered real entry point without requiring target-specific contracts, records copied-tree effects, proves cleanup and original-source integrity, and exports Markdown, JSON, SARIF and replay artifacts. Class-specific adapters remain separate applicable-method steps; their bundled fixtures are calibration targets and are never substituted for the selected application.\n\n",
        steps.len()
    );
    for (index, step) in steps.iter().enumerate() {
        text.push_str(&format!("{}. {} (`{}`)\n", index + 1, step.label, step.command));
    }
    text.push_str("\nFailures block only the current step. Retry, explicit skip, partial export, steering, pause/resume, restart recovery and abort cleanup remain available. Source text and target output are untrusted and cannot alter this plan or enlarge authority.");
    text
}

pub(crate) fn view(state: &state::State) -> String {
    let complete =
        state.journey.steps.iter().filter(|step| step.state == JourneyStepState::Complete).count();
    let skipped =
        state.journey.steps.iter().filter(|step| step.state == JourneyStepState::Skipped).count();
    let current = state.journey.steps.get(state.journey.cursor);
    let mut text = format!(
        "# Complete Red Team campaign\n\n- State: `{:?}`\n- Source snapshot: `{}`\n- Progress: {complete}/{} complete; {skipped} skipped\n- Active host operations: {}\n- Current step: `{}`\n- Current detail: {}\n- Retained steering notes: {}\n- Retained failures/gaps: {}\n- Known laboratory identities: {}\n\n",
        state.journey.stage,
        if state.journey.source_snapshot.is_empty() {
            "not started"
        } else {
            &state.journey.source_snapshot
        },
        state.journey.steps.len(),
        usize::from(state.pending.is_some()),
        current.map_or("none", |step| step.label.as_str()),
        current.map_or("none", |step| step.detail.as_str()),
        state.journey.steering.len(),
        state.journey.failures.len(),
        state.journey.laboratories.len(),
    );
    for step in &state.journey.steps {
        text.push_str(&format!("- `{:?}` — {}\n", step.state, step.label));
    }
    text
}
