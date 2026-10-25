//! Diamond language/application binding over the generic isolated module-worker contract.

use crate::{
    Error, adapter, attack_graph, boundary_authority, browser_client, digest, file_fuzz, http_api,
    identity_access, invalid, reply, state, workflow_state,
};
use peritus_plugin_sdk::{
    ModuleAction, ModuleAdapterExecuteRequest, ModuleAdapterExecutionReceipt, ModuleHostProfile,
    ModuleLaboratoryPhase,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub(crate) const ADAPTER_ID: &str = "peritus.diamond-application";
pub(crate) const OPERATION: &str = "diamond.complete-campaign.v1";
const RECEIPT_DECODER: &str = "peritus.diamond-application.decoder@1";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiamondCampaign {
    schema: u16,
    profile: String,
    laboratory_id: String,
    source_snapshot: String,
    http: Value,
    browser: Value,
    identity: Value,
    parser: Value,
    workflow: Value,
    boundary: Value,
    attack_graph: Value,
}

pub(crate) fn handles(command: &str) -> bool {
    matches!(
        command,
        "diamond" | "diamond-install" | "diamond-run" | "diamond-status" | "diamond-remove"
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
            "This Peritus host does not advertise generic isolated module workers. The Diamond binding remains blocked; no ambient process fallback was attempted.",
            profile,
            super::actions(state),
            None,
        ));
    }
    match command {
        "diamond" => Ok(reply(view(state), profile, super::actions(state), None)),
        "diamond-install" => adapter::install(parameters, state, ADAPTER_ID),
        "diamond-status" => adapter::status_for(parameters, state, ADAPTER_ID),
        "diamond-remove" => adapter::remove_for(parameters, state, ADAPTER_ID),
        "diamond-run" => {
            let runtime = adapter::installed_runtime(state, ADAPTER_ID).ok_or_else(|| {
                invalid("install the Diamond application binding before running it")
            })?;
            let laboratory = state
                .laboratory_statuses
                .iter()
                .rev()
                .find(|status| status.phase == ModuleLaboratoryPhase::Ready)
                .ok_or_else(|| invalid("launch a ready disposable complete-source laboratory before running the Diamond binding"))?;
            adapter::execute(
                parameters,
                state,
                ModuleAdapterExecuteRequest {
                    schema: 1,
                    runtime,
                    operation: OPERATION.into(),
                    input: json!({
                        "schema": 1,
                        "profile": "diamond-lang.v1",
                        "laboratory_id": laboratory.handle.laboratory_id,
                        "source_snapshot": laboratory.handle.source_snapshot,
                    }),
                },
            )
        }
        _ => Err(invalid("unknown Diamond application binding command")),
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
        || receipt.executed_by != "peritus-red-team/diamond-application@1"
    {
        return Err(invalid(
            "Diamond application receipt has an unregistered module runtime identity",
        ));
    }
    let observation: DiamondCampaign = serde_json::from_value(receipt.observation)?;
    if observation.schema != 1 || observation.profile != "diamond-lang.v1" {
        return Err(invalid("Diamond application receipt has an unsupported profile"));
    }
    let laboratory = state
        .laboratory_statuses
        .iter()
        .rev()
        .find(|status| status.handle.laboratory_id == observation.laboratory_id)
        .ok_or_else(|| invalid("Diamond application receipt belongs to an unknown laboratory"))?;
    if laboratory.phase != ModuleLaboratoryPhase::Ready
        || laboratory.handle.source_snapshot != observation.source_snapshot
    {
        return Err(invalid("Diamond application receipt belongs to a stale laboratory"));
    }

    let values = [
        (
            http_api::OPERATION,
            "peritus.http-api.decoder@1",
            "peritus-red-team/http-api@1",
            observation.http,
        ),
        (
            browser_client::OPERATION,
            "peritus.browser-client.decoder@1",
            "peritus-red-team/browser-client@1",
            observation.browser,
        ),
        (
            identity_access::OPERATION,
            "peritus.identity-access.decoder@1",
            "peritus-red-team/identity-access@1",
            observation.identity,
        ),
        (
            file_fuzz::OPERATION,
            "peritus.file-parser.decoder@1",
            "peritus-red-team/file-parser@1",
            observation.parser,
        ),
        (
            workflow_state::OPERATION,
            "peritus.workflow-state.decoder@1",
            "peritus-red-team/workflow-state@1",
            observation.workflow,
        ),
        (
            boundary_authority::OPERATION,
            "peritus.boundary-authority.decoder@1",
            "peritus-red-team/boundary-authority@1",
            observation.boundary,
        ),
        (
            attack_graph::OPERATION,
            "peritus.attack-graph.decoder@1",
            "peritus-red-team/attack-graph@1",
            observation.attack_graph,
        ),
    ];
    let mut latest = None;
    for (operation, decoder, executed_by, value) in values {
        let synthetic = ModuleAdapterExecutionReceipt {
            schema: 1,
            runtime_digest: receipt.runtime_digest.clone(),
            operation: operation.into(),
            input_digest: digest(&serde_json::to_vec(&value)?),
            receipt_decoder: decoder.into(),
            observation: value,
            executed_by: executed_by.into(),
        };
        latest = Some(match operation {
            http_api::OPERATION => http_api::admit(parameters, profile, state, synthetic)?,
            browser_client::OPERATION => {
                browser_client::admit(parameters, profile, state, synthetic)?
            }
            identity_access::OPERATION => {
                identity_access::admit(parameters, profile, state, synthetic)?
            }
            file_fuzz::OPERATION => file_fuzz::admit(parameters, profile, state, synthetic)?,
            workflow_state::OPERATION => {
                workflow_state::admit(parameters, profile, state, synthetic)?
            }
            boundary_authority::OPERATION => {
                boundary_authority::admit(parameters, profile, state, synthetic)?
            }
            attack_graph::OPERATION => attack_graph::admit(parameters, profile, state, synthetic)?,
            _ => unreachable!("static Diamond observation route"),
        });
    }
    let _ = latest;
    Ok(reply(
        "# Diamond application campaign complete\n\nThe disposable Diamond source was compiled once and exercised through HTTP, a real browser, identity/session, parser, workflow, boundary, and cross-adapter attack-graph bindings. Seven independently validated class observations are retained; inspect each class report for bounded results and explicit gaps.",
        profile,
        super::actions(state),
        None,
    ))
}

fn view(state: &state::State) -> String {
    format!(
        "# Diamond application binding\n\n- Registered adapter: `{ADAPTER_ID}`\n- Operation: `{OPERATION}`\n- Installed: {}\n- Complete campaigns: {}\n\nThis binding recognizes the Diamond Rust workspace, compiles only the disposable source copy, launches the real `diamond` CLI and HTTP runtime, and returns the seven standard Red Team evidence classes without teaching the Peritus host anything application-specific.",
        adapter::installed_runtime(state, ADAPTER_ID).is_some(),
        state
            .attack_graph_observations
            .iter()
            .filter(|item| item.suite_version.contains("diamond"))
            .count(),
    )
}
