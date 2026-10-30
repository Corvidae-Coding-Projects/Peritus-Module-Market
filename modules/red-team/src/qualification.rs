//! Read-only Stage 8 supported-profile and residual-gap projection.

use crate::{reply, state::State};
use peritus_plugin_sdk::{ModuleAction, ModuleHostProfile};

const QUALIFICATION: &str = include_str!("../QUALIFICATION.md");

pub(crate) fn command(profile: &Option<ModuleHostProfile>, state: &State) -> ModuleAction {
    reply(QUALIFICATION, profile, super::actions(state), None)
}
