//! Inert licensed public-knowledge recipes that may guide, but never establish, research facts.

use crate::{Error, digest, invalid, reply, state, state::ResearchAutonomyPhase};
use peritus_plugin_sdk::{
    MODULE_RESEARCH_CONTRACT_VERSION, ModuleAction, ModuleHostProfile,
    ModuleResearchEmulationEvidenceClass, ModuleResearchEmulationProvenance,
    ModuleResearchEmulationRecipe,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::fmt::Write as _;

const MAXIMUM_RECIPES: usize = 16;
const MAXIMUM_LIST_ITEMS: usize = 32;
const MAXIMUM_TEXT: usize = 2_048;
const WSTG_STORED_XSS: &[u8] =
    include_bytes!("../resources/emulation-recipes/owasp-wstg-stored-xss-v4.2.json");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmbeddedRecipe {
    schema: u16,
    id: String,
    version: String,
    title: String,
    provenance: Vec<ModuleResearchEmulationProvenance>,
    license: String,
    evidence_class: ModuleResearchEmulationEvidenceClass,
    attacker_access: Vec<String>,
    tools_and_roles: Vec<String>,
    prerequisites: Vec<String>,
    observed_or_claimed_primitives: Vec<String>,
    harmless_laboratory_equivalents: Vec<String>,
    adapter_mappings: Vec<String>,
    unsafe_or_unsupported_gaps: Vec<String>,
    user_embargo_metadata: Option<String>,
    executable_content: bool,
}

pub(crate) fn handles(command: &str) -> bool {
    matches!(command, "research-recipes")
        || command.starts_with("research-recipe ")
        || command.starts_with("research-recipe-seed ")
}

pub(crate) fn command(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
    command: &str,
) -> Result<ModuleAction, Error> {
    if command == "research-recipes" {
        return Ok(reply(catalog_view()?, profile, super::actions(state), None));
    }
    if let Some(id) = command.strip_prefix("research-recipe-seed ") {
        return seed(parameters, profile, state, id.trim());
    }
    let id = command.strip_prefix("research-recipe ").unwrap_or_default().trim();
    if id.is_empty() {
        return Err(invalid("use `research-recipe RECIPE_ID`"));
    }
    let recipe =
        find(id)?.ok_or_else(|| invalid("the selected emulation recipe does not exist"))?;
    Ok(reply(recipe_view(&recipe), profile, super::actions(state), None))
}

pub(crate) fn catalog() -> Result<Vec<ModuleResearchEmulationRecipe>, Error> {
    let mut recipes = vec![parse(WSTG_STORED_XSS)?];
    recipes.sort_by(|left, right| left.id.cmp(&right.id));
    if recipes.len() > MAXIMUM_RECIPES {
        return Err(invalid("the emulation recipe catalog exceeds its hard bound"));
    }
    Ok(recipes)
}

pub(crate) fn find(id: &str) -> Result<Option<ModuleResearchEmulationRecipe>, Error> {
    Ok(catalog()?.into_iter().find(|recipe| recipe.id == id))
}

pub(crate) fn selection_digest(
    campaign_id: &str,
    recipe_id: &str,
    recipe_digest: &str,
    selected_turn: u16,
) -> String {
    digest(
        format!(
            "peritus.red-team.emulation-recipe-selection.v1\0{campaign_id}\0{recipe_id}\0{recipe_digest}\0{selected_turn}"
        )
        .as_bytes(),
    )
}

pub(crate) fn selected_projection(state: &state::State) -> Result<Value, Error> {
    let mut selected = Vec::new();
    for seed in &state.research_autonomy.recipe_seeds {
        let recipe = find(&seed.recipe_id)?
            .ok_or_else(|| invalid("a selected emulation recipe is absent from this module"))?;
        selected.push(json!({
            "id": recipe.id,
            "version": recipe.version,
            "record_digest": recipe.record_digest,
            "evidence_class": recipe.evidence_class,
            "prerequisites": recipe.prerequisites,
            "claimed_primitives": recipe.observed_or_claimed_primitives,
            "harmless_laboratory_equivalents": recipe.harmless_laboratory_equivalents,
            "adapter_mappings": recipe.adapter_mappings,
            "unsafe_or_unsupported_gaps": recipe.unsafe_or_unsupported_gaps,
            "proof_status": "inert hypothesis seed; creates no selected-target fact",
        }));
    }
    Ok(Value::Array(selected))
}

fn parse(bytes: &[u8]) -> Result<ModuleResearchEmulationRecipe, Error> {
    let embedded: EmbeddedRecipe = serde_json::from_slice(bytes)?;
    let recipe = ModuleResearchEmulationRecipe {
        schema: embedded.schema,
        id: embedded.id,
        version: embedded.version,
        title: embedded.title,
        record_digest: digest(bytes),
        provenance: embedded.provenance,
        license: embedded.license,
        evidence_class: embedded.evidence_class,
        attacker_access: embedded.attacker_access,
        tools_and_roles: embedded.tools_and_roles,
        prerequisites: embedded.prerequisites,
        observed_or_claimed_primitives: embedded.observed_or_claimed_primitives,
        harmless_laboratory_equivalents: embedded.harmless_laboratory_equivalents,
        adapter_mappings: embedded.adapter_mappings,
        unsafe_or_unsupported_gaps: embedded.unsafe_or_unsupported_gaps,
        user_embargo_metadata: embedded.user_embargo_metadata,
        executable_content: embedded.executable_content,
    };
    validate(&recipe)?;
    Ok(recipe)
}

fn validate(recipe: &ModuleResearchEmulationRecipe) -> Result<(), Error> {
    if recipe.schema != MODULE_RESEARCH_CONTRACT_VERSION
        || recipe.id.is_empty()
        || recipe.id.len() > 160
        || !recipe
            .id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || recipe.version.is_empty()
        || recipe.title.is_empty()
        || recipe.license.is_empty()
        || recipe.record_digest.len() != 64
        || recipe.executable_content
        || recipe.provenance.is_empty()
        || recipe.prerequisites.is_empty()
        || recipe.observed_or_claimed_primitives.is_empty()
        || recipe.harmless_laboratory_equivalents.is_empty()
        || recipe.adapter_mappings.is_empty()
        || recipe.unsafe_or_unsupported_gaps.is_empty()
    {
        return Err(invalid("an embedded emulation recipe violates its inert record contract"));
    }
    for source in &recipe.provenance {
        if source.kind.is_empty()
            || !source.url.starts_with("https://")
            || source.retrieved_on.len() != 10
            || source.kind.len() > 160
            || source.url.len() > MAXIMUM_TEXT
        {
            return Err(invalid("emulation recipe provenance is incomplete or non-HTTPS"));
        }
    }
    let lists = [
        &recipe.attacker_access,
        &recipe.tools_and_roles,
        &recipe.prerequisites,
        &recipe.observed_or_claimed_primitives,
        &recipe.harmless_laboratory_equivalents,
        &recipe.adapter_mappings,
        &recipe.unsafe_or_unsupported_gaps,
    ];
    if lists.iter().any(|items| {
        items.len() > MAXIMUM_LIST_ITEMS
            || items
                .iter()
                .any(|item| item.is_empty() || item.len() > MAXIMUM_TEXT || item.contains('\0'))
    }) || recipe
        .user_embargo_metadata
        .as_ref()
        .is_some_and(|value| value.is_empty() || value.len() > MAXIMUM_TEXT || value.contains('\0'))
    {
        return Err(invalid("emulation recipe text exceeds its finite record bounds"));
    }
    let allowed = [
        "http.campaign.v1",
        "browser.campaign.v1",
        "identity.campaign.v1",
        "file-fuzz.campaign.v1",
        "workflow.campaign.v1",
        "boundary.campaign.v1",
    ];
    if recipe.adapter_mappings.iter().any(|operation| !allowed.contains(&operation.as_str())) {
        return Err(invalid("emulation recipe names an unregistered experiment operation"));
    }
    Ok(())
}

fn seed(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
    id: &str,
) -> Result<ModuleAction, Error> {
    if id.is_empty() {
        return Err(invalid("use `research-recipe-seed RECIPE_ID`"));
    }
    if matches!(
        state.research_autonomy.phase,
        ResearchAutonomyPhase::Inactive
            | ResearchAutonomyPhase::Cancelled
            | ResearchAutonomyPhase::Complete
            | ResearchAutonomyPhase::Blocked
    ) {
        return Err(invalid(
            "select an emulation recipe only during an active or paused Stage 4 campaign",
        ));
    }
    let recipe =
        find(id)?.ok_or_else(|| invalid("the selected emulation recipe does not exist"))?;
    if state.research_autonomy.recipe_seeds.iter().any(|seed| seed.recipe_id == recipe.id) {
        return Ok(reply(
            format!(
                "Recipe `{}` is already selected as an inert `{:?}` hypothesis seed. It created no primitive, finding, edge, or target effect.",
                recipe.id, recipe.evidence_class
            ),
            profile,
            super::actions(state),
            None,
        ));
    }
    if state.research_autonomy.recipe_seeds.len() >= MAXIMUM_RECIPES {
        return Err(invalid("the active campaign reached its 16-recipe selection bound"));
    }
    let selected_turn = state.research_autonomy.turn;
    let selection_digest = selection_digest(
        &state.research_autonomy.campaign_id,
        &recipe.id,
        &recipe.record_digest,
        selected_turn,
    );
    state.research_autonomy.recipe_seeds.push(state::ResearchRecipeSeed {
        schema: MODULE_RESEARCH_CONTRACT_VERSION,
        recipe_id: recipe.id.clone(),
        recipe_digest: recipe.record_digest.clone(),
        evidence_class: recipe.evidence_class,
        selected_turn,
        selection_digest,
    });
    state::save(parameters, state)?;
    Ok(reply(
        format!(
            "Recipe `{}` was selected as an inert `{:?}` hypothesis seed for future model turns. It created no primitive, finding, edge, or target effect; only selected-target receipts can do so.",
            recipe.id, recipe.evidence_class
        ),
        profile,
        super::actions(state),
        None,
    ))
}

fn catalog_view() -> Result<String, Error> {
    let recipes = catalog()?;
    let mut text = String::from(
        "# Inert emulation recipe catalog\n\nRecipes retain provenance and evidence class, contain no executable incident content, and create no selected-target evidence. Explicit selection can guide future bounded proposals only.\n\n",
    );
    for recipe in recipes {
        let _ = writeln!(
            text,
            "- `{}` v{} — `{:?}` — license `{}` — adapters {} — digest `{}` — {}",
            recipe.id,
            recipe.version,
            recipe.evidence_class,
            recipe.license,
            recipe.adapter_mappings.join(", "),
            recipe.record_digest,
            recipe.title,
        );
    }
    Ok(text)
}

fn recipe_view(recipe: &ModuleResearchEmulationRecipe) -> String {
    format!(
        "# Emulation recipe `{}`\n\n- Version: `{}`\n- Evidence class: `{:?}`\n- License: `{}`\n- Record digest: `{}`\n- Executable content: false\n- Provenance: {}\n- Attacker access: {}\n- Prerequisites: {}\n- Claimed primitives: {}\n- Harmless laboratory equivalents: {}\n- Registered adapters: {}\n- Unsafe or unsupported gaps: {}\n- User embargo metadata: {}\n\nThis record is an inert hypothesis source. It cannot establish a finding until the exact selected target independently produces admitted receipts.",
        recipe.id,
        recipe.version,
        recipe.evidence_class,
        recipe.license,
        recipe.record_digest,
        recipe
            .provenance
            .iter()
            .map(|source| format!("{} {} ({})", source.kind, source.url, source.retrieved_on))
            .collect::<Vec<_>>()
            .join("; "),
        recipe.attacker_access.join("; "),
        recipe.prerequisites.join("; "),
        recipe.observed_or_claimed_primitives.join("; "),
        recipe.harmless_laboratory_equivalents.join("; "),
        recipe.adapter_mappings.join(", "),
        recipe.unsafe_or_unsupported_gaps.join("; "),
        recipe.user_embargo_metadata.as_deref().unwrap_or("none"),
    )
}
