//! Phase-nine target graph and method-backed coverage compiler.

use crate::{
    Error, digest, invalid,
    records::{
        ApplicationComponentRecord, ApplicationSurfaceRecord, CoverageCellRecord, CoverageRecord,
        CoverageState, IdentityConfigurationRecord, MethodAvailability, MethodRecord,
        RECORD_SCHEMA_VERSION, RecordId, RecordKind, SecurityPropertyRecord, StandardReference,
        SurfaceKind, SurfaceState, TargetProfileKind, TargetProfileRecord, TrustBoundaryRecord,
    },
    state::{FamilyRoute, InventoryRecord, State, security_families},
};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const COVERAGE_SCHEMA_VERSION: u16 = 1;
pub(crate) const SOURCE_REVIEW_METHOD: &str = "analysis.scoped-source-review.v1";
pub(crate) const STATIC_ANALYSIS_METHOD: &str = "analysis.static-source.v1";
pub(crate) const HTTP_API_METHOD: &str = "runtime.http-api.v1";
pub(crate) const BROWSER_METHOD: &str = "runtime.browser-client.v1";
pub(crate) const IDENTITY_METHOD: &str = "runtime.identity-access.v1";
pub(crate) const FILE_FUZZ_METHOD: &str = "runtime.file-parser-fuzz.v1";
pub(crate) const WORKFLOW_STATE_METHOD: &str = "runtime.workflow-state.v1";
pub(crate) const BOUNDARY_AUTHORITY_METHOD: &str = "runtime.boundary-authority.v1";
pub(crate) const ATTACK_GRAPH_METHOD: &str = "runtime.cross-adapter-attack-graph.v1";
pub(crate) const CANARY_METHOD: &str = "runtime.linux-canary-disclosure.v1";
pub(crate) const UNSUPPORTED_METHOD: &str = "gap.no-compatible-runtime.v1";

pub(crate) fn initialize_methods(state: &mut State) {
    for method in methods(&state.campaign.id) {
        if !state.methods.iter().any(|existing| existing.name == method.name) {
            state.methods.push(method);
        }
    }
}

/// Advances only static-analysis cells backed by one exact host-authored scan receipt.
pub(crate) fn record_static_method(
    state: &mut State,
    evidence: &RecordId,
    source_snapshot: &str,
) -> usize {
    let method_ids = state
        .methods
        .iter()
        .filter(|method| method.name == STATIC_ANALYSIS_METHOD)
        .map(|method| method.id.clone())
        .collect::<BTreeSet<_>>();
    let mut count = 0;
    for cell in &mut state.coverage_cells {
        if method_ids.contains(&cell.method) {
            cell.state = CoverageState::Examined;
            cell.reason = format!(
                "Host static analyzers completed against snapshot `{source_snapshot}`. This establishes source examination only, not runtime exploitability."
            );
            if !cell.evidence.contains(evidence) {
                cell.evidence.push(evidence.clone());
            }
            cell.invalidated_by = None;
            count += 1;
        }
    }
    rebuild_legacy_coverage(state);
    count
}

/// Advances compatible HTTP/API cells backed by one exact host traffic receipt.
pub(crate) fn record_http_method(state: &mut State, evidence: &RecordId) -> usize {
    let method_ids = state
        .methods
        .iter()
        .filter(|method| method.name == HTTP_API_METHOD)
        .map(|method| method.id.clone())
        .collect::<BTreeSet<_>>();
    let families = [
        "input_interpretation_and_injection",
        "network_and_protocol_boundaries",
        "configuration_secrets_and_observability",
        "business_logic_and_workflow",
    ];
    let mut count = 0;
    for cell in &mut state.coverage_cells {
        if method_ids.contains(&cell.method) && families.contains(&cell.family.as_str()) {
            cell.state = CoverageState::Examined;
            cell.reason = "The registered HTTP/API adapter executed the pinned real-interface suite with host-captured traffic and copied-state oracles.".into();
            if !cell.evidence.contains(evidence) {
                cell.evidence.push(evidence.clone());
            }
            cell.invalidated_by = None;
            count += 1;
        }
    }
    rebuild_legacy_coverage(state);
    count
}

/// Advances browser-compatible cells backed by one exact host browser receipt.
pub(crate) fn record_browser_method(state: &mut State, evidence: &RecordId) -> usize {
    let method_ids = state
        .methods
        .iter()
        .filter(|method| method.name == BROWSER_METHOD)
        .map(|method| method.id.clone())
        .collect::<BTreeSet<_>>();
    let families = [
        "input_interpretation_and_injection",
        "authentication_and_sessions",
        "authorization_and_tenancy",
        "browser_and_client_trust",
        "network_and_protocol_boundaries",
        "business_logic_and_workflow",
    ];
    let mut count = 0;
    for cell in &mut state.coverage_cells {
        if method_ids.contains(&cell.method) && families.contains(&cell.family.as_str()) {
            cell.state = CoverageState::Examined;
            cell.reason = "The registered browser-client adapter executed its pinned suite through an isolated real Chromium context with host-correlated copied-state, traffic, screenshot, trace, upload, and download evidence.".into();
            if !cell.evidence.contains(evidence) {
                cell.evidence.push(evidence.clone());
            }
            cell.invalidated_by = None;
            count += 1;
        }
    }
    rebuild_legacy_coverage(state);
    count
}

/// Advances authentication and authorization cells backed by one exact host identity receipt.
pub(crate) fn record_identity_method(state: &mut State, evidence: &RecordId) -> usize {
    let method_ids = state
        .methods
        .iter()
        .filter(|method| method.name == IDENTITY_METHOD)
        .map(|method| method.id.clone())
        .collect::<BTreeSet<_>>();
    let families =
        ["authentication_and_sessions", "authorization_and_tenancy", "business_logic_and_workflow"];
    let mut count = 0;
    for cell in &mut state.coverage_cells {
        if method_ids.contains(&cell.method) && families.contains(&cell.family.as_str()) {
            cell.state = CoverageState::Examined;
            cell.reason = "The registered identity-access adapter executed its pinned multi-user lifecycle and differential authorization suite through host-private credentials and copied-state oracles.".into();
            if !cell.evidence.contains(evidence) {
                cell.evidence.push(evidence.clone());
            }
            cell.invalidated_by = None;
            count += 1;
        }
    }
    rebuild_legacy_coverage(state);
    count
}

/// Advances file, parser, unsafe-interface, and availability cells backed by one host receipt.
pub(crate) fn record_file_fuzz_method(state: &mut State, evidence: &RecordId) -> usize {
    let method_ids = state
        .methods
        .iter()
        .filter(|method| method.name == FILE_FUZZ_METHOD)
        .map(|method| method.id.clone())
        .collect::<BTreeSet<_>>();
    let families = [
        "files_paths_archives_and_uploads",
        "input_interpretation_and_injection",
        "memory_integers_and_unsafe_interfaces",
        "availability_and_resource_use",
    ];
    let mut count = 0;
    for cell in &mut state.coverage_cells {
        if method_ids.contains(&cell.method) && families.contains(&cell.family.as_str()) {
            cell.state = CoverageState::Examined;
            cell.reason = "The registered host file/parser adapter exercised real filesystem and archive boundaries, structured inputs, deterministic generated cases, and an isolated native child fault with private canaries and minimized replay inputs.".into();
            if !cell.evidence.contains(evidence) {
                cell.evidence.push(evidence.clone());
            }
            cell.invalidated_by = None;
            count += 1;
        }
    }
    rebuild_legacy_coverage(state);
    count
}

/// Advances business-workflow and availability cells backed by one host workflow receipt.
pub(crate) fn record_workflow_state_method(state: &mut State, evidence: &RecordId) -> usize {
    let method_ids = state
        .methods
        .iter()
        .filter(|method| method.name == WORKFLOW_STATE_METHOD)
        .map(|method| method.id.clone())
        .collect::<BTreeSet<_>>();
    let families = ["business_logic_and_workflow", "availability_and_resource_use"];
    let mut count = 0;
    for cell in &mut state.coverage_cells {
        if method_ids.contains(&cell.method) && families.contains(&cell.family.as_str()) {
            cell.state = CoverageState::Examined;
            cell.reason = "The registered host workflow-state adapter exercised documented invariants across real ordered actions, duplicate/retry/cancellation/crash recovery, quota/accounting, and a retained deterministic two-worker schedule.".into();
            if !cell.evidence.contains(evidence) {
                cell.evidence.push(evidence.clone());
            }
            cell.invalidated_by = None;
            count += 1;
        }
    }
    rebuild_legacy_coverage(state);
    count
}

/// Advances network, TLS, platform, and agent-authority cells backed by one host receipt.
pub(crate) fn record_boundary_authority_method(state: &mut State, evidence: &RecordId) -> usize {
    let method_ids = state
        .methods
        .iter()
        .filter(|method| method.name == BOUNDARY_AUTHORITY_METHOD)
        .map(|method| method.id.clone())
        .collect::<BTreeSet<_>>();
    let families = [
        "network_and_protocol_boundaries",
        "cryptography_and_key_lifecycle",
        "configuration_secrets_and_observability",
        "privilege_sandbox_and_platform",
        "agent_prompt_and_tool_authority",
    ];
    let mut count = 0;
    for cell in &mut state.coverage_cells {
        if method_ids.contains(&cell.method) && families.contains(&cell.family.as_str()) {
            cell.state = CoverageState::Examined;
            cell.reason = "The registered host boundary-authority adapter exercised private DNS, redirect, callback, proxy, SSRF, TLS, local policy, contained privilege, and confused-deputy cases without granting routable network or host authority.".into();
            if !cell.evidence.contains(evidence) {
                cell.evidence.push(evidence.clone());
            }
            cell.invalidated_by = None;
            count += 1;
        }
    }
    rebuild_legacy_coverage(state);
    count
}

/// Advances cross-family cells only after a receipt-backed graph, counterfactual, and repair replay.
pub(crate) fn record_attack_graph_method(state: &mut State, evidence: &RecordId) -> usize {
    let method_ids = state
        .methods
        .iter()
        .filter(|method| method.name == ATTACK_GRAPH_METHOD)
        .map(|method| method.id.clone())
        .collect::<BTreeSet<_>>();
    let families = [
        "input_interpretation_and_injection",
        "browser_and_client_trust",
        "business_logic_and_workflow",
    ];
    let mut count = 0;
    for cell in &mut state.coverage_cells {
        if method_ids.contains(&cell.method) && families.contains(&cell.family.as_str()) {
            cell.state = CoverageState::Examined;
            cell.reason = "The registered host attack-graph adapter composed exact source, private HTTP, and isolated-browser receipts; broke a prerequisite, rejected an unsupported edge, and accepted the copy-only repair only after adapter-specific replays.".into();
            if !cell.evidence.contains(evidence) {
                cell.evidence.push(evidence.clone());
            }
            cell.invalidated_by = None;
            count += 1;
        }
    }
    rebuild_legacy_coverage(state);
    count
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InventoryInput {
    pub(crate) profiles: Vec<ProfileInput>,
    pub(crate) components: Vec<ComponentInput>,
    pub(crate) surfaces: Vec<SurfaceInput>,
    pub(crate) threat_boundaries: Vec<ThreatBoundaryInput>,
    pub(crate) identities: Vec<IdentityInput>,
    pub(crate) properties: Vec<PropertyInput>,
    pub(crate) routes: Vec<RouteInput>,
    pub(crate) source_evidence: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileInput {
    name: String,
    kind: String,
    operating_systems: Vec<String>,
    languages: Vec<String>,
    services: Vec<String>,
    stores: Vec<String>,
    interfaces: Vec<String>,
    unavailable_claims: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ComponentInput {
    name: String,
    profile: String,
    kind: String,
    source_paths: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SurfaceInput {
    name: String,
    profile: String,
    component: String,
    kind: String,
    entry_point: String,
    source_paths: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ThreatBoundaryInput {
    name: String,
    profile: String,
    from_component: String,
    to_component: String,
    protected_assets: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdentityInput {
    name: String,
    profile: String,
    attacker: String,
    privileges: Vec<String>,
    configuration: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PropertyInput {
    id: String,
    family: String,
    statement: String,
    standards: Vec<StandardReference>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RouteInput {
    family: String,
    state: String,
    reason: String,
    surfaces: Vec<String>,
    identities: Vec<String>,
    properties: Vec<String>,
    methods: Vec<String>,
}

/// Compiles model-discovered names into validated durable identities and exact coverage cells.
pub(crate) fn compile(
    state: &mut State,
    input: InventoryInput,
    evidence: Vec<RecordId>,
) -> Result<InventoryRecord, Error> {
    validate_count(&input.profiles, 1, 32, "target profiles")?;
    validate_count(&input.components, 1, 256, "components")?;
    validate_count(&input.surfaces, 1, 512, "surfaces")?;
    validate_count(&input.threat_boundaries, 1, 256, "trust boundaries")?;
    validate_count(&input.identities, 1, 128, "identity configurations")?;
    validate_count(&input.properties, 1, 512, "security properties")?;
    if evidence.is_empty() {
        return Err(invalid("coverage compilation requires exact retained source evidence"));
    }
    let scope = state
        .scopes
        .last()
        .ok_or_else(|| invalid("coverage compilation has no active scope"))?
        .id
        .clone();
    let campaign = state.campaign.id.clone();
    let profiles = compile_profiles(&input.profiles, &campaign, &scope, &evidence)?;
    let profile_ids = by_name(&profiles, |record| (&record.name, &record.id))?;
    let components = compile_components(state, &input.components, &campaign, &scope, &profile_ids)?;
    let component_ids = by_name(&components, |record| (&record.name, &record.id))?;
    let component_records =
        components.iter().map(|record| (record.id.clone(), record)).collect::<BTreeMap<_, _>>();
    let surfaces =
        compile_surfaces(state, &input.surfaces, &campaign, &scope, &profile_ids, &component_ids)?;
    let surface_ids = by_name(&surfaces, |record| (&record.name, &record.id))?;
    let boundaries = compile_boundaries(
        &input.threat_boundaries,
        &campaign,
        &scope,
        &profile_ids,
        &component_ids,
    )?;
    let identities = compile_identities(&input.identities, &campaign, &scope, &profile_ids)?;
    let identity_ids = by_name(&identities, |record| (&record.name, &record.id))?;
    let identity_records =
        identities.iter().map(|record| (record.id.clone(), record)).collect::<BTreeMap<_, _>>();
    let properties = compile_properties(&input.properties, &campaign)?;
    let property_ids = by_name(&properties, |record| (&record.id.value, &record.id))?;
    let methods = methods(&campaign);
    let method_ids = by_name(&methods, |record| (&record.name, &record.id))?;
    let routes = validate_routes(&input.routes)?;

    let old_cells = state
        .coverage_cells
        .iter()
        .map(|cell| (cell.id.value.clone(), cell.clone()))
        .collect::<BTreeMap<_, _>>();
    let surface_records =
        surfaces.iter().map(|record| (record.id.clone(), record)).collect::<BTreeMap<_, _>>();
    let property_records =
        properties.iter().map(|record| (record.id.clone(), record)).collect::<BTreeMap<_, _>>();
    let method_records =
        methods.iter().map(|record| (record.id.clone(), record)).collect::<BTreeMap<_, _>>();
    let mut cells = Vec::new();
    for route in &routes {
        let route_state = route_state(&route.state)?;
        for surface_name in &route.surfaces {
            let surface_id = required_name(&surface_ids, surface_name, "surface")?.clone();
            let surface = surface_records.get(&surface_id).expect("compiled surface identity");
            let component =
                component_records.get(&surface.component).expect("compiled component identity");
            if component.profile != surface.profile {
                return Err(invalid(format!(
                    "surface `{surface_name}` and its component belong to different target profiles"
                )));
            }
            for identity_name in &route.identities {
                let identity_id = required_name(&identity_ids, identity_name, "identity")?.clone();
                let identity =
                    identity_records.get(&identity_id).expect("compiled identity configuration");
                if identity.profile != surface.profile {
                    return Err(invalid(format!(
                        "identity `{identity_name}` and surface `{surface_name}` belong to different target profiles"
                    )));
                }
                for property_name in &route.properties {
                    let property_id =
                        required_name(&property_ids, property_name, "property")?.clone();
                    let property =
                        property_records.get(&property_id).expect("compiled property identity");
                    if property.family != route.family {
                        return Err(invalid(format!(
                            "property `{property_name}` belongs to `{}` rather than route `{}`",
                            property.family, route.family
                        )));
                    }
                    for method_name in &route.methods {
                        let method_id = required_name(&method_ids, method_name, "method")?.clone();
                        let method =
                            method_records.get(&method_id).expect("compiled method identity");
                        validate_compatibility(method, surface, property)?;
                        let id = stable_id(
                            RecordKind::CoverageCell,
                            "cell",
                            &[
                                &surface_id.value,
                                &identity_id.value,
                                &property_id.value,
                                &method_id.value,
                            ],
                        )?;
                        let unavailable = method.availability == MethodAvailability::Unsupported;
                        let mut cell = CoverageCellRecord {
                            schema: COVERAGE_SCHEMA_VERSION,
                            id: id.clone(),
                            campaign: campaign.clone(),
                            scope_revision: scope.clone(),
                            profile: surface.profile.clone(),
                            surface: surface_id.clone(),
                            identity_configuration: identity_id.clone(),
                            security_property: property_id.clone(),
                            method: method_id,
                            family: route.family.clone(),
                            state: if unavailable { CoverageState::Blocked } else { route_state },
                            reason: if unavailable {
                                format!(
                                    "Unsupported by the current adapter set: {}",
                                    method.limitation
                                )
                            } else {
                                route.reason.clone()
                            },
                            source_paths: surface.source_paths.clone(),
                            evidence: Vec::new(),
                            invalidated_by: None,
                            supersedes: None,
                        };
                        if let Some(old) = old_cells.get(&id.value)
                            && old.invalidated_by.is_none()
                            && old.source_paths == cell.source_paths
                            && !unavailable
                            && route_state == CoverageState::Unexamined
                        {
                            cell.state = old.state;
                            cell.reason = old.reason.clone();
                            cell.evidence = old.evidence.clone();
                        }
                        cells.push(cell);
                    }
                }
            }
        }
    }
    if cells.is_empty() {
        return Err(invalid("coverage compiler produced no coverage cells"));
    }
    ensure_unique(cells.iter().map(|cell| cell.id.value.as_str()), "coverage cell")?;

    state.target_profiles = profiles;
    state.application_components = components;
    state.application_surfaces = surfaces;
    state.trust_boundaries = boundaries;
    state.identity_configurations = identities;
    state.security_properties = properties;
    state.methods = methods;
    state.coverage_cells = cells;
    rebuild_legacy_coverage(state);
    Ok(InventoryRecord {
        surfaces: input.surfaces.iter().map(|surface| surface.name.clone()).collect(),
        threat_boundaries: input
            .threat_boundaries
            .iter()
            .map(|boundary| boundary.name.clone())
            .collect(),
        routes: routes
            .into_iter()
            .map(|route| FamilyRoute {
                family: route.family,
                state: route_state(&route.state).expect("validated route state"),
                reason: route.reason,
                surfaces: route.surfaces,
                identities: route.identities,
                properties: route.properties,
                methods: route.methods,
            })
            .collect(),
        source_observations: evidence,
        profiles: state.target_profiles.iter().map(|record| record.id.clone()).collect(),
        components: state.application_components.iter().map(|record| record.id.clone()).collect(),
        surface_records: state
            .application_surfaces
            .iter()
            .map(|record| record.id.clone())
            .collect(),
        boundary_records: state.trust_boundaries.iter().map(|record| record.id.clone()).collect(),
        identity_configurations: state
            .identity_configurations
            .iter()
            .map(|record| record.id.clone())
            .collect(),
        security_properties: state
            .security_properties
            .iter()
            .map(|record| record.id.clone())
            .collect(),
        methods: state.methods.iter().map(|record| record.id.clone()).collect(),
        coverage_cells: state.coverage_cells.iter().map(|record| record.id.clone()).collect(),
    })
}

/// Carries an existing graph into a new snapshot and invalidates only path-dependent cells.
pub(crate) fn refresh_scope(
    state: &mut State,
    scope: &RecordId,
    snapshot_digest: &str,
    changed_paths: &[String],
    removed_paths: &[String],
) {
    let changed = changed_paths.iter().chain(removed_paths).collect::<BTreeSet<_>>();
    for record in &mut state.target_profiles {
        record.scope_revision = scope.clone();
    }
    for record in &mut state.application_components {
        record.scope_revision = scope.clone();
    }
    for record in &mut state.trust_boundaries {
        record.scope_revision = scope.clone();
    }
    for record in &mut state.identity_configurations {
        record.scope_revision = scope.clone();
    }
    for surface in &mut state.application_surfaces {
        surface.scope_revision = scope.clone();
        let affected = surface.source_paths.iter().any(|path| path_affected(path, &changed));
        if !affected {
            continue;
        }
        surface.state = if surface.source_paths.iter().all(|path| {
            removed_paths.iter().any(|removed| path_affected(path, &BTreeSet::from([removed])))
        }) {
            SurfaceState::Removed
        } else {
            SurfaceState::NeedsRefresh
        };
        surface.invalidated_by = Some(snapshot_digest.into());
    }
    let unsupported_methods = state
        .methods
        .iter()
        .filter(|method| method.availability == MethodAvailability::Unsupported)
        .map(|method| method.id.clone())
        .collect::<BTreeSet<_>>();
    for cell in &mut state.coverage_cells {
        cell.scope_revision = scope.clone();
        if cell.source_paths.iter().any(|path| path_affected(path, &changed)) {
            if unsupported_methods.contains(&cell.method) {
                cell.reason = "Unsupported by the current adapter set; the source refresh did not add a compatible host method.".into();
                continue;
            }
            cell.state = CoverageState::Unexamined;
            cell.reason = format!(
                "Source dependency changed in snapshot {snapshot_digest}; this exact method must run again."
            );
            cell.evidence.clear();
            cell.invalidated_by = Some(snapshot_digest.into());
        }
    }
    rebuild_legacy_coverage(state);
}

/// Advances only cells backed by one admitted host receipt for the named operation.
pub(crate) fn record_runtime_method(
    state: &mut State,
    operation: &str,
    family: &str,
    entry_point: &str,
    evidence: &RecordId,
) -> usize {
    let method_ids = state
        .methods
        .iter()
        .filter(|method| method.operation.as_deref() == Some(operation))
        .map(|method| method.id.clone())
        .collect::<BTreeSet<_>>();
    let surface_ids = state
        .application_surfaces
        .iter()
        .filter(|surface| {
            surface.state == SurfaceState::Current
                && (surface.entry_point == entry_point || surface.name == entry_point)
        })
        .map(|surface| surface.id.clone())
        .collect::<BTreeSet<_>>();
    let mut count = 0;
    for cell in &mut state.coverage_cells {
        if cell.family == family
            && method_ids.contains(&cell.method)
            && surface_ids.contains(&cell.surface)
        {
            cell.state = CoverageState::Examined;
            cell.reason = format!("Method `{operation}` completed with an admitted host receipt.");
            if !cell.evidence.contains(evidence) {
                cell.evidence.push(evidence.clone());
            }
            cell.invalidated_by = None;
            count += 1;
        }
    }
    rebuild_legacy_coverage(state);
    count
}

pub(crate) fn profiles_view(state: &State) -> String {
    let mut text = format!(
        "# Red Team target profiles\n\nCoverage schema: v{COVERAGE_SCHEMA_VERSION}. Profiles are source-evidenced application shapes, not claims that every interface is testable.\n\n"
    );
    if state.target_profiles.is_empty() {
        text.push_str("No target profile has been compiled. Run the bounded inventory.\n");
    }
    for profile in &state.target_profiles {
        text.push_str(&format!(
            "## `{}` · `{:?}`\n\n- Operating systems: {}\n- Languages: {}\n- Services: {}\n- Stores: {}\n- Interfaces: {}\n- Explicitly unavailable claims: {}\n\n",
            profile.name,
            profile.kind,
            list(&profile.operating_systems),
            list(&profile.languages),
            list(&profile.services),
            list(&profile.stores),
            list(&profile.interfaces),
            list(&profile.unavailable_claims),
        ));
    }
    text
}

pub(crate) fn surfaces_view(state: &State) -> String {
    let mut text = "# Red Team surface graph\n\n".to_owned();
    if state.application_surfaces.is_empty() {
        text.push_str("No surface graph has been compiled.\n");
    }
    for surface in &state.application_surfaces {
        let component = state
            .application_components
            .iter()
            .find(|record| record.id == surface.component)
            .map_or("unknown", |record| record.name.as_str());
        text.push_str(&format!(
            "- `{}` · `{:?}` · `{:?}` — component `{component}`; entry `{}`; paths {}; invalidated by `{}`\n",
            surface.name,
            surface.kind,
            surface.state,
            surface.entry_point,
            list(&surface.source_paths),
            surface.invalidated_by.as_deref().unwrap_or("none"),
        ));
    }
    text.push_str("\n## Trust boundaries\n\n");
    for boundary in &state.trust_boundaries {
        text.push_str(&format!(
            "- `{}` — `{}` → `{}`; assets {}\n",
            boundary.name,
            boundary.from_component.value,
            boundary.to_component.value,
            list(&boundary.protected_assets),
        ));
    }
    text
}

pub(crate) fn methods_view(state: &State) -> String {
    let mut text = "# Red Team method registry\n\nA method is available only through the named host capability/operation. Unsupported methods remain explicit gaps.\n\n".to_owned();
    for method in &state.methods {
        text.push_str(&format!(
            "- `{}` — `{:?}`; operation `{}`; capability `{}` — {}\n",
            method.name,
            method.availability,
            method.operation.as_deref().unwrap_or("none"),
            method.required_capability.as_deref().unwrap_or("none"),
            method.limitation,
        ));
    }
    text
}

pub(crate) fn coverage_view(state: &State) -> String {
    let mut text = "# Red Team coverage cells\n\n`Examined` means only that the exact named method ran for the exact surface, identity/configuration, and property. It is not a secure-project claim.\n\n".to_owned();
    if state.coverage_cells.is_empty() {
        text.push_str("No method-backed cells exist. Run the bounded inventory.\n");
        return text;
    }
    for cell in &state.coverage_cells {
        let surface = state
            .application_surfaces
            .iter()
            .find(|record| record.id == cell.surface)
            .map_or(cell.surface.value.as_str(), |record| record.name.as_str());
        let identity = state
            .identity_configurations
            .iter()
            .find(|record| record.id == cell.identity_configuration)
            .map_or(cell.identity_configuration.value.as_str(), |record| record.name.as_str());
        let property =
            state.security_properties.iter().find(|record| record.id == cell.security_property);
        let method = state
            .methods
            .iter()
            .find(|record| record.id == cell.method)
            .map_or(cell.method.value.as_str(), |record| record.name.as_str());
        text.push_str(&format!(
            "- `{}` · surface `{surface}` · identity `{identity}` · property `{}` · method `{method}` — `{:?}`: {}\n",
            cell.family,
            property.map_or(cell.security_property.value.as_str(), |record| record.statement.as_str()),
            cell.state,
            cell.reason,
        ));
        if let Some(property) = property {
            text.push_str(&format!(
                "  Standards: {}\n",
                property
                    .standards
                    .iter()
                    .map(|reference| format!(
                        "{} {} {}",
                        reference.catalog, reference.version, reference.identifier
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    text
}

fn compile_profiles(
    values: &[ProfileInput],
    campaign: &RecordId,
    scope: &RecordId,
    evidence: &[RecordId],
) -> Result<Vec<TargetProfileRecord>, Error> {
    ensure_unique(values.iter().map(|value| value.name.as_str()), "profile name")?;
    values
        .iter()
        .map(|value| {
            validate_text(&value.name, "profile name")?;
            validate_text_list(&value.operating_systems, "profile operating systems")?;
            validate_text_list(&value.languages, "profile languages")?;
            validate_text_list(&value.interfaces, "profile interfaces")?;
            Ok(TargetProfileRecord {
                schema: COVERAGE_SCHEMA_VERSION,
                id: stable_id(RecordKind::TargetProfile, "profile", &[&value.name])?,
                campaign: campaign.clone(),
                scope_revision: scope.clone(),
                name: value.name.clone(),
                kind: profile_kind(&value.kind)?,
                operating_systems: value.operating_systems.clone(),
                languages: value.languages.clone(),
                services: value.services.clone(),
                stores: value.stores.clone(),
                interfaces: value.interfaces.clone(),
                unavailable_claims: value.unavailable_claims.clone(),
                evidence: evidence.to_vec(),
            })
        })
        .collect()
}

fn compile_components(
    state: &State,
    values: &[ComponentInput],
    campaign: &RecordId,
    scope: &RecordId,
    profiles: &BTreeMap<String, RecordId>,
) -> Result<Vec<ApplicationComponentRecord>, Error> {
    ensure_unique(values.iter().map(|value| value.name.as_str()), "component name")?;
    values
        .iter()
        .map(|value| {
            validate_text(&value.kind, "component kind")?;
            validate_paths(state, &value.source_paths)?;
            Ok(ApplicationComponentRecord {
                schema: COVERAGE_SCHEMA_VERSION,
                id: stable_id(RecordKind::Component, "component", &[&value.name])?,
                campaign: campaign.clone(),
                scope_revision: scope.clone(),
                profile: required_name(profiles, &value.profile, "profile")?.clone(),
                name: value.name.clone(),
                kind: value.kind.clone(),
                source_paths: value.source_paths.clone(),
            })
        })
        .collect()
}

fn compile_surfaces(
    state: &State,
    values: &[SurfaceInput],
    campaign: &RecordId,
    scope: &RecordId,
    profiles: &BTreeMap<String, RecordId>,
    components: &BTreeMap<String, RecordId>,
) -> Result<Vec<ApplicationSurfaceRecord>, Error> {
    ensure_unique(values.iter().map(|value| value.name.as_str()), "surface name")?;
    values
        .iter()
        .map(|value| {
            validate_text(&value.entry_point, "surface entry point")?;
            validate_paths(state, &value.source_paths)?;
            let profile = required_name(profiles, &value.profile, "profile")?.clone();
            let component = required_name(components, &value.component, "component")?.clone();
            Ok(ApplicationSurfaceRecord {
                schema: COVERAGE_SCHEMA_VERSION,
                id: stable_id(RecordKind::Surface, "surface", &[&value.name])?,
                campaign: campaign.clone(),
                scope_revision: scope.clone(),
                profile,
                component,
                name: value.name.clone(),
                kind: surface_kind(&value.kind)?,
                entry_point: value.entry_point.clone(),
                source_paths: value.source_paths.clone(),
                state: SurfaceState::Current,
                invalidated_by: None,
            })
        })
        .collect()
}

fn compile_boundaries(
    values: &[ThreatBoundaryInput],
    campaign: &RecordId,
    scope: &RecordId,
    profiles: &BTreeMap<String, RecordId>,
    components: &BTreeMap<String, RecordId>,
) -> Result<Vec<TrustBoundaryRecord>, Error> {
    ensure_unique(values.iter().map(|value| value.name.as_str()), "trust-boundary name")?;
    values
        .iter()
        .map(|value| {
            validate_text_list(&value.protected_assets, "protected assets")?;
            Ok(TrustBoundaryRecord {
                schema: COVERAGE_SCHEMA_VERSION,
                id: stable_id(RecordKind::TrustBoundary, "boundary", &[&value.name])?,
                campaign: campaign.clone(),
                scope_revision: scope.clone(),
                profile: required_name(profiles, &value.profile, "profile")?.clone(),
                name: value.name.clone(),
                from_component: required_name(components, &value.from_component, "component")?
                    .clone(),
                to_component: required_name(components, &value.to_component, "component")?.clone(),
                protected_assets: value.protected_assets.clone(),
            })
        })
        .collect()
}

fn compile_identities(
    values: &[IdentityInput],
    campaign: &RecordId,
    scope: &RecordId,
    profiles: &BTreeMap<String, RecordId>,
) -> Result<Vec<IdentityConfigurationRecord>, Error> {
    ensure_unique(values.iter().map(|value| value.name.as_str()), "identity name")?;
    values
        .iter()
        .map(|value| {
            validate_text(&value.attacker, "identity attacker")?;
            validate_text_list(&value.configuration, "identity configuration")?;
            Ok(IdentityConfigurationRecord {
                schema: COVERAGE_SCHEMA_VERSION,
                id: stable_id(
                    RecordKind::IdentityConfiguration,
                    "identity",
                    &[
                        &value.name,
                        &value.attacker,
                        &value.privileges.join("\u{1f}"),
                        &value.configuration.join("\u{1f}"),
                    ],
                )?,
                campaign: campaign.clone(),
                scope_revision: scope.clone(),
                profile: required_name(profiles, &value.profile, "profile")?.clone(),
                name: value.name.clone(),
                attacker: value.attacker.clone(),
                privileges: value.privileges.clone(),
                configuration: value.configuration.clone(),
            })
        })
        .collect()
}

fn compile_properties(
    values: &[PropertyInput],
    campaign: &RecordId,
) -> Result<Vec<SecurityPropertyRecord>, Error> {
    ensure_unique(values.iter().map(|value| value.id.as_str()), "property identity")?;
    values
        .iter()
        .map(|value| {
            if !security_families().contains(&value.family.as_str()) {
                return Err(invalid(format!("property `{}` uses an unknown family", value.id)));
            }
            validate_text(&value.statement, "security property")?;
            if value.standards.is_empty() {
                return Err(invalid(format!(
                    "property `{}` needs a versioned ASVS/WSTG/CWE mapping or PERITUS custom identifier",
                    value.id
                )));
            }
            for reference in &value.standards {
                validate_standard(reference)?;
            }
            Ok(SecurityPropertyRecord {
                schema: COVERAGE_SCHEMA_VERSION,
                id: RecordId::new(RecordKind::SecurityProperty, value.id.clone()).map_err(invalid)?,
                campaign: campaign.clone(),
                family: value.family.clone(),
                statement: value.statement.clone(),
                standards: value.standards.clone(),
            })
        })
        .collect()
}

fn methods(campaign: &RecordId) -> Vec<MethodRecord> {
    [
        (
            SOURCE_REVIEW_METHOD,
            MethodAvailability::Available,
            None,
            Some("module.scoped-source@1"),
            "Examines only explicitly retained source ranges; it does not establish runtime behavior.",
        ),
        (
            STATIC_ANALYSIS_METHOD,
            MethodAvailability::Available,
            Some("source.scan.v1"),
            Some("module.adapter-runtime@1"),
            "Deterministic language, pattern, bounded same-file flow, dependency, secret and configuration analysis over an immutable snapshot; emits source leads only.",
        ),
        (
            HTTP_API_METHOD,
            MethodAvailability::Available,
            Some("http.campaign.v1"),
            Some("module.adapter-runtime@1"),
            "Host-captured HTTP/1.1, live OpenAPI, GraphQL, WebSocket and JSON-RPC campaign against an exact ready disposable laboratory; authentication and browser trust remain separate phases.",
        ),
        (
            BROWSER_METHOD,
            MethodAvailability::Available,
            Some("browser.campaign.v1"),
            Some("module.adapter-runtime@1"),
            "Isolated real Chromium campaign with DOM/script, navigation, origin, cookie, CSP, CSRF, validation, crawl, upload/download, reset and retained evidence; other engines and application-specific workflows remain explicit gaps.",
        ),
        (
            IDENTITY_METHOD,
            MethodAvailability::Available,
            Some("identity.campaign.v1"),
            Some("module.adapter-runtime@1"),
            "Host-private laboratory credentials drive login, MFA, recovery, token lifecycle, ownership, role, adjacent-route, and tenant differential oracles; federated identity and application-specific permissions remain explicit gaps.",
        ),
        (
            FILE_FUZZ_METHOD,
            MethodAvailability::Available,
            Some("file-fuzz.campaign.v1"),
            Some("module.adapter-runtime@1"),
            "Host-owned path, link, temporary-file, permission, TAR, structured-parser, deterministic fuzz, minimization, resource, and Linux native-child fault campaign; arbitrary grammars and compiler sanitizers require separately registered target profiles.",
        ),
        (
            WORKFLOW_STATE_METHOD,
            MethodAvailability::Available,
            Some("workflow-state.campaign.v1"),
            Some("module.adapter-runtime@1"),
            "Host-owned documented/proposed invariant separation, ordered real actions, copied-state observations, retries, cancellation, crash recovery, quota/accounting oracles, and one deterministic concurrency schedule; application-specific contracts and distributed systems require separate profiles.",
        ),
        (
            BOUNDARY_AUTHORITY_METHOD,
            MethodAvailability::Available,
            Some("boundary-authority.campaign.v1"),
            Some("module.adapter-runtime@1"),
            "Host-owned Unix-socket DNS/HTTP/TLS peers, lab-only certificates, deny-all IP networking, contained privilege probes, policy checks, and copied-application authority cases; live cloud/provider and host-privileged checks remain blocked without a purpose-built emulator.",
        ),
        (
            ATTACK_GRAPH_METHOD,
            MethodAvailability::Available,
            Some("attack-graph.campaign.v1"),
            Some("module.adapter-runtime@1"),
            "Host-composed receipt-backed chain search across exact source, private HTTP, and isolated Chromium with counterfactual prerequisite removal, unsupported-edge rejection, root-cause grouping, exact copy-only diff, and adapter-specific repair replays; other adapter combinations require registered graph profiles.",
        ),
        (
            CANARY_METHOD,
            MethodAvailability::Available,
            Some("linux.canary-disclosure.v1"),
            Some("module.owned-jobs@1"),
            "Linux command-line/native targets only; proves one exact hidden-canary disclosure case.",
        ),
        (
            UNSUPPORTED_METHOD,
            MethodAvailability::Unsupported,
            None,
            None,
            "No compatible class-specific runtime adapter exists in Phase 9.",
        ),
    ]
    .into_iter()
    .map(|(name, availability, operation, capability, limitation)| MethodRecord {
        schema: COVERAGE_SCHEMA_VERSION,
        id: stable_id(RecordKind::Method, "method", &[name]).expect("static method identity"),
        campaign: campaign.clone(),
        name: name.into(),
        availability,
        operation: operation.map(str::to_owned),
        required_capability: capability.map(str::to_owned),
        limitation: limitation.into(),
    })
    .collect()
}

fn validate_routes(values: &[RouteInput]) -> Result<Vec<RouteInput>, Error> {
    if values.len() != security_families().len() {
        return Err(invalid("inventory must route every supported security family exactly once"));
    }
    let expected = security_families().into_iter().collect::<BTreeSet<_>>();
    let actual = values.iter().map(|route| route.family.as_str()).collect::<BTreeSet<_>>();
    if actual != expected || actual.len() != values.len() {
        return Err(invalid("inventory family routes are missing, duplicated, or unknown"));
    }
    for route in values {
        if route.state == "examined" {
            return Err(invalid(
                "inventory prose cannot mark coverage examined; only an admitted method receipt can do that",
            ));
        }
        let _ = route_state(&route.state)?;
        validate_text(&route.reason, "coverage route reason")?;
        validate_text_list(&route.surfaces, "coverage route surfaces")?;
        validate_text_list(&route.identities, "coverage route identities")?;
        validate_text_list(&route.properties, "coverage route properties")?;
        validate_text_list(&route.methods, "coverage route methods")?;
    }
    Ok(values.to_vec())
}

fn validate_standard(value: &StandardReference) -> Result<(), Error> {
    let valid = match (value.catalog.as_str(), value.version.as_str()) {
        ("ASVS", "5.0.0") => {
            let parts = value.identifier.strip_prefix('V').map(|value| value.split('.'));
            parts.is_some_and(|mut parts| {
                parts.clone().count() == 3
                    && parts.all(|part| {
                        !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit())
                    })
            })
        }
        ("WSTG", "4.2") => value.identifier.strip_prefix("WSTG-v42-").is_some_and(|suffix| {
            !suffix.is_empty()
                && value.identifier.len() <= 64
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
        }),
        ("CWE", "4.18") => value.identifier.strip_prefix("CWE-").is_some_and(|number| {
            !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
        }),
        ("PERITUS", "1") => value.identifier.strip_prefix("peritus:").is_some_and(|id| {
            !id.is_empty()
                && id.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_' | b'.')
                })
        }),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(invalid(format!(
            "unsupported or malformed standards mapping `{}` `{}` `{}`",
            value.catalog, value.version, value.identifier
        )))
    }
}

fn validate_compatibility(
    method: &MethodRecord,
    surface: &ApplicationSurfaceRecord,
    property: &SecurityPropertyRecord,
) -> Result<(), Error> {
    if method.name != CANARY_METHOD {
        return Ok(());
    }
    if !matches!(surface.kind, SurfaceKind::CommandLine | SurfaceKind::Native) {
        return Err(invalid(format!(
            "method `{CANARY_METHOD}` cannot be assigned to non-command surface `{}`",
            surface.name
        )));
    }
    let disclosure = property.standards.iter().any(|reference| {
        (reference.catalog == "ASVS"
            && reference.version == "5.0.0"
            && reference.identifier == "V14.2.6")
            || (reference.catalog == "CWE"
                && reference.version == "4.18"
                && reference.identifier == "CWE-200")
    });
    if !disclosure {
        return Err(invalid(format!(
            "method `{CANARY_METHOD}` is only compatible with an ASVS 5.0.0 V14.2.6 or CWE 4.18 CWE-200 disclosure property"
        )));
    }
    Ok(())
}

fn rebuild_legacy_coverage(state: &mut State) {
    let scope = state.scopes.last().map(|scope| scope.id.clone());
    let Some(scope) = scope else { return };
    state.coverage = security_families()
        .into_iter()
        .map(|family| {
            let cells = state
                .coverage_cells
                .iter()
                .filter(|cell| cell.family == family)
                .collect::<Vec<_>>();
            let state_value = if cells.is_empty()
                || cells.iter().any(|cell| cell.state == CoverageState::Unexamined)
            {
                CoverageState::Unexamined
            } else if cells.iter().any(|cell| cell.state == CoverageState::Blocked) {
                CoverageState::Blocked
            } else if cells.iter().any(|cell| cell.state == CoverageState::Examined) {
                CoverageState::Examined
            } else {
                CoverageState::NotApplicable
            };
            let evidence = cells
                .iter()
                .flat_map(|cell| cell.evidence.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            CoverageRecord {
                schema: RECORD_SCHEMA_VERSION,
                id: stable_id(RecordKind::Coverage, "coverage", &[family])
                    .expect("static family identity"),
                campaign: state.campaign.id.clone(),
                scope_revision: scope.clone(),
                family: family.into(),
                surface: format!("{} compiled cells", cells.len()),
                state: state_value,
                reason: if cells.is_empty() {
                    "No coverage cell was compiled for this family.".into()
                } else {
                    format!(
                        "{} examined, {} unexamined, {} blocked, {} not applicable.",
                        cells.iter().filter(|cell| cell.state == CoverageState::Examined).count(),
                        cells.iter().filter(|cell| cell.state == CoverageState::Unexamined).count(),
                        cells.iter().filter(|cell| cell.state == CoverageState::Blocked).count(),
                        cells
                            .iter()
                            .filter(|cell| cell.state == CoverageState::NotApplicable)
                            .count(),
                    )
                },
                evidence,
                supersedes: None,
            }
        })
        .collect();
}

fn validate_paths(state: &State, values: &[String]) -> Result<(), Error> {
    validate_text_list(values, "source paths")?;
    for path in values {
        let prefix = format!("{}/", path.trim_end_matches('/'));
        if !state
            .investigation
            .manifest_entries
            .iter()
            .any(|entry| entry.path == *path || entry.path.starts_with(&prefix))
        {
            return Err(invalid(format!("source path `{path}` is outside the captured manifest")));
        }
    }
    Ok(())
}

fn path_affected(path: &str, changed: &BTreeSet<&String>) -> bool {
    changed.iter().any(|candidate| {
        path == candidate.as_str()
            || path.starts_with(&format!("{candidate}/"))
            || candidate.starts_with(&format!("{path}/"))
    })
}

fn stable_id(kind: RecordKind, prefix: &str, parts: &[&str]) -> Result<RecordId, Error> {
    let bytes = parts.join("\u{1f}");
    RecordId::new(kind, format!("{prefix}-{}", &digest(bytes.as_bytes())[..24])).map_err(invalid)
}

fn by_name<T>(
    values: &[T],
    field: impl Fn(&T) -> (&String, &RecordId),
) -> Result<BTreeMap<String, RecordId>, Error> {
    let mut result = BTreeMap::new();
    for value in values {
        let (name, id) = field(value);
        if result.insert(name.clone(), id.clone()).is_some() {
            return Err(invalid(format!("duplicate compiled name `{name}`")));
        }
    }
    Ok(result)
}

fn required_name<'a>(
    values: &'a BTreeMap<String, RecordId>,
    name: &str,
    kind: &str,
) -> Result<&'a RecordId, Error> {
    values.get(name).ok_or_else(|| invalid(format!("unknown {kind} `{name}`")))
}

fn ensure_unique<'a>(values: impl Iterator<Item = &'a str>, label: &str) -> Result<(), Error> {
    let mut seen = BTreeSet::new();
    for value in values {
        validate_text(value, label)?;
        if !seen.insert(value) {
            return Err(invalid(format!("duplicate {label} `{value}`")));
        }
    }
    Ok(())
}

fn validate_count<T>(
    values: &[T],
    minimum: usize,
    maximum: usize,
    label: &str,
) -> Result<(), Error> {
    if !(minimum..=maximum).contains(&values.len()) {
        return Err(invalid(format!("{label} must contain {minimum}..={maximum} entries")));
    }
    Ok(())
}

fn validate_text(value: &str, label: &str) -> Result<(), Error> {
    if value.trim().is_empty() || value.len() > 4096 || value.contains('\0') {
        Err(invalid(format!("{label} must contain bounded nonempty text")))
    } else {
        Ok(())
    }
}

fn validate_text_list(values: &[String], label: &str) -> Result<(), Error> {
    if values.is_empty() {
        return Err(invalid(format!("{label} must not be empty")));
    }
    for value in values {
        validate_text(value, label)?;
    }
    ensure_unique(values.iter().map(String::as_str), label)
}

fn route_state(value: &str) -> Result<CoverageState, Error> {
    match value {
        "unexamined" => Ok(CoverageState::Unexamined),
        "not_applicable" => Ok(CoverageState::NotApplicable),
        "blocked" => Ok(CoverageState::Blocked),
        "examined" => Err(invalid(
            "inventory prose cannot mark coverage examined; only an admitted method receipt can do that",
        )),
        _ => Err(invalid("unknown coverage route state")),
    }
}

fn profile_kind(value: &str) -> Result<TargetProfileKind, Error> {
    match value {
        "command_line" => Ok(TargetProfileKind::CommandLine),
        "native_application" => Ok(TargetProfileKind::NativeApplication),
        "web_application" => Ok(TargetProfileKind::WebApplication),
        "api_service" => Ok(TargetProfileKind::ApiService),
        "browser_client" => Ok(TargetProfileKind::BrowserClient),
        "multi_service" => Ok(TargetProfileKind::MultiService),
        "other" => Ok(TargetProfileKind::Other),
        _ => Err(invalid("unknown target profile kind")),
    }
}

fn surface_kind(value: &str) -> Result<SurfaceKind, Error> {
    match value {
        "command_line" => Ok(SurfaceKind::CommandLine),
        "native" => Ok(SurfaceKind::Native),
        "web" => Ok(SurfaceKind::Web),
        "api" => Ok(SurfaceKind::Api),
        "browser" => Ok(SurfaceKind::Browser),
        "service" => Ok(SurfaceKind::Service),
        "file" => Ok(SurfaceKind::File),
        "library" => Ok(SurfaceKind::Library),
        "other" => Ok(SurfaceKind::Other),
        _ => Err(invalid("unknown surface kind")),
    }
}

fn list(values: &[String]) -> String {
    if values.is_empty() { "none".into() } else { values.join(", ") }
}
