//! Stage 2-7 capability, graph, replay, repair, disclosure, and provenance views.

use crate::state::State;
use peritus_plugin_sdk::MODULE_RESEARCH_CONTRACT_VERSION;
use std::fmt::Write as _;

pub(crate) fn status_view(state: &State) -> String {
    format!(
        "# Autonomous exploit research contracts\n\n- Contract: v{contract}\n- Durable state: schema v{schema}, phase {phase}\n- Stage 4 campaign phase: `{autonomy_phase:?}`\n- Stage 4 turns / experiments / cost: {turns}/{maximum_turns} / {started}/{maximum_experiments} / {cost}/{maximum_cost}\n- Selected inert emulation recipes: {recipe_seeds}\n- Experiments: {experiments}\n- Capability records: {capabilities}\n- Projected / experimentally admitted primitives: {projected} / {admitted}\n- Rejected candidates: {rejected}\n- Graph-v2 records: {graphs}\n- Owner-only artifact records: {artifacts}\n- Safe PoC bundles: {pocs}\n- Copy-only repair bundles: {repairs}\n- Disclosure packages: {disclosures}\n- Research-record digest: `{digest}`\n- Existing graph-v1 campaigns: {graph_v1}\n\n## Capability availability\n\n- Deterministic capability projection from seven existing adapters: **available**\n- Read-only primitive and provenance inspection: **available**\n- Inert licensed emulation-recipe inspection and explicit hypothesis seeding: **available**\n- Bounded deterministic graph-v2 search and counterfactuals: **available**\n- Unresolved experiment specifications: **available**\n- Bounded model-role scheduling and registered private-laboratory experiments: **available**\n- Pause, resume, cancellation, steering, provider-failure recovery, and exact frontier inspection: **available**\n- Fresh full-chain replay and confirmation: **available**\n- Safe private standalone PoC generation: **available**\n- Exact-preimage copy-only repair and adversarial regression: **available**\n- Private responsible-disclosure package generation, review, and local export: **available**\n- Disclosure delivery: **unavailable**\n\nSelected recipes remain public-knowledge hypotheses with their original evidence class; they create no finding until the selected target independently produces exact admitted receipts. Stage 4 may schedule one host-owned registered adapter operation at a time against the selected private disposable laboratory. Stage 5 accepts only a fully supported candidate, replays it from fresh target state with counterfactual and safe-twin controls, applies the independent skeptic, and verifies an owner-only standalone PoC. Stage 6 creates only a fresh patched twin, replays the exact PoC and chain, exercises a finite mutation matrix, independently reviews the exact diff, and requires a host re-read of the original workspace. Stage 7 deterministically renders, redacts, reviews, and locally exports an owner-only private disclosure package from verified Stage 6 evidence; its only host operations are bounded scoped-source manifest and read requests for SECURITY.md contact provenance. Rust—not the model—validates target, authority, operation, identity, literal private destination, receipts, cleanup, package bytes, and finite bounds. These stages cannot modify the original source, use ambient credentials or personal browser state, reach the public network, or deliver a disclosure.",
        contract = MODULE_RESEARCH_CONTRACT_VERSION,
        schema = state.schema,
        phase = state.phase,
        autonomy_phase = state.research_autonomy.phase,
        turns = state.research_autonomy.turn,
        maximum_turns = state.research_autonomy.budgets.maximum_model_turns,
        started = state.research_autonomy.experiments_started,
        maximum_experiments = state.research_autonomy.budgets.maximum_experiments,
        cost = state.research_autonomy.cost_spent,
        maximum_cost = state.research_autonomy.budgets.maximum_cost,
        recipe_seeds = state.research_autonomy.recipe_seeds.len(),
        experiments = state.research_experiments.len(),
        capabilities = state.research_capabilities.len(),
        projected = state
            .research_capabilities
            .iter()
            .filter(|record| {
                record.disposition
                    == peritus_plugin_sdk::ModuleResearchCapabilityDisposition::Projected
            })
            .count(),
        admitted = state
            .research_capabilities
            .iter()
            .filter(|record| {
                record.disposition
                    == peritus_plugin_sdk::ModuleResearchCapabilityDisposition::Admitted
            })
            .count(),
        rejected = state
            .research_capabilities
            .iter()
            .filter(|record| {
                record.disposition
                    == peritus_plugin_sdk::ModuleResearchCapabilityDisposition::Rejected
            })
            .count(),
        graphs = state.research_graphs.len(),
        artifacts = state.research_artifacts.len(),
        pocs = state.research_poc_bundles.len(),
        repairs = state.research_repair_bundles.len(),
        disclosures = state.research_disclosure_packages.len(),
        digest = state.research_records_digest,
        graph_v1 = state.attack_graph_observations.len(),
    )
}

pub(crate) fn history_view(state: &State) -> String {
    let mut text = String::from(
        "# Autonomous exploit research history\n\nThis is a read-only projection of immutable v2 records. Existing graph-v1 history remains available through `graph-history`.\n\n",
    );
    if state.research_experiments.is_empty()
        && state.research_capabilities.is_empty()
        && state.research_graphs.is_empty()
        && state.research_artifacts.is_empty()
        && state.research_poc_bundles.is_empty()
        && state.research_repair_bundles.is_empty()
        && state.research_disclosure_packages.is_empty()
    {
        text.push_str(
            "No v2 research records exist. Project retained adapter evidence and build graph-v2 before starting Stage 4. No chain replay, PoC, patch, export, or disclosure has run.\n",
        );
        return text;
    }

    for experiment in &state.research_experiments {
        let _ = writeln!(
            text,
            "- Experiment `{}` — `{:?}` — request `{}` — receipts {} — artifacts {}",
            experiment.id,
            experiment.phase,
            experiment.request.digest,
            experiment.receipts.len(),
            experiment.artifacts.len()
        );
    }
    for capability in &state.research_capabilities {
        let _ = writeln!(
            text,
            "- Capability `{}` — `{:?}` — `{:?}` — adapter `{}` / `{}` — projection `{}` — boundary `{:?}` — receipts {} — rejection `{:?}`",
            capability.id,
            capability.capability,
            capability.disposition,
            capability.adapter_id,
            capability.adapter_version,
            capability.projection_version,
            capability.evidence_boundary,
            capability.receipts.len(),
            capability.rejection_reason,
        );
    }
    for graph in &state.research_graphs {
        let _ = writeln!(
            text,
            "- Graph-v2 `{}` — nodes {} — edges {} — chains {} — experiment specifications {} — excluded prerequisites {} — truncated {}",
            graph.id,
            graph.nodes.len(),
            graph.edges.len(),
            graph.chains.len(),
            graph.experiments.len(),
            graph.excluded_capabilities.len(),
            graph.summary.truncated,
        );
    }
    for artifact in &state.research_artifacts {
        let _ = writeln!(
            text,
            "- Artifact `{}` — `{:?}` — {} bytes — owner-only `{}`",
            artifact.identity.digest, artifact.classification, artifact.bytes, artifact.owner_only
        );
    }
    for bundle in &state.research_poc_bundles {
        let _ = writeln!(
            text,
            "- PoC `{}` — `{:?}` — chain `{}` — artifacts {}",
            bundle.id,
            bundle.state,
            bundle.chain_id,
            bundle.artifacts.len()
        );
    }
    for bundle in &state.research_repair_bundles {
        let _ = writeln!(
            text,
            "- Repair `{}` — `{:?}` — PoC `{}` — chain `{}` — artifacts {}",
            bundle.id,
            bundle.state,
            bundle.poc_bundle_id,
            bundle.chain_id,
            bundle.artifacts.len()
        );
    }
    for package in &state.research_disclosure_packages {
        let _ = writeln!(
            text,
            "- Disclosure `{}` — `{:?}` — chain `{}` — timeline entries {} — artifacts {}",
            package.id,
            package.state,
            package.chain_id,
            package.timeline.len(),
            package.artifacts.len()
        );
    }
    text
}

pub(crate) fn capability_view(state: &State) -> String {
    let mut text = String::from(
        "# Receipt-backed capability primitives\n\nOnly projected or experimentally admitted records appear here. Rejections remain available through `capability-history`.\n\n",
    );
    let mut count = 0_usize;
    for record in &state.research_capabilities {
        if !matches!(
            record.disposition,
            peritus_plugin_sdk::ModuleResearchCapabilityDisposition::Projected
                | peritus_plugin_sdk::ModuleResearchCapabilityDisposition::Admitted
        ) {
            continue;
        }
        count = count.saturating_add(1);
        let _ = writeln!(
            text,
            "- `{}` — `{:?}` / `{:?}` — target `{}` — subject `{}` — authority `{}` -> `{}` — adapter `{}` / `{}` — receipts {}",
            record.id,
            record.capability,
            record.evidence_boundary,
            record.target.digest,
            record.subject.digest,
            record.authority_before.digest,
            record.authority_after.digest,
            record.adapter_id,
            record.adapter_version,
            record.receipts.len(),
        );
    }
    if count == 0 {
        text.push_str("No receipt-backed primitives are currently admitted.\n");
    }
    text
}

pub(crate) fn capability_history_view(state: &State) -> String {
    let mut text = String::from(
        "# Capability projection provenance\n\nEvery record is content-bound to its target, subject, authority, adapter version, projection version, oracle, and source receipt. Rejected candidates are not primitives.\n\n",
    );
    if state.research_capabilities.is_empty() {
        text.push_str("No capability projection records exist.\n");
        return text;
    }
    for record in &state.research_capabilities {
        let _ = writeln!(
            text,
            "- `{}` — `{:?}` — disposition `{:?}` — source `{}` — adapter `{}` / `{}` — projection `{}` — consumes {} / produces {} — receipts {} — rejection `{:?}` — {}",
            record.id,
            record.capability,
            record.disposition,
            record.source_record,
            record.adapter_id,
            record.adapter_version,
            record.projection_version,
            record.consumes.len(),
            record.produces.len(),
            record.receipts.len(),
            record.rejection_reason,
            record.detail,
        );
    }
    text
}

pub(crate) fn graph_view(state: &State) -> String {
    let Some(graph) = active_graph(state) else {
        return "# Deterministic graph-v2\n\nNo graph-v2 record exists. Run `graph-v2-build` after admitting capability primitives.\n".into();
    };
    let mut text = format!(
        "# Deterministic graph-v2\n\n- Graph: `{}`\n- Builder: `{}`\n- Target: `{}`\n- Nodes / edges / chains: {} / {} / {}\n- Candidate / broken chains: {} / {}\n- Rejected edges: {}\n- Unscheduled experiment specifications: {}\n- Excluded prerequisites: {}\n- Pairs considered / candidates expanded / cycles rejected: {} / {} / {}\n- Search truncated: {}\n- Bounds: nodes {}, edges {}, depth {}, open {}, cycles {}, cost {}\n\nCandidate chains below are compatibility-search results, not confirmed exploit chains.\n\n## Chains\n\n",
        graph.id,
        graph.builder.value,
        graph.target.digest,
        graph.nodes.len(),
        graph.edges.len(),
        graph.chains.len(),
        graph
            .chains
            .iter()
            .filter(|chain| chain.disposition
                == peritus_plugin_sdk::ModuleResearchChainDisposition::Candidate)
            .count(),
        graph
            .chains
            .iter()
            .filter(|chain| chain.disposition
                == peritus_plugin_sdk::ModuleResearchChainDisposition::Broken)
            .count(),
        graph
            .edges
            .iter()
            .filter(|edge| edge.disposition
                == peritus_plugin_sdk::ModuleResearchGraphEdgeDisposition::Rejected)
            .count(),
        graph.experiments.len(),
        graph.excluded_capabilities.len(),
        graph.summary.pairs_considered,
        graph.summary.candidates_expanded,
        graph.summary.cycles_rejected,
        graph.summary.truncated,
        graph.bounds.maximum_nodes,
        graph.bounds.maximum_edges,
        graph.bounds.maximum_depth,
        graph.bounds.maximum_open_candidates,
        graph.bounds.maximum_cycles,
        graph.bounds.maximum_cost,
    );
    if graph.chains.is_empty() {
        text.push_str("No bounded multi-primitive impact candidate was found.\n");
    }
    for chain in &graph.chains {
        let _ = writeln!(
            text,
            "- `{}` — `{:?}` — goal `{:?}` — {} capability nodes / {} adapters — cost {} — unresolved experiments {} — replay `{}`",
            chain.id,
            chain.disposition,
            chain.goal,
            chain.nodes.len(),
            chain.adapter_families.len(),
            chain.cost,
            chain.missing_experiments.len(),
            chain.replay.as_ref().map_or("none", |value| value.digest.as_str()),
        );
    }
    text.push_str("\n## Explicit gaps\n\n");
    for gap in &graph.gaps {
        let _ = writeln!(text, "- {gap}");
    }
    text
}

pub(crate) fn graph_history_view(state: &State) -> String {
    let mut text = String::from(
        "# Graph-v2 history\n\nRecords are immutable bounded search projections. Existing graph-v1 history remains available through `graph-history`.\n\n",
    );
    if state.research_graphs.is_empty() {
        text.push_str("No graph-v2 records exist.\n");
    }
    for graph in state.research_graphs.iter().rev() {
        let _ = writeln!(
            text,
            "- `{}`{} — target `{}` — nodes {} / edges {} / chains {} / experiments {} — excluded {} — truncated {}",
            graph.id,
            if state.research_active_graph.as_deref() == Some(graph.id.as_str()) {
                " (selected)"
            } else {
                ""
            },
            graph.target.digest,
            graph.nodes.len(),
            graph.edges.len(),
            graph.chains.len(),
            graph.experiments.len(),
            graph.excluded_capabilities.len(),
            graph.summary.truncated,
        );
    }
    text
}

pub(crate) fn graph_experiment_view(state: &State) -> String {
    let Some(graph) = active_graph(state) else {
        return "# Unresolved graph-v2 experiments\n\nNo graph-v2 record exists.\n".into();
    };
    let mut text = String::from(
        "# Unresolved graph-v2 experiments\n\nThese immutable bounded specifications may be selected by Stage 4. Their presence is not evidence that an experiment ran; observed experiments and receipts appear in `research-history`.\n\n",
    );
    if graph.experiments.is_empty() {
        text.push_str("No unresolved legal relation requires an experiment in this graph.\n");
    }
    for experiment in &graph.experiments {
        let _ = writeln!(
            text,
            "- `{}` — `{}` -> `{}` — relation `{}` — adapter operation `{}` — goal `{:?}` — maximum operations {} — {}",
            experiment.id,
            experiment.from_capability,
            experiment.to_capability,
            experiment.relation.value,
            experiment.adapter_operation,
            experiment.required_capability,
            experiment.maximum_operations,
            experiment.detail,
        );
    }
    text
}

fn active_graph(state: &State) -> Option<&peritus_plugin_sdk::ModuleResearchGraphRecord> {
    crate::capability_graph::current_graph(state)
}
