//! Deterministic Stage 3 graph-v2 construction and bounded capability-chain search.

use crate::{Error, digest, invalid, state::State};
use peritus_plugin_sdk::{
    MODULE_RESEARCH_CONTRACT_VERSION, ModuleResearchCapabilityDisposition,
    ModuleResearchCapabilityFact, ModuleResearchCapabilityFactKind, ModuleResearchCapabilityKind,
    ModuleResearchCapabilityRecord, ModuleResearchChainDisposition, ModuleResearchChainRecord,
    ModuleResearchEvidenceBoundary, ModuleResearchExperimentPhase,
    ModuleResearchExperimentSpecification, ModuleResearchGraphEdgeDisposition,
    ModuleResearchGraphEdgeRecord, ModuleResearchGraphNodeKind, ModuleResearchGraphNodeRecord,
    ModuleResearchGraphRecord, ModuleResearchGraphRejection, ModuleResearchIdentity,
    ModuleResearchIdentityKind, ModuleResearchSearchBounds, ModuleResearchSearchSummary,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const BUILDER_VERSION: &str = "peritus-capability-graph@2";
const SOURCE_RUNTIME_RELATION: &str = "source-corroborates-runtime-input-interpretation@1";
const RUNTIME_BROWSER_RELATION: &str = "runtime-input-to-browser-script-candidate@1";
const INTERNAL_CONSUMES_RELATION: &str = "capability-consumes-fact@1";
const INTERNAL_PRODUCES_RELATION: &str = "capability-produces-fact@1";
const INTERNAL_IMPACT_RELATION: &str = "capability-demonstrates-impact@1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BuildSummary {
    pub(crate) graph_id: String,
    pub(crate) nodes: usize,
    pub(crate) edges: usize,
    pub(crate) candidates: usize,
    pub(crate) broken: usize,
    pub(crate) rejected_edges: usize,
    pub(crate) experiments: usize,
    pub(crate) truncated: bool,
    pub(crate) reused: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JoinKind {
    SourceRuntime,
    RuntimeBrowser,
}

#[derive(Clone, Debug)]
struct Join {
    from_capability: String,
    to_capability: String,
    edge_id: String,
    disposition: ModuleResearchGraphEdgeDisposition,
    experiment_id: Option<String>,
}

#[derive(Clone, Debug)]
struct PathState {
    capabilities: Vec<String>,
    edges: Vec<String>,
    missing_experiments: BTreeSet<String>,
    cost: u32,
    cycles: u16,
}

#[derive(Serialize)]
struct GraphIdentityMaterial<'a> {
    builder: &'a ModuleResearchIdentity,
    target: &'a ModuleResearchIdentity,
    bounds: ModuleResearchSearchBounds,
    excluded_capabilities: &'a [String],
    nodes: &'a [ModuleResearchGraphNodeRecord],
    edges: &'a [ModuleResearchGraphEdgeRecord],
    chains: &'a [ModuleResearchChainRecord],
    experiments: &'a [ModuleResearchExperimentSpecification],
    summary: ModuleResearchSearchSummary,
    gaps: &'a [String],
}

pub(crate) const fn default_bounds() -> ModuleResearchSearchBounds {
    ModuleResearchSearchBounds {
        maximum_nodes: 256,
        maximum_edges: 512,
        maximum_depth: 6,
        maximum_open_candidates: 128,
        maximum_cycles: 0,
        maximum_cost: 12,
    }
}

pub(crate) fn current_graph(
    state: &State,
) -> Option<&peritus_plugin_sdk::ModuleResearchGraphRecord> {
    let target = format!("source:{}", state.active_snapshot()?.snapshot_digest);
    state
        .research_active_graph
        .as_ref()
        .and_then(|id| state.research_graphs.iter().find(|graph| graph.id == *id))
        .filter(|graph| graph.target.value == target)
        .or_else(|| state.research_graphs.iter().rev().find(|graph| graph.target.value == target))
}

pub(crate) fn parse_bounds(input: &str) -> Result<ModuleResearchSearchBounds, Error> {
    let mut bounds = default_bounds();
    for item in input.split_whitespace() {
        let (name, raw) = item
            .split_once('=')
            .ok_or_else(|| invalid(format!("graph-v2 bound `{item}` must use name=value")))?;
        match name {
            "nodes" => bounds.maximum_nodes = parse_u32(name, raw)?,
            "edges" => bounds.maximum_edges = parse_u32(name, raw)?,
            "depth" => bounds.maximum_depth = parse_u16(name, raw)?,
            "open" => bounds.maximum_open_candidates = parse_u32(name, raw)?,
            "cycles" => bounds.maximum_cycles = parse_u16(name, raw)?,
            "cost" => bounds.maximum_cost = parse_u32(name, raw)?,
            _ => {
                return Err(invalid(format!(
                    "unknown graph-v2 bound `{name}`; use nodes, edges, depth, open, cycles, or cost"
                )));
            }
        }
    }
    validate_bounds(bounds)?;
    Ok(bounds)
}

fn parse_u32(name: &str, raw: &str) -> Result<u32, Error> {
    raw.parse::<u32>()
        .map_err(|_| invalid(format!("graph-v2 bound `{name}` is not an unsigned integer")))
}

fn parse_u16(name: &str, raw: &str) -> Result<u16, Error> {
    raw.parse::<u16>()
        .map_err(|_| invalid(format!("graph-v2 bound `{name}` is not an unsigned integer")))
}

fn validate_bounds(bounds: ModuleResearchSearchBounds) -> Result<(), Error> {
    if !(8..=4096).contains(&bounds.maximum_nodes)
        || !(8..=16384).contains(&bounds.maximum_edges)
        || !(2..=16).contains(&bounds.maximum_depth)
        || !(1..=4096).contains(&bounds.maximum_open_candidates)
        || bounds.maximum_cycles > 4
        || !(2..=64).contains(&bounds.maximum_cost)
    {
        return Err(invalid(
            "graph-v2 bounds must satisfy nodes 8..4096, edges 8..16384, depth 2..16, open 1..4096, cycles 0..4, and cost 2..64",
        ));
    }
    Ok(())
}

pub(crate) fn build(
    state: &mut State,
    bounds: ModuleResearchSearchBounds,
    excluded_capabilities: BTreeSet<String>,
) -> Result<BuildSummary, Error> {
    validate_bounds(bounds)?;
    let snapshot = state
        .active_snapshot()
        .ok_or_else(|| invalid("select an immutable source before building graph-v2"))?;
    let target = identity(
        ModuleResearchIdentityKind::Target,
        &format!("source:{}", snapshot.snapshot_digest),
    );
    let builder = identity(ModuleResearchIdentityKind::RoleImplementation, BUILDER_VERSION);
    let mut capabilities = state
        .research_capabilities
        .iter()
        .filter(|record| {
            matches!(
                record.disposition,
                ModuleResearchCapabilityDisposition::Projected
                    | ModuleResearchCapabilityDisposition::Admitted
            ) && record.evidence_boundary != ModuleResearchEvidenceBoundary::Untrusted
                && record.capability != ModuleResearchCapabilityKind::Unsupported
                && !record.receipts.is_empty()
                && record.consumes.iter().any(|fact| {
                    fact.kind
                        == peritus_plugin_sdk::ModuleResearchCapabilityFactKind::SourceSnapshot
                        && fact.value == snapshot.snapshot_digest
                })
        })
        .cloned()
        .collect::<Vec<_>>();
    capabilities.sort_by(|left, right| left.id.cmp(&right.id));

    for excluded in &excluded_capabilities {
        if !capabilities.iter().any(|record| &record.id == excluded) {
            return Err(invalid(format!(
                "counterfactual capability `{excluded}` is not an admitted primitive"
            )));
        }
    }

    let mut nodes = BTreeMap::<String, ModuleResearchGraphNodeRecord>::new();
    let mut edges = BTreeMap::<String, ModuleResearchGraphEdgeRecord>::new();
    let mut capability_nodes = BTreeMap::<String, String>::new();
    let mut gaps = BTreeSet::<String>::new();
    let mut truncated = false;

    for capability in &capabilities {
        let Some(capability_node) =
            insert_capability_node(&mut nodes, capability, bounds.maximum_nodes, &mut truncated)
        else {
            gaps.insert(
                "node bound prevented one or more admitted primitives from entering graph-v2"
                    .into(),
            );
            continue;
        };
        capability_nodes.insert(capability.id.clone(), capability_node.clone());
        let excluded = excluded_capabilities.contains(&capability.id);

        for fact in &capability.consumes {
            let Some(node) = insert_fact_node(
                &mut nodes,
                capability,
                fact,
                true,
                bounds.maximum_nodes,
                &mut truncated,
            ) else {
                gaps.insert("node bound truncated prerequisite projection".into());
                break;
            };
            insert_edge(
                &mut edges,
                edge_record(
                    &node,
                    &capability_node,
                    INTERNAL_CONSUMES_RELATION,
                    &capability.receipts,
                    if excluded {
                        ModuleResearchGraphEdgeDisposition::Broken
                    } else {
                        ModuleResearchGraphEdgeDisposition::Supported
                    },
                    None,
                    if excluded {
                        "counterfactual removed the consuming capability"
                    } else {
                        "the admitted primitive names this exact typed prerequisite"
                    },
                ),
                bounds.maximum_edges,
                &mut truncated,
            );
        }
        for fact in &capability.produces {
            let Some(node) = insert_fact_node(
                &mut nodes,
                capability,
                fact,
                false,
                bounds.maximum_nodes,
                &mut truncated,
            ) else {
                gaps.insert("node bound truncated produced-fact projection".into());
                break;
            };
            insert_edge(
                &mut edges,
                edge_record(
                    &capability_node,
                    &node,
                    INTERNAL_PRODUCES_RELATION,
                    &capability.receipts,
                    if excluded {
                        ModuleResearchGraphEdgeDisposition::Broken
                    } else {
                        ModuleResearchGraphEdgeDisposition::Supported
                    },
                    None,
                    if excluded {
                        "counterfactual removed the producing capability"
                    } else {
                        "the admitted primitive names this exact typed output"
                    },
                ),
                bounds.maximum_edges,
                &mut truncated,
            );
        }
        if is_goal(capability.capability)
            && let Some(impact) =
                insert_impact_node(&mut nodes, capability, bounds.maximum_nodes, &mut truncated)
        {
            insert_edge(
                &mut edges,
                edge_record(
                    &capability_node,
                    &impact,
                    INTERNAL_IMPACT_RELATION,
                    &capability.receipts,
                    if excluded {
                        ModuleResearchGraphEdgeDisposition::Broken
                    } else {
                        ModuleResearchGraphEdgeDisposition::Supported
                    },
                    None,
                    if excluded {
                        "counterfactual removed the impact-producing capability"
                    } else {
                        "the admitted primitive's class-specific oracle demonstrated this bounded impact"
                    },
                ),
                bounds.maximum_edges,
                &mut truncated,
            );
        }
    }

    let mut joins = Vec::<Join>::new();
    let mut experiments = BTreeMap::<String, ModuleResearchExperimentSpecification>::new();
    let mut pairs_considered = 0_u64;
    'pairs: for producer in &capabilities {
        let Some(from_node) = capability_nodes.get(&producer.id) else {
            continue;
        };
        for consumer in &capabilities {
            let Some(to_node) = capability_nodes.get(&consumer.id) else {
                continue;
            };
            pairs_considered = pairs_considered.saturating_add(1);
            if edges.len() >= bounds.maximum_edges as usize {
                truncated = true;
                gaps.insert("edge bound truncated ordered primitive-pair evaluation".into());
                break 'pairs;
            }
            let evaluation = evaluate_join(producer, consumer);
            let counterfactual = excluded_capabilities.contains(&producer.id)
                || excluded_capabilities.contains(&consumer.id);
            let (relation, disposition, rejection, detail, experiment, experiment_receipts) =
                match evaluation {
                    JoinEvaluation::Accepted { kind, disposition, detail } => {
                        let relation = relation_name(kind);
                        let mut disposition = if counterfactual {
                            ModuleResearchGraphEdgeDisposition::Broken
                        } else {
                            disposition
                        };
                        let mut experiment = (disposition
                            == ModuleResearchGraphEdgeDisposition::Unresolved)
                            .then(|| experiment_specification(producer, consumer, relation));
                        let mut experiment_receipts = Vec::new();
                        let mut detail = detail;
                        if let Some(specification) = &experiment {
                            experiment_receipts =
                                observed_experiment_receipts(state, specification);
                            if !experiment_receipts.is_empty() {
                                disposition = ModuleResearchGraphEdgeDisposition::Supported;
                                detail = "a bounded Stage 4 experiment preserved exact target, authority, changed-dimension and oracle continuity for this relation; full-chain replay remains unconfirmed".into();
                                experiment = None;
                            }
                        }
                        (
                            relation,
                            disposition,
                            None,
                            if counterfactual {
                                "counterfactual removed a necessary admitted primitive".into()
                            } else {
                                detail
                            },
                            experiment,
                            experiment_receipts,
                        )
                    }
                    JoinEvaluation::Rejected { relation, reason, detail } => (
                        relation,
                        ModuleResearchGraphEdgeDisposition::Rejected,
                        Some(reason),
                        detail,
                        None,
                        Vec::new(),
                    ),
                };
            let mut receipts = combined_receipts(producer, consumer);
            receipts.extend(experiment_receipts);
            receipts.sort_by(|left, right| left.digest.cmp(&right.digest));
            receipts.dedup_by(|left, right| left.digest == right.digest);
            let edge = edge_record(
                from_node,
                to_node,
                relation,
                &receipts,
                disposition,
                rejection,
                &detail,
            );
            let edge_id = edge.id.clone();
            edges.insert(edge_id.clone(), edge);
            if matches!(
                disposition,
                ModuleResearchGraphEdgeDisposition::Supported
                    | ModuleResearchGraphEdgeDisposition::Unresolved
                    | ModuleResearchGraphEdgeDisposition::Broken
            ) {
                let experiment_id = experiment.as_ref().map(|value| value.id.clone());
                if let Some(experiment) = experiment {
                    experiments.insert(experiment.id.clone(), experiment);
                }
                joins.push(Join {
                    from_capability: producer.id.clone(),
                    to_capability: consumer.id.clone(),
                    edge_id,
                    disposition,
                    experiment_id,
                });
            }
        }
    }

    let (chains, candidates_expanded, cycles_rejected, search_truncated) =
        search(&capabilities, &capability_nodes, &joins, bounds);
    truncated |= search_truncated;
    if search_truncated {
        gaps.insert(
            "frontier, depth, cycle, or cost bounds truncated candidate enumeration".into(),
        );
    }
    if chains.is_empty() {
        gaps.insert(
            "no bounded multi-primitive impact candidate satisfied the versioned compatibility map"
                .into(),
        );
    }
    if !experiments.is_empty() {
        gaps.insert(format!(
            "{} legal relation(s) still require bounded experiments",
            experiments.len()
        ));
    }
    if !excluded_capabilities.is_empty() {
        gaps.insert(format!(
            "counterfactual removed {} admitted prerequisite(s) without deleting the original catalog",
            excluded_capabilities.len()
        ));
    }
    gaps.insert(
        "graph-v2 construction does not execute experiments or confirm full exploit chains; Stage 5 fresh-chain replay remains required"
            .into(),
    );

    let nodes = nodes.into_values().collect::<Vec<_>>();
    let edges = edges.into_values().collect::<Vec<_>>();
    let chains = chains.into_values().collect::<Vec<_>>();
    let experiments = experiments.into_values().collect::<Vec<_>>();
    let excluded_capabilities = excluded_capabilities.into_iter().collect::<Vec<_>>();
    let gaps = gaps.into_iter().collect::<Vec<_>>();
    let summary = ModuleResearchSearchSummary {
        capabilities_considered: u32::try_from(capabilities.len()).unwrap_or(u32::MAX),
        pairs_considered,
        candidates_expanded,
        cycles_rejected,
        truncated,
    };
    let material = GraphIdentityMaterial {
        builder: &builder,
        target: &target,
        bounds,
        excluded_capabilities: &excluded_capabilities,
        nodes: &nodes,
        edges: &edges,
        chains: &chains,
        experiments: &experiments,
        summary,
        gaps: &gaps,
    };
    let graph_id = format!("graph-v2-{}", digest(&serde_json::to_vec(&material)?));
    let graph = ModuleResearchGraphRecord {
        schema: MODULE_RESEARCH_CONTRACT_VERSION,
        id: graph_id.clone(),
        target,
        builder,
        bounds,
        excluded_capabilities,
        nodes,
        edges,
        chains,
        experiments,
        summary,
        gaps,
    };
    let reused = state.research_graphs.iter().any(|value| value.id == graph_id);
    if !reused {
        state.research_graphs.push(graph.clone());
    }
    state.research_active_graph = Some(graph_id.clone());
    Ok(BuildSummary {
        graph_id,
        nodes: graph.nodes.len(),
        edges: graph.edges.len(),
        candidates: graph
            .chains
            .iter()
            .filter(|chain| chain.disposition == ModuleResearchChainDisposition::Candidate)
            .count(),
        broken: graph
            .chains
            .iter()
            .filter(|chain| chain.disposition == ModuleResearchChainDisposition::Broken)
            .count(),
        rejected_edges: graph
            .edges
            .iter()
            .filter(|edge| edge.disposition == ModuleResearchGraphEdgeDisposition::Rejected)
            .count(),
        experiments: graph.experiments.len(),
        truncated,
        reused,
    })
}

fn observed_experiment_receipts(
    state: &State,
    specification: &ModuleResearchExperimentSpecification,
) -> Vec<ModuleResearchIdentity> {
    state
        .research_experiments
        .iter()
        .filter(|record| {
            record.phase == ModuleResearchExperimentPhase::Observed
                && record.request.value == specification.id
                && record.target.digest == specification.target.digest
                && record.adapter_operation == specification.adapter_operation
                && record.changed_dimension == specification.changed_dimension
                && record.oracle.digest == specification.oracle.digest
        })
        .flat_map(|record| record.receipts.iter().cloned())
        .map(|receipt| (receipt.digest.clone(), receipt))
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect()
}

enum JoinEvaluation {
    Accepted { kind: JoinKind, disposition: ModuleResearchGraphEdgeDisposition, detail: String },
    Rejected { relation: &'static str, reason: ModuleResearchGraphRejection, detail: String },
}

fn evaluate_join(
    producer: &ModuleResearchCapabilityRecord,
    consumer: &ModuleResearchCapabilityRecord,
) -> JoinEvaluation {
    if producer.receipts.is_empty() || consumer.receipts.is_empty() {
        return rejected(
            "receipt-continuity@1",
            ModuleResearchGraphRejection::InsufficientEvidence,
            "both sides of a graph-v2 relation require exact admitted receipts",
        );
    }
    if producer.id == consumer.id {
        return rejected(
            "cycle-requires-state-transition@1",
            ModuleResearchGraphRejection::UnsupportedCycle,
            "a primitive cannot satisfy itself without an explicit state transition and cycle budget",
        );
    }
    let producer_snapshot = fact_value(producer, ModuleResearchCapabilityFactKind::SourceSnapshot);
    let consumer_snapshot = fact_value(consumer, ModuleResearchCapabilityFactKind::SourceSnapshot);
    if producer_snapshot.is_none() || producer_snapshot != consumer_snapshot {
        return rejected(
            "target-continuity@1",
            ModuleResearchGraphRejection::CrossTarget,
            "primitive source snapshots are absent or different",
        );
    }

    let candidate = match (producer.capability, consumer.capability) {
        (
            ModuleResearchCapabilityKind::SourceWeakness,
            ModuleResearchCapabilityKind::InputInterpretationViolation,
        ) => {
            if source_weakness_class(producer) != Some("input_interpretation_and_injection") {
                return rejected(
                    SOURCE_RUNTIME_RELATION,
                    ModuleResearchGraphRejection::IncompatibleCapability,
                    "source weakness class cannot satisfy the runtime input-interpretation primitive",
                );
            }
            JoinKind::SourceRuntime
        }
        (
            ModuleResearchCapabilityKind::InputInterpretationViolation,
            ModuleResearchCapabilityKind::ClientScriptExecution,
        ) => JoinKind::RuntimeBrowser,
        _ => {
            return rejected(
                "co-observation-is-not-causation@1",
                ModuleResearchGraphRejection::TemporalOnly,
                "co-observation order alone supplies no typed capability relation",
            );
        }
    };

    match candidate {
        JoinKind::SourceRuntime => {
            if !producer.subject.value.starts_with("source-path:")
                || !consumer.subject.value.starts_with("endpoint:")
            {
                return rejected(
                    SOURCE_RUNTIME_RELATION,
                    ModuleResearchGraphRejection::IncompatibleSubject,
                    "source-to-runtime corroboration requires a source-path lead and endpoint subject",
                );
            }
            JoinEvaluation::Accepted {
                kind: candidate,
                disposition: ModuleResearchGraphEdgeDisposition::Supported,
                detail: "matching source weakness and runtime input-interpretation receipts share one immutable source snapshot".into(),
            }
        }
        JoinKind::RuntimeBrowser => {
            let producer_lab = fact_value(producer, ModuleResearchCapabilityFactKind::Laboratory);
            let consumer_lab = fact_value(consumer, ModuleResearchCapabilityFactKind::Laboratory);
            if producer_lab.is_none() || producer_lab != consumer_lab {
                return rejected(
                    RUNTIME_BROWSER_RELATION,
                    ModuleResearchGraphRejection::StaleTargetState,
                    "runtime primitives do not share one exact disposable laboratory",
                );
            }
            if !producer.subject.value.starts_with("endpoint:")
                || !consumer.subject.value.starts_with("browser:")
            {
                return rejected(
                    RUNTIME_BROWSER_RELATION,
                    ModuleResearchGraphRejection::IncompatibleSubject,
                    "runtime-to-browser handoff requires endpoint and isolated-browser subjects",
                );
            }
            if authority_class(&producer.authority_after.value)
                != authority_class(&consumer.authority_before.value)
                || authority_class(&producer.authority_after.value) != Some("ordinary-user")
            {
                return rejected(
                    RUNTIME_BROWSER_RELATION,
                    ModuleResearchGraphRejection::IncompatibleAuthority,
                    "runtime producer and browser consumer do not retain ordinary-user authority continuity",
                );
            }
            JoinEvaluation::Accepted {
                kind: candidate,
                disposition: ModuleResearchGraphEdgeDisposition::Unresolved,
                detail: "capability types, source, laboratory, subject handoff, and authority are compatible; exact producer-state to browser-input causality still requires a bounded experiment".into(),
            }
        }
    }
}

fn rejected(
    relation: &'static str,
    reason: ModuleResearchGraphRejection,
    detail: &str,
) -> JoinEvaluation {
    JoinEvaluation::Rejected { relation, reason, detail: detail.into() }
}

fn relation_name(kind: JoinKind) -> &'static str {
    match kind {
        JoinKind::SourceRuntime => SOURCE_RUNTIME_RELATION,
        JoinKind::RuntimeBrowser => RUNTIME_BROWSER_RELATION,
    }
}

fn source_weakness_class(record: &ModuleResearchCapabilityRecord) -> Option<&str> {
    record.produces.iter().find_map(|fact| {
        (fact.kind == ModuleResearchCapabilityFactKind::SecurityProperty)
            .then(|| fact.value.strip_prefix("source-lead:"))
            .flatten()
            .and_then(|value| value.split(':').next())
    })
}

fn fact_value(
    record: &ModuleResearchCapabilityRecord,
    kind: ModuleResearchCapabilityFactKind,
) -> Option<&str> {
    record
        .consumes
        .iter()
        .chain(&record.produces)
        .find(|fact| fact.kind == kind)
        .map(|fact| fact.value.as_str())
}

fn authority_class(value: &str) -> Option<&'static str> {
    if value.contains("application-user") || value.contains("ordinary-user") {
        Some("ordinary-user")
    } else if value.contains("anonymous") {
        Some("anonymous")
    } else if value.contains("admin") || value.contains("privilege") {
        Some("privileged")
    } else {
        None
    }
}

fn experiment_specification(
    producer: &ModuleResearchCapabilityRecord,
    consumer: &ModuleResearchCapabilityRecord,
    relation: &str,
) -> ModuleResearchExperimentSpecification {
    let material = format!(
        "graph-experiment-v2\0{}\0{}\0{}\0{}",
        producer.id, consumer.id, relation, consumer.oracle.digest
    );
    let id = format!("experiment-spec-{}", digest(material.as_bytes()));
    ModuleResearchExperimentSpecification {
        schema: MODULE_RESEARCH_CONTRACT_VERSION,
        id,
        target: consumer.target.clone(),
        from_capability: producer.id.clone(),
        to_capability: consumer.id.clone(),
        relation: identity(ModuleResearchIdentityKind::GraphRelation, relation),
        adapter_operation: adapter_operation(&consumer.adapter_id).into(),
        changed_dimension: "producer target-state continuity into consumer controlled input".into(),
        required_capability: consumer.capability,
        oracle: identity(
            ModuleResearchIdentityKind::Oracle,
            &format!(
                "graph-transition-oracle@1:{}:{}",
                producer.oracle.digest, consumer.oracle.digest
            ),
        ),
        maximum_operations: 2,
        detail: "a later Stage 4 action may replay the producer, preserve its exact output state, and observe the consumer oracle in the same disposable laboratory; this graph build did not execute it".into(),
    }
}

fn adapter_operation(adapter_id: &str) -> &'static str {
    match adapter_id {
        "peritus.browser-client" => "browser.campaign.v1",
        "peritus.http-api" => "http.campaign.v1",
        "peritus.identity-access" => "identity.campaign.v1",
        "peritus.file-parser" => "file-fuzz.campaign.v1",
        "peritus.workflow-state" => "workflow.campaign.v1",
        "peritus.boundary-authority" => "boundary.campaign.v1",
        _ => "unsupported.stage4.operation",
    }
}

fn combined_receipts(
    producer: &ModuleResearchCapabilityRecord,
    consumer: &ModuleResearchCapabilityRecord,
) -> Vec<ModuleResearchIdentity> {
    producer
        .receipts
        .iter()
        .chain(&consumer.receipts)
        .cloned()
        .map(|receipt| (receipt.digest.clone(), receipt))
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect()
}

fn insert_capability_node(
    nodes: &mut BTreeMap<String, ModuleResearchGraphNodeRecord>,
    capability: &ModuleResearchCapabilityRecord,
    maximum: u32,
    truncated: &mut bool,
) -> Option<String> {
    let id =
        node_id(ModuleResearchGraphNodeKind::Capability, &capability.target.digest, &capability.id);
    insert_node(
        nodes,
        ModuleResearchGraphNodeRecord {
            id: id.clone(),
            kind: ModuleResearchGraphNodeKind::Capability,
            target: capability.target.clone(),
            capability_id: Some(capability.id.clone()),
            label: format!("{:?} via {}", capability.capability, capability.adapter_id),
        },
        maximum,
        truncated,
    )
    .then_some(id)
}

fn insert_fact_node(
    nodes: &mut BTreeMap<String, ModuleResearchGraphNodeRecord>,
    capability: &ModuleResearchCapabilityRecord,
    fact: &ModuleResearchCapabilityFact,
    consumed: bool,
    maximum: u32,
    truncated: &mut bool,
) -> Option<String> {
    let kind = if consumed {
        match fact.kind {
            ModuleResearchCapabilityFactKind::EntryPoint => ModuleResearchGraphNodeKind::EntryPoint,
            _ => ModuleResearchGraphNodeKind::Prerequisite,
        }
    } else {
        match fact.kind {
            ModuleResearchCapabilityFactKind::Authority => {
                ModuleResearchGraphNodeKind::AuthorityTransition
            }
            ModuleResearchCapabilityFactKind::BrowserEffect => ModuleResearchGraphNodeKind::Impact,
            _ => ModuleResearchGraphNodeKind::StateEffect,
        }
    };
    let id = node_id(kind, &capability.target.digest, &fact.digest);
    insert_node(
        nodes,
        ModuleResearchGraphNodeRecord {
            id: id.clone(),
            kind,
            target: capability.target.clone(),
            capability_id: None,
            label: format!("{:?}:{}", fact.kind, &fact.digest[..12]),
        },
        maximum,
        truncated,
    )
    .then_some(id)
}

fn insert_impact_node(
    nodes: &mut BTreeMap<String, ModuleResearchGraphNodeRecord>,
    capability: &ModuleResearchCapabilityRecord,
    maximum: u32,
    truncated: &mut bool,
) -> Option<String> {
    let id = node_id(
        ModuleResearchGraphNodeKind::Impact,
        &capability.target.digest,
        capability_code(capability.capability),
    );
    insert_node(
        nodes,
        ModuleResearchGraphNodeRecord {
            id: id.clone(),
            kind: ModuleResearchGraphNodeKind::Impact,
            target: capability.target.clone(),
            capability_id: Some(capability.id.clone()),
            label: format!("bounded impact: {:?}", capability.capability),
        },
        maximum,
        truncated,
    )
    .then_some(id)
}

fn insert_node(
    nodes: &mut BTreeMap<String, ModuleResearchGraphNodeRecord>,
    node: ModuleResearchGraphNodeRecord,
    maximum: u32,
    truncated: &mut bool,
) -> bool {
    if nodes.contains_key(&node.id) {
        return true;
    }
    if nodes.len() >= maximum as usize {
        *truncated = true;
        return false;
    }
    nodes.insert(node.id.clone(), node);
    true
}

fn insert_edge(
    edges: &mut BTreeMap<String, ModuleResearchGraphEdgeRecord>,
    edge: ModuleResearchGraphEdgeRecord,
    maximum: u32,
    truncated: &mut bool,
) {
    if edges.contains_key(&edge.id) {
        return;
    }
    if edges.len() >= maximum as usize {
        *truncated = true;
        return;
    }
    edges.insert(edge.id.clone(), edge);
}

fn node_id(kind: ModuleResearchGraphNodeKind, target: &str, material: &str) -> String {
    format!(
        "graph-node-{}",
        digest(format!("graph-node-v2\0{}\0{target}\0{material}", node_kind_code(kind)).as_bytes())
    )
}

fn edge_record(
    from: &str,
    to: &str,
    relation: &str,
    receipts: &[ModuleResearchIdentity],
    disposition: ModuleResearchGraphEdgeDisposition,
    rejection_reason: Option<ModuleResearchGraphRejection>,
    detail: &str,
) -> ModuleResearchGraphEdgeRecord {
    let receipt_material =
        receipts.iter().map(|receipt| receipt.digest.as_str()).collect::<Vec<_>>().join(":");
    let id = format!(
        "graph-edge-{}",
        digest(
            format!(
                "graph-edge-v2\0{from}\0{to}\0{relation}\0{}\0{}\0{receipt_material}",
                edge_disposition_code(disposition),
                rejection_reason.map_or("none", rejection_code),
            )
            .as_bytes()
        )
    );
    ModuleResearchGraphEdgeRecord {
        id,
        from: from.into(),
        to: to.into(),
        relation: identity(ModuleResearchIdentityKind::GraphRelation, relation),
        receipts: receipts.to_vec(),
        disposition,
        rejection_reason,
        detail: detail.into(),
    }
}

fn search(
    capabilities: &[ModuleResearchCapabilityRecord],
    capability_nodes: &BTreeMap<String, String>,
    joins: &[Join],
    bounds: ModuleResearchSearchBounds,
) -> (BTreeMap<String, ModuleResearchChainRecord>, u32, u32, bool) {
    let by_id =
        capabilities.iter().map(|record| (record.id.as_str(), record)).collect::<BTreeMap<_, _>>();
    let mut outgoing = BTreeMap::<&str, Vec<&Join>>::new();
    let mut incoming = BTreeSet::<&str>::new();
    for join in joins {
        outgoing.entry(&join.from_capability).or_default().push(join);
        incoming.insert(&join.to_capability);
    }
    for values in outgoing.values_mut() {
        values.sort_by(|left, right| {
            left.to_capability.cmp(&right.to_capability).then(left.edge_id.cmp(&right.edge_id))
        });
    }
    let mut roots = capabilities
        .iter()
        .filter(|record| {
            record.capability == ModuleResearchCapabilityKind::SourceWeakness
                || !incoming.contains(record.id.as_str())
        })
        .map(|record| record.id.clone())
        .collect::<Vec<_>>();
    roots.sort();
    roots.dedup();

    let mut frontier = VecDeque::<PathState>::new();
    let mut opened = 0_u32;
    let mut truncated = false;
    for root in roots {
        if opened >= bounds.maximum_open_candidates {
            truncated = true;
            break;
        }
        frontier.push_back(PathState {
            capabilities: vec![root],
            edges: Vec::new(),
            missing_experiments: BTreeSet::new(),
            cost: 1,
            cycles: 0,
        });
        opened = opened.saturating_add(1);
    }

    let experiment_by_edge = joins
        .iter()
        .filter_map(|join| {
            join.experiment_id.as_ref().map(|id| (join.edge_id.as_str(), id.as_str()))
        })
        .collect::<BTreeMap<_, _>>();
    let disposition_by_edge = joins
        .iter()
        .map(|join| (join.edge_id.as_str(), join.disposition))
        .collect::<BTreeMap<_, _>>();
    let mut chains = BTreeMap::<String, ModuleResearchChainRecord>::new();
    let mut expanded = 0_u32;
    let mut cycles_rejected = 0_u32;

    while let Some(path) = frontier.pop_front() {
        expanded = expanded.saturating_add(1);
        let Some(current) = path.capabilities.last() else {
            continue;
        };
        let Some(next_joins) = outgoing.get(current.as_str()) else {
            continue;
        };
        for join in next_joins {
            let repeated = path.capabilities.contains(&join.to_capability);
            let next_cycles = path.cycles.saturating_add(u16::from(repeated));
            if repeated && next_cycles > bounds.maximum_cycles {
                cycles_rejected = cycles_rejected.saturating_add(1);
                continue;
            }
            let next_cost = path.cost.saturating_add(1);
            if path.capabilities.len() >= usize::from(bounds.maximum_depth)
                || next_cost > bounds.maximum_cost
            {
                truncated = true;
                continue;
            }
            let mut next = path.clone();
            next.capabilities.push(join.to_capability.clone());
            next.edges.push(join.edge_id.clone());
            next.cost = next_cost;
            next.cycles = next_cycles;
            if let Some(experiment) = &join.experiment_id {
                next.missing_experiments.insert(experiment.clone());
            }

            let Some(goal_record) = by_id.get(join.to_capability.as_str()) else {
                continue;
            };
            if is_goal(goal_record.capability) && next.capabilities.len() >= 2 {
                let node_ids = next
                    .capabilities
                    .iter()
                    .filter_map(|id| capability_nodes.get(id).cloned())
                    .collect::<Vec<_>>();
                if node_ids.len() == next.capabilities.len() {
                    let adapter_families = next
                        .capabilities
                        .iter()
                        .filter_map(|id| by_id.get(id.as_str()))
                        .map(|record| record.adapter_id.clone())
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>();
                    let broken = next.edges.iter().any(|id| {
                        disposition_by_edge.get(id.as_str())
                            == Some(&ModuleResearchGraphEdgeDisposition::Broken)
                    });
                    let missing_experiments = next
                        .edges
                        .iter()
                        .filter_map(|id| experiment_by_edge.get(id.as_str()).copied())
                        .map(str::to_owned)
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>();
                    let disposition = if broken {
                        ModuleResearchChainDisposition::Broken
                    } else {
                        ModuleResearchChainDisposition::Candidate
                    };
                    let id = chain_id(&node_ids, &next.edges, goal_record.capability, disposition);
                    chains.insert(
                        id.clone(),
                        ModuleResearchChainRecord {
                            id,
                            nodes: node_ids,
                            edges: next.edges.clone(),
                            goal: goal_record.capability,
                            cost: next.cost,
                            missing_experiments,
                            adapter_families,
                            disposition,
                            replay: None,
                            detail: if broken {
                                "counterfactual removal broke at least one necessary compatibility edge; no target operation ran".into()
                            } else {
                                "bounded deterministic compatibility candidate; unresolved edges require later experiments and this is not a confirmed chain".into()
                            },
                        },
                    );
                }
            }

            if opened >= bounds.maximum_open_candidates {
                truncated = true;
                continue;
            }
            frontier.push_back(next);
            opened = opened.saturating_add(1);
        }
    }
    (chains, expanded, cycles_rejected, truncated)
}

fn chain_id(
    nodes: &[String],
    edges: &[String],
    goal: ModuleResearchCapabilityKind,
    disposition: ModuleResearchChainDisposition,
) -> String {
    format!(
        "chain-v2-{}",
        digest(
            format!(
                "chain-v2\0{}\0{}\0{}\0{}",
                nodes.join(":"),
                edges.join(":"),
                capability_code(goal),
                chain_disposition_code(disposition)
            )
            .as_bytes()
        )
    )
}

fn is_goal(kind: ModuleResearchCapabilityKind) -> bool {
    !matches!(
        kind,
        ModuleResearchCapabilityKind::SourceWeakness
            | ModuleResearchCapabilityKind::InputInterpretationViolation
            | ModuleResearchCapabilityKind::Unsupported
    )
}

fn identity(kind: ModuleResearchIdentityKind, value: &str) -> ModuleResearchIdentity {
    ModuleResearchIdentity {
        schema: MODULE_RESEARCH_CONTRACT_VERSION,
        kind,
        value: value.into(),
        digest: digest(
            format!("research-identity-v2\0{}\0{value}", identity_kind_code(kind)).as_bytes(),
        ),
    }
}

const fn node_kind_code(kind: ModuleResearchGraphNodeKind) -> &'static str {
    match kind {
        ModuleResearchGraphNodeKind::EntryPoint => "entry_point",
        ModuleResearchGraphNodeKind::Prerequisite => "prerequisite",
        ModuleResearchGraphNodeKind::Capability => "capability",
        ModuleResearchGraphNodeKind::StateEffect => "state_effect",
        ModuleResearchGraphNodeKind::AuthorityTransition => "authority_transition",
        ModuleResearchGraphNodeKind::Impact => "impact",
    }
}

const fn edge_disposition_code(kind: ModuleResearchGraphEdgeDisposition) -> &'static str {
    match kind {
        ModuleResearchGraphEdgeDisposition::Proposed => "proposed",
        ModuleResearchGraphEdgeDisposition::Supported => "supported",
        ModuleResearchGraphEdgeDisposition::Unresolved => "unresolved",
        ModuleResearchGraphEdgeDisposition::Rejected => "rejected",
        ModuleResearchGraphEdgeDisposition::Broken => "broken",
        ModuleResearchGraphEdgeDisposition::Blocked => "blocked",
        ModuleResearchGraphEdgeDisposition::Superseded => "superseded",
    }
}

const fn rejection_code(reason: ModuleResearchGraphRejection) -> &'static str {
    match reason {
        ModuleResearchGraphRejection::CrossTarget => "cross_target",
        ModuleResearchGraphRejection::StaleTargetState => "stale_target_state",
        ModuleResearchGraphRejection::IncompatibleSubject => "incompatible_subject",
        ModuleResearchGraphRejection::IncompatibleAuthority => "incompatible_authority",
        ModuleResearchGraphRejection::IncompatibleCapability => "incompatible_capability",
        ModuleResearchGraphRejection::TemporalOnly => "temporal_only",
        ModuleResearchGraphRejection::InsufficientEvidence => "insufficient_evidence",
        ModuleResearchGraphRejection::UnsupportedCycle => "unsupported_cycle",
        ModuleResearchGraphRejection::SearchBoundExceeded => "search_bound_exceeded",
    }
}

const fn capability_code(kind: ModuleResearchCapabilityKind) -> &'static str {
    match kind {
        ModuleResearchCapabilityKind::SourceWeakness => "source_weakness",
        ModuleResearchCapabilityKind::InputInterpretationViolation => {
            "input_interpretation_violation"
        }
        ModuleResearchCapabilityKind::SensitiveDataDisclosure => "sensitive_data_disclosure",
        ModuleResearchCapabilityKind::UnauthorizedApplicationAction => {
            "unauthorized_application_action"
        }
        ModuleResearchCapabilityKind::ClientScriptExecution => "client_script_execution",
        ModuleResearchCapabilityKind::ClientPolicyViolation => "client_policy_violation",
        ModuleResearchCapabilityKind::CrossOriginAction => "cross_origin_action",
        ModuleResearchCapabilityKind::AuthenticationBypass => "authentication_bypass",
        ModuleResearchCapabilityKind::AuthorizationBypass => "authorization_bypass",
        ModuleResearchCapabilityKind::TenancyBoundaryCrossing => "tenancy_boundary_crossing",
        ModuleResearchCapabilityKind::SessionLifecycleViolation => "session_lifecycle_violation",
        ModuleResearchCapabilityKind::FileBoundaryViolation => "file_boundary_violation",
        ModuleResearchCapabilityKind::ParserFault => "parser_fault",
        ModuleResearchCapabilityKind::WorkflowInvariantViolation => "workflow_invariant_violation",
        ModuleResearchCapabilityKind::PrivateNetworkBoundaryViolation => {
            "private_network_boundary_violation"
        }
        ModuleResearchCapabilityKind::TlsBoundaryViolation => "tls_boundary_violation",
        ModuleResearchCapabilityKind::PrivilegeBoundaryViolation => "privilege_boundary_violation",
        ModuleResearchCapabilityKind::DelegatedAuthorityViolation => {
            "delegated_authority_violation"
        }
        ModuleResearchCapabilityKind::Unsupported => "unsupported",
    }
}

const fn identity_kind_code(kind: ModuleResearchIdentityKind) -> &'static str {
    match kind {
        ModuleResearchIdentityKind::RoleImplementation => "role_implementation",
        ModuleResearchIdentityKind::ExperimentRequest => "experiment_request",
        ModuleResearchIdentityKind::Target => "target",
        ModuleResearchIdentityKind::Authority => "authority",
        ModuleResearchIdentityKind::Subject => "subject",
        ModuleResearchIdentityKind::Oracle => "oracle",
        ModuleResearchIdentityKind::Receipt => "receipt",
        ModuleResearchIdentityKind::GraphRelation => "graph_relation",
        ModuleResearchIdentityKind::Minimizer => "minimizer",
        ModuleResearchIdentityKind::Template => "template",
        ModuleResearchIdentityKind::Artifact => "artifact",
    }
}

const fn chain_disposition_code(kind: ModuleResearchChainDisposition) -> &'static str {
    match kind {
        ModuleResearchChainDisposition::Candidate => "candidate",
        ModuleResearchChainDisposition::Confirmed => "confirmed",
        ModuleResearchChainDisposition::Broken => "broken",
        ModuleResearchChainDisposition::Rejected => "rejected",
        ModuleResearchChainDisposition::Blocked => "blocked",
        ModuleResearchChainDisposition::Superseded => "superseded",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use peritus_plugin_sdk::ModuleResearchProjectionRejection;
    use serde_json::json;

    fn hash(value: &str) -> String {
        digest(value.as_bytes())
    }

    fn fact(kind: ModuleResearchCapabilityFactKind, value: &str) -> ModuleResearchCapabilityFact {
        ModuleResearchCapabilityFact {
            schema: MODULE_RESEARCH_CONTRACT_VERSION,
            kind,
            value: value.into(),
            digest: hash(&format!("fact:{kind:?}:{value}")),
        }
    }

    fn capability(
        id: &str,
        adapter: &str,
        kind: ModuleResearchCapabilityKind,
        snapshot: &str,
        lab: Option<&str>,
    ) -> ModuleResearchCapabilityRecord {
        let subject = match adapter {
            "peritus.source-analysis" => "source-path:service.py".into(),
            "peritus.http-api" => format!("endpoint:{}", lab.unwrap()),
            "peritus.browser-client" => {
                format!("browser:{}:chromium", lab.unwrap())
            }
            _ => format!("subject:{adapter}"),
        };
        let authority = match adapter {
            "peritus.source-analysis" => format!("scope:source-read:{snapshot}"),
            "peritus.http-api" => format!("laboratory:{}:application-user", lab.unwrap()),
            "peritus.browser-client" => {
                format!("browser-context:{}:ordinary-user", lab.unwrap())
            }
            _ => format!("authority:{adapter}"),
        };
        let mut consumes = vec![
            fact(ModuleResearchCapabilityFactKind::SourceSnapshot, snapshot),
            fact(ModuleResearchCapabilityFactKind::Subject, &subject),
            fact(ModuleResearchCapabilityFactKind::Authority, &authority),
            fact(ModuleResearchCapabilityFactKind::EntryPoint, &format!("entry:{id}")),
            fact(ModuleResearchCapabilityFactKind::Oracle, &format!("oracle:{id}")),
        ];
        if let Some(lab) = lab {
            consumes.push(fact(ModuleResearchCapabilityFactKind::Laboratory, lab));
        }
        let produces = if kind == ModuleResearchCapabilityKind::SourceWeakness {
            vec![fact(
                ModuleResearchCapabilityFactKind::SecurityProperty,
                "source-lead:input_interpretation_and_injection:python.eval",
            )]
        } else {
            vec![fact(ModuleResearchCapabilityFactKind::TargetState, &format!("state:{id}"))]
        };
        ModuleResearchCapabilityRecord {
            schema: MODULE_RESEARCH_CONTRACT_VERSION,
            id: id.into(),
            adapter_id: adapter.into(),
            adapter_version: format!("{adapter}@1"),
            projection_version: format!("projection:{adapter}@1"),
            target: identity(
                ModuleResearchIdentityKind::Target,
                &format!("source:{snapshot}:lab:{}", lab.unwrap_or("none")),
            ),
            subject: identity(ModuleResearchIdentityKind::Subject, &subject),
            authority_before: identity(ModuleResearchIdentityKind::Authority, &authority),
            authority_after: identity(ModuleResearchIdentityKind::Authority, &authority),
            capability: kind,
            consumes,
            produces,
            evidence_boundary: if adapter == "peritus.source-analysis" {
                ModuleResearchEvidenceBoundary::SourceLead
            } else {
                ModuleResearchEvidenceBoundary::RuntimeConfirmed
            },
            oracle: identity(ModuleResearchIdentityKind::Oracle, &format!("oracle:{id}")),
            receipts: vec![identity(ModuleResearchIdentityKind::Receipt, &format!("receipt:{id}"))],
            source_record: format!("source:{id}"),
            disposition: ModuleResearchCapabilityDisposition::Projected,
            rejection_reason: None::<ModuleResearchProjectionRejection>,
            detail: "test primitive".into(),
        }
    }

    fn state_with_capabilities() -> State {
        let mut state = State::default();
        state.snapshots.push(
            serde_json::from_value(json!({
                "schema": 1,
                "id": {"schema":1,"kind":"source_snapshot","value":"snapshot-stage3"},
                "campaign": state.campaign.id,
                "scope_revision": {"schema":1,"kind":"scope_revision","value":"scope-stage3"},
                "source_handle": "source-stage3",
                "snapshot_digest": hash("snapshot-stage3"),
                "manifest_artifact": hash("manifest-stage3")
            }))
            .unwrap(),
        );
        let snapshot = state.active_snapshot().unwrap().snapshot_digest.clone();
        state.research_capabilities = vec![
            capability(
                "source-input",
                "peritus.source-analysis",
                ModuleResearchCapabilityKind::SourceWeakness,
                &snapshot,
                None,
            ),
            capability(
                "http-input",
                "peritus.http-api",
                ModuleResearchCapabilityKind::InputInterpretationViolation,
                &snapshot,
                Some("lab-stage3"),
            ),
            capability(
                "browser-script",
                "peritus.browser-client",
                ModuleResearchCapabilityKind::ClientScriptExecution,
                &snapshot,
                Some("lab-stage3"),
            ),
        ];
        state
    }

    #[test]
    fn three_family_candidate_is_deterministic_and_unconfirmed() {
        let mut state = state_with_capabilities();
        let first = build(&mut state, default_bounds(), BTreeSet::new()).unwrap();
        assert_eq!(first.candidates, 1);
        assert_eq!(first.broken, 0);
        assert_eq!(first.experiments, 1);
        let graph = state.research_graphs.last().unwrap();
        let chain = graph.chains.first().unwrap();
        assert_eq!(chain.adapter_families.len(), 3);
        assert_eq!(chain.disposition, ModuleResearchChainDisposition::Candidate);
        assert!(chain.replay.is_none());
        assert_eq!(chain.missing_experiments.len(), 1);
        let graph_id = first.graph_id;
        let second = build(&mut state, default_bounds(), BTreeSet::new()).unwrap();
        assert_eq!(second.graph_id, graph_id);
        assert!(second.reused);
        assert_eq!(state.research_graphs.len(), 1);
    }

    #[test]
    fn observed_stage4_experiment_supports_relation_without_confirming_chain() {
        let mut state = state_with_capabilities();
        build(&mut state, default_bounds(), BTreeSet::new()).unwrap();
        let specification = state.research_graphs.last().unwrap().experiments[0].clone();
        let receipt = identity(ModuleResearchIdentityKind::Receipt, "stage4-relation-receipt");
        state.research_experiments.push(peritus_plugin_sdk::ModuleResearchExperimentRecord {
            schema: MODULE_RESEARCH_CONTRACT_VERSION,
            id: "stage4-relation-experiment".into(),
            request: identity(ModuleResearchIdentityKind::ExperimentRequest, &specification.id),
            role_implementation: identity(
                ModuleResearchIdentityKind::RoleImplementation,
                "stage4-test-role@1",
            ),
            target: specification.target.clone(),
            authority: identity(
                ModuleResearchIdentityKind::Authority,
                "laboratory:lab-stage3:ordinary-user:credential-free",
            ),
            oracle: specification.oracle.clone(),
            adapter_operation: specification.adapter_operation.clone(),
            changed_dimension: specification.changed_dimension.clone(),
            phase: ModuleResearchExperimentPhase::Observed,
            receipts: vec![receipt.clone()],
            artifacts: Vec::new(),
            limitations: vec!["bounded relation oracle observed".into()],
        });

        let result = build(&mut state, default_bounds(), BTreeSet::new()).unwrap();
        assert_eq!(result.experiments, 0);
        let graph = state.research_graphs.last().unwrap();
        let chain = graph.chains.first().unwrap();
        assert_eq!(chain.disposition, ModuleResearchChainDisposition::Candidate);
        assert!(chain.replay.is_none());
        assert!(chain.missing_experiments.is_empty());
        assert!(graph.edges.iter().any(|edge| {
            edge.disposition == ModuleResearchGraphEdgeDisposition::Supported
                && edge.receipts.iter().any(|value| value.digest == receipt.digest)
        }));
    }

    #[test]
    fn counterfactual_breaks_chain_without_deleting_other_primitives() {
        let mut state = state_with_capabilities();
        let base = build(&mut state, default_bounds(), BTreeSet::new()).unwrap();
        let excluded = BTreeSet::from(["http-input".to_owned()]);
        let result = build(&mut state, default_bounds(), excluded).unwrap();
        assert_eq!(result.candidates, 0);
        assert_eq!(result.broken, 1);
        assert_eq!(state.research_capabilities.len(), 3);
        let graph = state.research_graphs.last().unwrap();
        assert_eq!(graph.excluded_capabilities, ["http-input"]);
        assert!(graph.edges.iter().any(|edge| {
            edge.disposition == ModuleResearchGraphEdgeDisposition::Supported
                && edge.from.contains("graph-node")
        }));
        let selected = build(&mut state, default_bounds(), BTreeSet::new()).unwrap();
        assert!(selected.reused);
        assert_eq!(selected.graph_id, base.graph_id);
        assert_eq!(state.research_active_graph.as_deref(), Some(base.graph_id.as_str()));
        assert_eq!(state.research_graphs.len(), 2);
    }

    #[test]
    fn incompatible_and_stale_joins_have_stable_reasons() {
        let mut state = state_with_capabilities();
        let snapshot = state.active_snapshot().unwrap().snapshot_digest.clone();
        state.research_capabilities.push(capability(
            "browser-stale",
            "peritus.browser-client",
            ModuleResearchCapabilityKind::ClientScriptExecution,
            &snapshot,
            Some("other-lab"),
        ));
        let mut unrelated = capability(
            "source-secret",
            "peritus.source-analysis",
            ModuleResearchCapabilityKind::SourceWeakness,
            &snapshot,
            None,
        );
        unrelated.produces[0] = fact(
            ModuleResearchCapabilityFactKind::SecurityProperty,
            "source-lead:configuration_secrets_and_observability:literal",
        );
        state.research_capabilities.push(unrelated);
        let cross_target = capability(
            "browser-cross-target",
            "peritus.browser-client",
            ModuleResearchCapabilityKind::ClientScriptExecution,
            &hash("other-snapshot"),
            Some("lab-stage3"),
        );
        let cross_target_id = cross_target.id.clone();
        state.research_capabilities.push(cross_target);
        let mut wrong_subject = capability(
            "browser-wrong-subject",
            "peritus.browser-client",
            ModuleResearchCapabilityKind::ClientScriptExecution,
            &snapshot,
            Some("lab-stage3"),
        );
        wrong_subject.subject =
            identity(ModuleResearchIdentityKind::Subject, "service:unrelated-subject");
        state.research_capabilities.push(wrong_subject);
        let mut wrong_authority = capability(
            "browser-wrong-authority",
            "peritus.browser-client",
            ModuleResearchCapabilityKind::ClientScriptExecution,
            &snapshot,
            Some("lab-stage3"),
        );
        wrong_authority.authority_before =
            identity(ModuleResearchIdentityKind::Authority, "laboratory:lab-stage3:admin");
        state.research_capabilities.push(wrong_authority);
        build(&mut state, default_bounds(), BTreeSet::new()).unwrap();
        let graph = state.research_graphs.last().unwrap();
        let reasons =
            graph.edges.iter().filter_map(|edge| edge.rejection_reason).collect::<Vec<_>>();
        assert!(reasons.contains(&ModuleResearchGraphRejection::StaleTargetState));
        assert!(
            !graph
                .nodes
                .iter()
                .any(|node| { node.capability_id.as_deref() == Some(cross_target_id.as_str()) }),
            "a primitive from a different source snapshot must never enter the current graph"
        );
        assert!(reasons.contains(&ModuleResearchGraphRejection::IncompatibleSubject));
        assert!(reasons.contains(&ModuleResearchGraphRejection::IncompatibleAuthority));
        assert!(reasons.contains(&ModuleResearchGraphRejection::IncompatibleCapability));
        assert!(reasons.contains(&ModuleResearchGraphRejection::TemporalOnly));
        assert!(reasons.contains(&ModuleResearchGraphRejection::UnsupportedCycle), "{reasons:?}");
    }

    #[test]
    fn bounded_search_terminates_and_reports_truncation() {
        let mut state = state_with_capabilities();
        let bounds = ModuleResearchSearchBounds {
            maximum_nodes: 8,
            maximum_edges: 8,
            maximum_depth: 2,
            maximum_open_candidates: 1,
            maximum_cycles: 0,
            maximum_cost: 2,
        };
        let result = build(&mut state, bounds, BTreeSet::new()).unwrap();
        assert!(result.truncated);
        let graph = state.research_graphs.last().unwrap();
        assert!(graph.summary.truncated);
        assert!(graph.gaps.iter().any(|gap| gap.contains("bound")));
    }

    #[test]
    fn bounds_parser_accepts_only_the_hard_safe_range() {
        assert_eq!(parse_bounds("").unwrap(), default_bounds());
        let parsed = parse_bounds("nodes=64 edges=128 depth=4 open=16 cycles=1 cost=8").unwrap();
        assert_eq!(parsed.maximum_nodes, 64);
        assert_eq!(parsed.maximum_cycles, 1);
        assert!(parse_bounds("nodes=7").is_err());
        assert!(parse_bounds("depth=17").is_err());
        assert!(parse_bounds("unknown=1").is_err());
    }

    #[test]
    fn historical_graph_survives_catalog_reprojection() {
        let mut state = state_with_capabilities();
        let graph = build(&mut state, default_bounds(), BTreeSet::new()).unwrap();
        state.research_capabilities.clear();
        let directory = tempfile::tempdir().unwrap();
        let parameters = json!({"state_directory": directory.path()});
        crate::state::save(&parameters, &state).unwrap();
        let loaded = crate::state::load(&parameters).unwrap();
        assert!(loaded.research_capabilities.is_empty());
        assert_eq!(loaded.research_graphs.len(), 1);
        assert_eq!(loaded.research_graphs[0].id, graph.graph_id);
        assert_eq!(loaded.research_active_graph.as_deref(), Some(graph.graph_id.as_str()));
    }
}
