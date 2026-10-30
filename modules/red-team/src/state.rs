//! Small durable campaign checkpoint; large source and report bytes live in separate artifacts.

use crate::{Error, invalid, records::*};
use peritus_plugin_sdk::{
    MODULE_RESEARCH_CONTRACT_VERSION, ModuleAdapterCancelRequest, ModuleAdapterCatalog,
    ModuleAdapterCompleteRequest, ModuleAdapterExecuteRequest, ModuleAdapterExecutionReceipt,
    ModuleAdapterPreparationHandle, ModuleAdapterPrepareRequest, ModuleAdapterRemoveRequest,
    ModuleAdapterStatus, ModuleAdapterStatusRequest, ModuleAttackGraphObservation,
    ModuleBoundaryObservation, ModuleBrowserObservation, ModuleFileFuzzObservation,
    ModuleHttpApiObservation, ModuleIdentityAccessObservation, ModuleJobCancelRequest,
    ModuleJobLogRequest, ModuleJobReceipt, ModuleJobRequest, ModuleJobStatusRequest,
    ModuleLaboratoryCatalog, ModuleLaboratoryCreateRequest, ModuleLaboratoryInvokeRequest,
    ModuleLaboratoryLifecycleRequest, ModuleLaboratoryReceipt, ModuleLaboratorySourceCreateRequest,
    ModuleLaboratoryStatus, ModulePatchReceipt, ModuleResearchArtifactClassification,
    ModuleResearchArtifactIdentity, ModuleResearchCapabilityDisposition,
    ModuleResearchCapabilityFact, ModuleResearchCapabilityKind, ModuleResearchCapabilityRecord,
    ModuleResearchChainDisposition, ModuleResearchDisclosurePackage, ModuleResearchDisclosureState,
    ModuleResearchEvidenceBoundary, ModuleResearchExperimentRecord,
    ModuleResearchGraphEdgeDisposition, ModuleResearchGraphRecord, ModuleResearchIdentity,
    ModuleResearchIdentityKind, ModuleResearchPocBundle, ModuleResearchPocState,
    ModuleResearchRepairBundle, ModuleResearchRepairState, ModuleSourceAnalysisObservation,
    ModuleWorkflowObservation, ScopedSourceAuthority, ScopedSourceEntry, ScopedSourceHandle,
    ScopedSourceVerification, ScopedSourceVerifyRequest,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

pub(crate) const STATE_SCHEMA: u16 = 19;
pub(crate) const PHASE: u8 = 22;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct State {
    pub(crate) schema: u16,
    pub(crate) phase: u8,
    pub(crate) module_version: String,
    pub(crate) checkpoint: Option<SkeletonCheckpoint>,
    pub(crate) campaign: CampaignRecord,
    pub(crate) scopes: Vec<ScopeRevisionRecord>,
    pub(crate) snapshots: Vec<SourceSnapshotRecord>,
    pub(crate) coverage: Vec<CoverageRecord>,
    #[serde(default)]
    pub(crate) target_profiles: Vec<TargetProfileRecord>,
    #[serde(default)]
    pub(crate) application_components: Vec<ApplicationComponentRecord>,
    #[serde(default)]
    pub(crate) application_surfaces: Vec<ApplicationSurfaceRecord>,
    #[serde(default)]
    pub(crate) trust_boundaries: Vec<TrustBoundaryRecord>,
    #[serde(default)]
    pub(crate) identity_configurations: Vec<IdentityConfigurationRecord>,
    #[serde(default)]
    pub(crate) security_properties: Vec<SecurityPropertyRecord>,
    #[serde(default)]
    pub(crate) methods: Vec<MethodRecord>,
    #[serde(default)]
    pub(crate) coverage_cells: Vec<CoverageCellRecord>,
    #[serde(default)]
    pub(crate) adapter_catalog: Option<ModuleAdapterCatalog>,
    #[serde(default)]
    pub(crate) adapter_preparation: Option<ModuleAdapterPreparationHandle>,
    #[serde(default)]
    pub(crate) adapter_statuses: Vec<ModuleAdapterStatus>,
    #[serde(default)]
    pub(crate) adapter_receipts: Vec<ModuleAdapterExecutionReceipt>,
    #[serde(default)]
    pub(crate) adapter_errors: Vec<String>,
    #[serde(default)]
    pub(crate) analysis_observations: Vec<ModuleSourceAnalysisObservation>,
    #[serde(default)]
    pub(crate) analysis_evidence: Vec<EvidenceRecord>,
    #[serde(default)]
    pub(crate) api_observations: Vec<ModuleHttpApiObservation>,
    #[serde(default)]
    pub(crate) api_evidence: Vec<EvidenceRecord>,
    #[serde(default)]
    pub(crate) browser_observations: Vec<ModuleBrowserObservation>,
    #[serde(default)]
    pub(crate) browser_evidence: Vec<EvidenceRecord>,
    #[serde(default)]
    pub(crate) identity_observations: Vec<ModuleIdentityAccessObservation>,
    #[serde(default)]
    pub(crate) identity_evidence: Vec<EvidenceRecord>,
    #[serde(default)]
    pub(crate) file_fuzz_observations: Vec<ModuleFileFuzzObservation>,
    #[serde(default)]
    pub(crate) file_fuzz_evidence: Vec<EvidenceRecord>,
    #[serde(default)]
    pub(crate) workflow_observations: Vec<ModuleWorkflowObservation>,
    #[serde(default)]
    pub(crate) workflow_evidence: Vec<EvidenceRecord>,
    #[serde(default)]
    pub(crate) boundary_observations: Vec<ModuleBoundaryObservation>,
    #[serde(default)]
    pub(crate) boundary_evidence: Vec<EvidenceRecord>,
    #[serde(default)]
    pub(crate) attack_graph_observations: Vec<ModuleAttackGraphObservation>,
    #[serde(default)]
    pub(crate) attack_graph_evidence: Vec<EvidenceRecord>,
    /// Integrity digest over the additive v2 research collections below.
    #[serde(default)]
    pub(crate) research_records_digest: String,
    /// Durable bounded experiment lifecycles emitted by Stage 4 and retained across recovery.
    #[serde(default)]
    pub(crate) research_experiments: Vec<ModuleResearchExperimentRecord>,
    /// Recoverable Stage 4 control-plane state. Evidence remains in the integrity-bound records.
    #[serde(default)]
    pub(crate) research_autonomy: ResearchAutonomyState,
    /// Deterministically projected receipt-backed primitives and explicit rejected candidates.
    #[serde(default)]
    pub(crate) research_capabilities: Vec<ModuleResearchCapabilityRecord>,
    /// Additive graph-v2 records. Existing graph-v1 observations remain separate above.
    #[serde(default)]
    pub(crate) research_graphs: Vec<ModuleResearchGraphRecord>,
    /// UI selection for the most recently built or reselected graph; this is not evidence.
    #[serde(default)]
    pub(crate) research_active_graph: Option<String>,
    /// Owner-only artifact metadata retained by v2 records.
    #[serde(default)]
    pub(crate) research_artifacts: Vec<ModuleResearchArtifactIdentity>,
    /// Safe private PoC bundles generated after fresh replay and independent skepticism.
    #[serde(default)]
    pub(crate) research_poc_bundles: Vec<ModuleResearchPocBundle>,
    /// Copy-only root-cause patch and regression bundles produced from verified PoCs.
    #[serde(default)]
    pub(crate) research_repair_bundles: Vec<ModuleResearchRepairBundle>,
    /// Private disclosure packages retained through owner-local export only.
    #[serde(default)]
    pub(crate) research_disclosure_packages: Vec<ModuleResearchDisclosurePackage>,
    #[serde(default)]
    pub(crate) application_observations: Vec<crate::application_binding::ApplicationCampaign>,
    #[serde(default)]
    pub(crate) application_evidence: Vec<EvidenceRecord>,
    #[serde(default)]
    pub(crate) application_campaign_pending: bool,
    #[serde(default)]
    pub(crate) laboratory_catalog: Option<ModuleLaboratoryCatalog>,
    #[serde(default)]
    pub(crate) laboratory_statuses: Vec<ModuleLaboratoryStatus>,
    #[serde(default)]
    pub(crate) laboratory_receipts: Vec<ModuleLaboratoryReceipt>,
    #[serde(default)]
    pub(crate) laboratory_errors: Vec<String>,
    #[serde(default)]
    pub(crate) runtime_targets: Vec<RuntimeTargetBinding>,
    pub(crate) hypotheses: Vec<HypothesisRecord>,
    pub(crate) observations: Vec<SourceObservation>,
    #[serde(default)]
    pub(crate) jobs: Vec<JobRecord>,
    #[serde(default)]
    pub(crate) job_receipts: Vec<ModuleJobReceipt>,
    #[serde(default)]
    pub(crate) job_evidence: Vec<EvidenceRecord>,
    #[serde(default)]
    pub(crate) findings: Vec<FindingRecord>,
    #[serde(default)]
    pub(crate) patches: Vec<PatchRecord>,
    #[serde(default)]
    pub(crate) patch_receipts: Vec<ModulePatchReceipt>,
    #[serde(default)]
    pub(crate) reviews: Vec<ReviewRecord>,
    pub(crate) reports: Vec<ReportRecord>,
    pub(crate) pending: Option<PendingRequest>,
    #[serde(default)]
    pub(crate) investigation: InvestigationState,
    #[serde(default)]
    pub(crate) repair: RepairState,
    #[serde(default)]
    pub(crate) original_verification: Option<ScopedSourceVerification>,
    #[serde(default)]
    pub(crate) journey: JourneyState,
}

/// Module-owned launch metadata for one generic host laboratory identity.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeTarget {
    pub(crate) application_path: String,
    pub(crate) service_path: String,
}

/// Durable association between an opaque generic laboratory and module-owned target metadata.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeTargetBinding {
    pub(crate) laboratory_id: String,
    pub(crate) target: RuntimeTarget,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum JourneyStage {
    #[default]
    Inactive,
    Running,
    Paused,
    Blocked,
    CleaningUp,
    Complete,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum JourneyStepState {
    #[default]
    Planned,
    Waiting,
    Complete,
    Skipped,
    Blocked,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JourneyCounters {
    pub(crate) scopes: usize,
    pub(crate) adapter_statuses: usize,
    pub(crate) adapter_receipts: usize,
    pub(crate) adapter_errors: usize,
    pub(crate) observations: usize,
    pub(crate) laboratory_statuses: usize,
    pub(crate) laboratory_receipts: usize,
    pub(crate) laboratory_errors: usize,
    pub(crate) reports: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JourneyStep {
    pub(crate) id: String,
    pub(crate) label: String,
    pub(crate) command: String,
    pub(crate) state: JourneyStepState,
    #[serde(default)]
    pub(crate) laboratory_alias: Option<String>,
    #[serde(default)]
    pub(crate) baseline: JourneyCounters,
    #[serde(default)]
    pub(crate) detail: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JourneyLaboratory {
    pub(crate) alias: String,
    pub(crate) laboratory_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JourneyState {
    pub(crate) schema: u16,
    pub(crate) stage: JourneyStage,
    pub(crate) source_snapshot: String,
    pub(crate) cursor: usize,
    pub(crate) steps: Vec<JourneyStep>,
    pub(crate) laboratories: Vec<JourneyLaboratory>,
    pub(crate) steering: Vec<String>,
    pub(crate) failures: Vec<String>,
}

impl Default for JourneyState {
    fn default() -> Self {
        Self {
            schema: 1,
            stage: JourneyStage::Inactive,
            source_snapshot: String::new(),
            cursor: 0,
            steps: Vec::new(),
            laboratories: Vec::new(),
            steering: Vec::new(),
            failures: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RepairStage {
    #[default]
    NotStarted,
    Planning,
    Replaying,
    Reviewing,
    VerifyingOriginal,
    Complete,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PatchCaseCategory {
    Attack,
    Legitimate,
    Malformed,
    Adjacent,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PatchCaseState {
    Planned,
    Running,
    Passed,
    Failed,
    Blocked,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PatchCasePlan {
    pub(crate) id: String,
    pub(crate) category: PatchCaseCategory,
    pub(crate) attacker_input: String,
    pub(crate) expected_stdout_fragment: String,
    pub(crate) state: PatchCaseState,
    pub(crate) host_job_id: Option<String>,
    pub(crate) evidence: Option<RecordId>,
    pub(crate) detail: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PatchPlan {
    pub(crate) finding_id: String,
    pub(crate) root_cause: String,
    pub(crate) target_path: String,
    pub(crate) expected_source_digest: String,
    pub(crate) replacement: String,
    pub(crate) prerequisites: Vec<String>,
    pub(crate) dependencies: Vec<String>,
    pub(crate) order: u32,
    pub(crate) cases: Vec<PatchCasePlan>,
    pub(crate) patch_digest: Option<String>,
    pub(crate) diff_artifact: Option<String>,
    pub(crate) diff_bytes: Option<Vec<u8>>,
    pub(crate) review_id: Option<RecordId>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RepairState {
    pub(crate) stage: RepairStage,
    pub(crate) round: u64,
    pub(crate) plans: Vec<PatchPlan>,
    pub(crate) active_finding: Option<String>,
    pub(crate) feedback: String,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum InvestigationStage {
    #[default]
    NotStarted,
    Inventory,
    Discovery,
    Probing,
    Skeptic,
    Complete,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HypothesisOrigin {
    KnownDescription,
    UnknownDiscovery,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InventoryRecord {
    pub(crate) surfaces: Vec<String>,
    pub(crate) threat_boundaries: Vec<String>,
    pub(crate) routes: Vec<FamilyRoute>,
    pub(crate) source_observations: Vec<RecordId>,
    #[serde(default)]
    pub(crate) profiles: Vec<RecordId>,
    #[serde(default)]
    pub(crate) components: Vec<RecordId>,
    #[serde(default)]
    pub(crate) surface_records: Vec<RecordId>,
    #[serde(default)]
    pub(crate) boundary_records: Vec<RecordId>,
    #[serde(default)]
    pub(crate) identity_configurations: Vec<RecordId>,
    #[serde(default)]
    pub(crate) security_properties: Vec<RecordId>,
    #[serde(default)]
    pub(crate) methods: Vec<RecordId>,
    #[serde(default)]
    pub(crate) coverage_cells: Vec<RecordId>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FamilyRoute {
    #[serde(default)]
    pub(crate) profile: String,
    pub(crate) family: String,
    pub(crate) state: CoverageState,
    pub(crate) reason: String,
    pub(crate) surfaces: Vec<String>,
    #[serde(default)]
    pub(crate) identities: Vec<String>,
    #[serde(default)]
    pub(crate) properties: Vec<String>,
    #[serde(default)]
    pub(crate) methods: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HypothesisPlan {
    pub(crate) hypothesis_id: String,
    pub(crate) family: String,
    pub(crate) origin: HypothesisOrigin,
    pub(crate) source_evidence: Vec<RecordId>,
    /// Generic disposable-laboratory runtime for source manifests and interpreted entry points.
    /// Older retained plans omit this and continue through the direct executable worker.
    #[serde(default)]
    pub(crate) runtime: Option<String>,
    pub(crate) target_path: Option<String>,
    /// Exact literal argv delivered after the module-owned runtime launcher.
    /// `{{PERITUS_CANARY}}` is replaced only inside this private plan at execution time.
    #[serde(default)]
    pub(crate) arguments: Vec<String>,
    /// Optional exact stdin template. `{{PERITUS_CANARY}}` has the same private substitution
    /// semantics as it does in `arguments`.
    #[serde(default)]
    pub(crate) stdin: Option<String>,
    /// Exact literal environment delivered to the disposable process. Values stay in private
    /// campaign state; reports retain only names and digests. `{{PERITUS_CANARY}}` has the same
    /// private substitution semantics as it does in `arguments` and `stdin`.
    #[serde(default)]
    pub(crate) environment: BTreeMap<String, String>,
    /// Compatibility field for plans retained before argv vectors were introduced.
    #[serde(default)]
    pub(crate) attacker_input: Option<String>,
    pub(crate) changed_dimension: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProbeState {
    Planned,
    Running,
    Completed,
    Blocked,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProbeAttempt {
    pub(crate) id: String,
    pub(crate) hypothesis_id: String,
    pub(crate) target_path: String,
    #[serde(default)]
    pub(crate) arguments: Vec<String>,
    #[serde(default)]
    pub(crate) stdin_digest: Option<String>,
    /// Environment values are deliberately absent from report-facing probe records.
    #[serde(default)]
    pub(crate) environment_digests: BTreeMap<String, String>,
    /// Compatibility summary for older reports and retained state.
    #[serde(default)]
    pub(crate) attacker_input: String,
    pub(crate) changed_dimension: String,
    pub(crate) state: ProbeState,
    pub(crate) host_job_id: Option<String>,
    pub(crate) evidence: Option<RecordId>,
    pub(crate) detail: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QueuedRead {
    pub(crate) path: String,
    pub(crate) offset: u64,
    pub(crate) maximum_bytes: u64,
    pub(crate) reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProviderRouteRecord {
    pub(crate) role: String,
    pub(crate) provider: String,
    pub(crate) model: String,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ResearchAutonomyPhase {
    #[default]
    Inactive,
    Proposing,
    Executing,
    Paused,
    Complete,
    Cancelled,
    Blocked,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ResearchRole {
    #[default]
    Reconnaissance,
    PrimitiveHunter,
    ChainBuilder,
    ExploitEngineer,
    Mutation,
    Skeptic,
    PatchEngineer,
    PatchReviewer,
    DisclosureWriter,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResearchBudgets {
    pub(crate) maximum_model_turns: u16,
    pub(crate) maximum_experiments: u16,
    pub(crate) maximum_cost: u32,
}

impl Default for ResearchBudgets {
    fn default() -> Self {
        Self { maximum_model_turns: 12, maximum_experiments: 8, maximum_cost: 16 }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ResearchProposalDisposition {
    Admitted,
    Running,
    Observed,
    Rejected,
    Blocked,
    Cancelled,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResearchProposal {
    pub(crate) id: String,
    pub(crate) experiment_id: String,
    pub(crate) role: ResearchRole,
    #[serde(default)]
    pub(crate) specification_id: Option<String>,
    pub(crate) adapter_operation: String,
    pub(crate) changed_dimension: String,
    pub(crate) required_capability: ModuleResearchCapabilityKind,
    pub(crate) novelty: u16,
    pub(crate) cost: u32,
    pub(crate) created_turn: u16,
    pub(crate) rationale_digest: String,
    #[serde(default)]
    pub(crate) baseline_capabilities: Vec<String>,
    pub(crate) disposition: ResearchProposalDisposition,
    pub(crate) detail: String,
}

/// One explicit selection of an inert public-knowledge recipe for future model turns.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResearchRecipeSeed {
    pub(crate) schema: u16,
    pub(crate) recipe_id: String,
    pub(crate) recipe_digest: String,
    pub(crate) evidence_class: peritus_plugin_sdk::ModuleResearchEmulationEvidenceClass,
    pub(crate) selected_turn: u16,
    pub(crate) selection_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResearchAutonomyState {
    pub(crate) schema: u16,
    pub(crate) phase: ResearchAutonomyPhase,
    pub(crate) campaign_id: String,
    pub(crate) graph_id: String,
    pub(crate) target_digest: String,
    pub(crate) role_index: usize,
    pub(crate) turn: u16,
    pub(crate) budgets: ResearchBudgets,
    pub(crate) experiments_started: u16,
    pub(crate) cost_spent: u32,
    pub(crate) frontier: Vec<ResearchProposal>,
    #[serde(default)]
    pub(crate) active_experiment: Option<String>,
    #[serde(default)]
    pub(crate) steering: Vec<String>,
    #[serde(default)]
    pub(crate) preferred_operations: Vec<String>,
    #[serde(default)]
    pub(crate) excluded_operations: Vec<String>,
    #[serde(default)]
    pub(crate) failures: Vec<String>,
    #[serde(default)]
    pub(crate) provider_routes: Vec<ProviderRouteRecord>,
    /// Explicit inert recipe selections. These guide future proposals but are never evidence.
    #[serde(default)]
    pub(crate) recipe_seeds: Vec<ResearchRecipeSeed>,
}

impl Default for ResearchAutonomyState {
    fn default() -> Self {
        Self {
            schema: MODULE_RESEARCH_CONTRACT_VERSION,
            phase: ResearchAutonomyPhase::Inactive,
            campaign_id: String::new(),
            graph_id: String::new(),
            target_digest: String::new(),
            role_index: 0,
            turn: 0,
            budgets: ResearchBudgets::default(),
            experiments_started: 0,
            cost_spent: 0,
            frontier: Vec::new(),
            active_experiment: None,
            steering: Vec::new(),
            preferred_operations: Vec::new(),
            excluded_operations: Vec::new(),
            failures: Vec::new(),
            provider_routes: Vec::new(),
            recipe_seeds: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReuseMeasurements {
    pub(crate) manifest_pages: u64,
    pub(crate) source_reads_requested: u64,
    pub(crate) source_reads_reused: u64,
    pub(crate) builds_reused: u64,
    pub(crate) probes_repeated: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InvestigationState {
    pub(crate) stage: InvestigationStage,
    pub(crate) paused: bool,
    pub(crate) round: u64,
    pub(crate) manifest_entries: Vec<ScopedSourceEntry>,
    pub(crate) manifest_complete: bool,
    pub(crate) inventory: Option<InventoryRecord>,
    pub(crate) hypothesis_plans: Vec<HypothesisPlan>,
    pub(crate) probes: Vec<ProbeAttempt>,
    pub(crate) queued_read: Option<QueuedRead>,
    #[serde(default)]
    pub(crate) queued_reads: Vec<QueuedRead>,
    #[serde(default)]
    pub(crate) batch_read_active: bool,
    pub(crate) steering: Vec<String>,
    pub(crate) feedback: String,
    pub(crate) provider_routes: Vec<ProviderRouteRecord>,
    pub(crate) skill_digest: String,
    pub(crate) reuse: ReuseMeasurements,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SkeletonCheckpoint {
    pub(crate) key: String,
    pub(crate) acknowledged: bool,
    pub(crate) host_profile_schema: u16,
    pub(crate) observed_capabilities: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ObservationState {
    Current,
    Invalidated,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceObservation {
    pub(crate) record: EvidenceRecord,
    pub(crate) snapshot_digest: String,
    pub(crate) path: String,
    pub(crate) source_digest: String,
    pub(crate) source_bytes: u64,
    pub(crate) range_start: u64,
    pub(crate) range_end: u64,
    #[serde(default)]
    pub(crate) retained_path: Option<String>,
    pub(crate) state: ObservationState,
    pub(crate) invalidated_by: Option<String>,
    pub(crate) reuse_count: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum PendingRequest {
    AdapterCatalog {
        key: String,
        install_after: bool,
        complete_after: bool,
        #[serde(default)]
        adapter_id: Option<String>,
    },
    AdapterPrepare {
        key: String,
        request: ModuleAdapterPrepareRequest,
        complete_after: bool,
    },
    AdapterComplete {
        key: String,
        request: ModuleAdapterCompleteRequest,
    },
    AdapterCancel {
        key: String,
        request: ModuleAdapterCancelRequest,
    },
    AdapterStatus {
        key: String,
        request: ModuleAdapterStatusRequest,
    },
    AdapterRemove {
        key: String,
        request: ModuleAdapterRemoveRequest,
    },
    AdapterExecute {
        key: String,
        request: ModuleAdapterExecuteRequest,
    },
    ResearchExperimentExecute {
        key: String,
        experiment_id: String,
        request: ModuleAdapterExecuteRequest,
    },
    LaboratoryCatalog {
        key: String,
    },
    LaboratoryCreate {
        key: String,
        request: ModuleLaboratoryCreateRequest,
    },
    LaboratorySourceCreate {
        key: String,
        request: ModuleLaboratorySourceCreateRequest,
        #[serde(default)]
        target: Option<RuntimeTarget>,
    },
    LaboratoryLifecycle {
        key: String,
        operation: String,
        request: ModuleLaboratoryLifecycleRequest,
    },
    LaboratoryInvoke {
        key: String,
        request: ModuleLaboratoryInvokeRequest,
    },
    Capture {
        key: String,
        exclusions: Vec<String>,
        refresh: Option<ScopedSourceAuthority>,
    },
    Manifest {
        key: String,
        authority: ScopedSourceAuthority,
        #[serde(default)]
        after: Option<String>,
        #[serde(default = "default_manifest_entries")]
        maximum_entries: u16,
    },
    Read {
        key: String,
        authority: ScopedSourceAuthority,
        path: String,
        offset: u64,
        maximum_bytes: u64,
    },
    DisclosureManifest {
        key: String,
        repair_bundle_id: String,
        authority: ScopedSourceAuthority,
        #[serde(default)]
        after: Option<String>,
        #[serde(default)]
        candidates: Vec<ScopedSourceEntry>,
    },
    DisclosureContactRead {
        key: String,
        repair_bundle_id: String,
        authority: ScopedSourceAuthority,
        expected: ScopedSourceEntry,
    },
    Revoke {
        key: String,
        authority: ScopedSourceAuthority,
    },
    JobSubmit {
        key: String,
        request: ModuleJobRequest,
    },
    JobPoll {
        key: String,
        request: ModuleJobStatusRequest,
    },
    JobLog {
        key: String,
        request: ModuleJobLogRequest,
    },
    JobCancel {
        key: String,
        request: ModuleJobCancelRequest,
    },
    SourceVerify {
        key: String,
        request: ScopedSourceVerifyRequest,
    },
}

const fn default_manifest_entries() -> u16 {
    100
}

impl PendingRequest {
    pub(crate) fn key(&self) -> &str {
        match self {
            Self::AdapterCatalog { key, .. }
            | Self::AdapterPrepare { key, .. }
            | Self::AdapterComplete { key, .. }
            | Self::AdapterCancel { key, .. }
            | Self::AdapterStatus { key, .. }
            | Self::AdapterRemove { key, .. }
            | Self::AdapterExecute { key, .. }
            | Self::ResearchExperimentExecute { key, .. }
            | Self::LaboratoryCatalog { key }
            | Self::LaboratoryCreate { key, .. }
            | Self::LaboratorySourceCreate { key, .. }
            | Self::LaboratoryLifecycle { key, .. }
            | Self::LaboratoryInvoke { key, .. }
            | Self::Capture { key, .. }
            | Self::Manifest { key, .. }
            | Self::Read { key, .. }
            | Self::DisclosureManifest { key, .. }
            | Self::DisclosureContactRead { key, .. }
            | Self::Revoke { key, .. }
            | Self::JobSubmit { key, .. }
            | Self::JobPoll { key, .. }
            | Self::JobLog { key, .. }
            | Self::JobCancel { key, .. }
            | Self::SourceVerify { key, .. } => key,
        }
    }
}

impl Default for State {
    fn default() -> Self {
        let campaign_id =
            RecordId::new(RecordKind::Campaign, "campaign-main").expect("static campaign identity");
        Self {
            schema: STATE_SCHEMA,
            phase: PHASE,
            module_version: env!("CARGO_PKG_VERSION").into(),
            checkpoint: None,
            campaign: CampaignRecord {
                schema: RECORD_SCHEMA_VERSION,
                id: campaign_id,
                state: CampaignState::Draft,
                scope_revision: None,
                source_snapshot: None,
                supersedes: None,
            },
            scopes: Vec::new(),
            snapshots: Vec::new(),
            coverage: Vec::new(),
            target_profiles: Vec::new(),
            application_components: Vec::new(),
            application_surfaces: Vec::new(),
            trust_boundaries: Vec::new(),
            identity_configurations: Vec::new(),
            security_properties: Vec::new(),
            methods: Vec::new(),
            coverage_cells: Vec::new(),
            adapter_catalog: None,
            adapter_preparation: None,
            adapter_statuses: Vec::new(),
            adapter_receipts: Vec::new(),
            adapter_errors: Vec::new(),
            analysis_observations: Vec::new(),
            analysis_evidence: Vec::new(),
            api_observations: Vec::new(),
            api_evidence: Vec::new(),
            browser_observations: Vec::new(),
            browser_evidence: Vec::new(),
            identity_observations: Vec::new(),
            identity_evidence: Vec::new(),
            file_fuzz_observations: Vec::new(),
            file_fuzz_evidence: Vec::new(),
            workflow_observations: Vec::new(),
            workflow_evidence: Vec::new(),
            boundary_observations: Vec::new(),
            boundary_evidence: Vec::new(),
            attack_graph_observations: Vec::new(),
            attack_graph_evidence: Vec::new(),
            research_records_digest: String::new(),
            research_experiments: Vec::new(),
            research_autonomy: ResearchAutonomyState::default(),
            research_capabilities: Vec::new(),
            research_graphs: Vec::new(),
            research_active_graph: None,
            research_artifacts: Vec::new(),
            research_poc_bundles: Vec::new(),
            research_repair_bundles: Vec::new(),
            research_disclosure_packages: Vec::new(),
            application_observations: Vec::new(),
            application_evidence: Vec::new(),
            application_campaign_pending: false,
            laboratory_catalog: None,
            laboratory_statuses: Vec::new(),
            laboratory_receipts: Vec::new(),
            laboratory_errors: Vec::new(),
            runtime_targets: Vec::new(),
            hypotheses: Vec::new(),
            observations: Vec::new(),
            jobs: Vec::new(),
            job_receipts: Vec::new(),
            job_evidence: Vec::new(),
            findings: Vec::new(),
            patches: Vec::new(),
            patch_receipts: Vec::new(),
            reviews: Vec::new(),
            reports: Vec::new(),
            pending: None,
            investigation: InvestigationState::default(),
            repair: RepairState::default(),
            original_verification: None,
            journey: JourneyState::default(),
        }
    }
}

impl State {
    pub(crate) fn active_handle(&self) -> Option<ScopedSourceAuthority> {
        let snapshot = self.snapshots.last()?;
        let scope = self.scopes.last()?;
        Some(ScopedSourceAuthority {
            handle: snapshot.source_handle.clone(),
            scope_revision: scope.id.value.clone(),
        })
    }

    pub(crate) fn active_snapshot(&self) -> Option<&SourceSnapshotRecord> {
        self.snapshots.last()
    }

    pub(crate) fn current_observations(&self) -> impl Iterator<Item = &SourceObservation> {
        self.observations
            .iter()
            .filter(|observation| observation.state == ObservationState::Current)
    }

    pub(crate) fn admit_scope(&mut self, handle: &ScopedSourceHandle) -> Result<(), Error> {
        let scope_id = RecordId::new(RecordKind::ScopeRevision, handle.scope_revision.clone())
            .map_err(invalid)?;
        let snapshot_id = RecordId::new(
            RecordKind::SourceSnapshot,
            format!("snapshot-{}", &handle.snapshot_digest[..16]),
        )
        .map_err(invalid)?;
        let prior_scope = self.scopes.last().map(|record| record.id.clone());
        let scope = ScopeRevisionRecord {
            schema: RECORD_SCHEMA_VERSION,
            id: scope_id.clone(),
            campaign: self.campaign.id.clone(),
            revision: u64::try_from(self.scopes.len())
                .map_err(|_| invalid("scope history is too large"))?
                .checked_add(1)
                .ok_or_else(|| invalid("scope revision overflow"))?,
            source_label: handle.display_name.clone(),
            attacker_model: "The selected source authority permits literal input only to module-owned contained proof adapters."
                .into(),
            allowed_effects: vec![
                "inert_source_capture".into(),
                "bounded_source_read".into(),
                "credential_free_dependency_preparation".into(),
                "contained_canary_disclosure_proof".into(),
                "allowlisted_managed_adapter_runtime".into(),
                "bounded_immutable_source_analysis".into(),
                "host_owned_disposable_application_laboratory".into(),
                "host_captured_http_api_campaign".into(),
                "host_captured_isolated_browser_campaign".into(),
                "host_private_identity_and_access_campaign".into(),
                "host_owned_file_archive_parser_and_native_fault_campaign".into(),
                "host_owned_private_network_tls_policy_and_authority_campaign".into(),
                "host_owned_cross_adapter_attack_graph_and_copy_repair".into(),
            ],
            exclusions: handle.exclusions.clone(),
            supersedes: prior_scope,
        };
        let snapshot = SourceSnapshotRecord {
            schema: RECORD_SCHEMA_VERSION,
            id: snapshot_id.clone(),
            campaign: self.campaign.id.clone(),
            scope_revision: scope_id.clone(),
            source_handle: handle.handle.clone(),
            snapshot_digest: handle.snapshot_digest.clone(),
            manifest_artifact: handle.manifest_artifact.clone(),
        };
        let changed = handle
            .changed_paths
            .iter()
            .chain(&handle.removed_paths)
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        for observation in &mut self.observations {
            if observation.state != ObservationState::Current {
                continue;
            }
            if changed.contains(observation.path.as_str()) {
                observation.state = ObservationState::Invalidated;
                observation.invalidated_by = Some(handle.snapshot_digest.clone());
            } else {
                observation.snapshot_digest = handle.snapshot_digest.clone();
                observation.record.scope_revision = scope_id.clone();
                observation.record.dependencies = vec![snapshot_id.clone()];
            }
        }
        let retained_inventory = self.investigation.inventory.clone();
        let retained_graph = !self.coverage_cells.is_empty();
        self.scopes.push(scope);
        self.snapshots.push(snapshot);
        self.campaign.scope_revision = Some(scope_id.clone());
        self.campaign.source_snapshot = Some(snapshot_id);
        self.campaign.state = CampaignState::Active;
        crate::coverage::initialize_methods(self);
        if retained_graph {
            crate::coverage::refresh_scope(
                self,
                &scope_id,
                &handle.snapshot_digest,
                &handle.changed_paths,
                &handle.removed_paths,
            );
        }
        self.investigation = InvestigationState::default();
        if retained_graph {
            self.investigation.inventory = retained_inventory;
            self.investigation.stage = InvestigationStage::Inventory;
            self.investigation.feedback = "The prior target graph was retained. Recompile the bounded inventory against the refreshed manifest; only cells whose source dependencies changed were invalidated.".into();
        }
        self.repair = RepairState::default();
        self.research_autonomy = ResearchAutonomyState::default();
        self.research_active_graph = None;
        self.original_verification = None;
        self.journey = JourneyState::default();
        if !retained_graph {
            self.coverage = security_families()
                .into_iter()
                .enumerate()
                .map(|(index, family)| CoverageRecord {
                    schema: RECORD_SCHEMA_VERSION,
                    id: RecordId::new(
                        RecordKind::Coverage,
                        format!("coverage-{}-{index}", &handle.snapshot_digest[..12]),
                    )
                    .expect("generated coverage identity"),
                    campaign: self.campaign.id.clone(),
                    scope_revision: scope_id.clone(),
                    family: family.into(),
                    surface: "whole_application".into(),
                    state: CoverageState::Unexamined,
                    reason: "The source boundary is retained; broad investigation has not begun."
                        .into(),
                    evidence: Vec::new(),
                    supersedes: None,
                })
                .collect();
        }
        Ok(())
    }
}

pub(crate) fn load(parameters: &serde_json::Value) -> Result<State, Error> {
    let path = state_path(parameters)?;
    let (mut state, migrated) = match fs::read(&path) {
        Ok(bytes) => {
            let state = serde_json::from_slice(&bytes).map_err(|error| {
                invalid(format!(
                    "durable Red Team state is unreadable ({error}); the original bytes remain unchanged at {}. Restore or inspect that file before retrying; no empty campaign was substituted",
                    path.display()
                ))
            })?;
            (state, false)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            (migrate_phase_twenty(parameters)?, true)
        }
        Err(error) => return Err(error.into()),
    };
    if state.schema != STATE_SCHEMA || state.phase != PHASE {
        return Err(invalid(format!(
            "unsupported Red Team state schema {} phase {}",
            state.schema, state.phase
        )));
    }
    if !migrated {
        validate_research_state(&state)?;
    }
    state.module_version = env!("CARGO_PKG_VERSION").into();
    if state.active_snapshot().is_some() {
        crate::coverage::initialize_methods(&mut state);
    }
    if migrated {
        state.research_records_digest = research_records_digest(&state)?;
        publish_state(&path, &state)?;
    }
    Ok(state)
}

pub(crate) fn save(parameters: &serde_json::Value, state: &State) -> Result<(), Error> {
    publish_state(&state_path(parameters)?, state)
}

pub(crate) fn private_root(parameters: &serde_json::Value) -> Result<PathBuf, Error> {
    let directory = parameters["state_directory"]
        .as_str()
        .ok_or_else(|| invalid("host did not provide a private state directory"))?;
    Ok(Path::new(directory).to_path_buf())
}

pub(crate) fn publish(path: &Path, value: &impl Serialize) -> Result<(), Error> {
    let parent = path.parent().ok_or_else(|| invalid("durable state path has no parent"))?;
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(&mut temporary, value)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[derive(Serialize)]
struct ResearchDigestView<'a> {
    schema: u16,
    experiments: &'a [ModuleResearchExperimentRecord],
    capabilities: &'a [ModuleResearchCapabilityRecord],
    graphs: &'a [ModuleResearchGraphRecord],
    artifacts: &'a [ModuleResearchArtifactIdentity],
    poc_bundles: &'a [ModuleResearchPocBundle],
    repair_bundles: &'a [ModuleResearchRepairBundle],
    disclosure_packages: &'a [ModuleResearchDisclosurePackage],
}

fn research_records_digest(state: &State) -> Result<String, Error> {
    let view = ResearchDigestView {
        schema: MODULE_RESEARCH_CONTRACT_VERSION,
        experiments: &state.research_experiments,
        capabilities: &state.research_capabilities,
        graphs: &state.research_graphs,
        artifacts: &state.research_artifacts,
        poc_bundles: &state.research_poc_bundles,
        repair_bundles: &state.research_repair_bundles,
        disclosure_packages: &state.research_disclosure_packages,
    };
    Ok(crate::digest(&serde_json::to_vec(&view)?))
}

fn publish_state(path: &Path, state: &State) -> Result<(), Error> {
    if state.schema != STATE_SCHEMA || state.phase != PHASE {
        return Err(invalid(format!(
            "refusing to publish unsupported Red Team state schema {} phase {}",
            state.schema, state.phase
        )));
    }
    let mut durable = state.clone();
    durable.research_records_digest = research_records_digest(&durable)?;
    validate_research_state(&durable)?;
    publish(path, &durable)
}

fn validate_research_state(state: &State) -> Result<(), Error> {
    let expected = research_records_digest(state)?;
    if state.research_records_digest != expected {
        return Err(invalid(format!(
            "Red Team research-record digest mismatch: expected {expected}; the durable file remains unchanged"
        )));
    }
    let mut experiment_ids = BTreeSet::new();
    for record in &state.research_experiments {
        validate_record_schema(record.schema, "experiment")?;
        validate_nonempty(&record.id, "experiment identity")?;
        if !experiment_ids.insert(record.id.as_str()) {
            return Err(invalid("experiment identities are duplicated"));
        }
        validate_identity_kind(&record.request, ModuleResearchIdentityKind::ExperimentRequest)?;
        validate_identity_kind(
            &record.role_implementation,
            ModuleResearchIdentityKind::RoleImplementation,
        )?;
        validate_identity_kind(&record.target, ModuleResearchIdentityKind::Target)?;
        validate_identity_kind(&record.authority, ModuleResearchIdentityKind::Authority)?;
        validate_identity_kind(&record.oracle, ModuleResearchIdentityKind::Oracle)?;
        validate_nonempty(&record.adapter_operation, "experiment adapter operation")?;
        validate_nonempty(&record.changed_dimension, "experiment changed dimension")?;
        for receipt in &record.receipts {
            validate_identity_kind(receipt, ModuleResearchIdentityKind::Receipt)?;
        }
        for artifact in &record.artifacts {
            validate_artifact(artifact)?;
        }
        match record.phase {
            peritus_plugin_sdk::ModuleResearchExperimentPhase::Observed => {
                if record.receipts.is_empty() {
                    return Err(invalid("observed experiment has no exact receipt"));
                }
            }
            peritus_plugin_sdk::ModuleResearchExperimentPhase::Proposed
            | peritus_plugin_sdk::ModuleResearchExperimentPhase::Admitted
            | peritus_plugin_sdk::ModuleResearchExperimentPhase::Running => {
                if !record.receipts.is_empty() {
                    return Err(invalid(
                        "unsettled experiment carries a receipt before observation",
                    ));
                }
            }
            peritus_plugin_sdk::ModuleResearchExperimentPhase::Rejected
            | peritus_plugin_sdk::ModuleResearchExperimentPhase::Blocked
            | peritus_plugin_sdk::ModuleResearchExperimentPhase::Cancelled
            | peritus_plugin_sdk::ModuleResearchExperimentPhase::Failed => {
                if record.limitations.is_empty() {
                    return Err(invalid(
                        "non-observed terminal experiment has no factual limitation",
                    ));
                }
            }
            peritus_plugin_sdk::ModuleResearchExperimentPhase::Superseded => {}
        }
    }
    for record in &state.research_capabilities {
        validate_record_schema(record.schema, "capability")?;
        validate_nonempty(&record.id, "capability identity")?;
        validate_nonempty(&record.adapter_id, "capability adapter identity")?;
        validate_nonempty(&record.adapter_version, "capability adapter version")?;
        validate_nonempty(&record.projection_version, "capability projection version")?;
        validate_identity_kind(&record.target, ModuleResearchIdentityKind::Target)?;
        validate_identity_kind(&record.subject, ModuleResearchIdentityKind::Subject)?;
        validate_identity_kind(&record.authority_before, ModuleResearchIdentityKind::Authority)?;
        validate_identity_kind(&record.authority_after, ModuleResearchIdentityKind::Authority)?;
        validate_identity_kind(&record.oracle, ModuleResearchIdentityKind::Oracle)?;
        validate_nonempty(&record.source_record, "capability source record")?;
        validate_nonempty(&record.detail, "capability detail")?;
        for fact in record.consumes.iter().chain(&record.produces) {
            validate_capability_fact(fact)?;
        }
        for receipt in &record.receipts {
            validate_identity_kind(receipt, ModuleResearchIdentityKind::Receipt)?;
        }
        match record.disposition {
            ModuleResearchCapabilityDisposition::Projected
            | ModuleResearchCapabilityDisposition::Admitted => {
                if record.rejection_reason.is_some()
                    || record.evidence_boundary == ModuleResearchEvidenceBoundary::Untrusted
                    || record.capability == ModuleResearchCapabilityKind::Unsupported
                    || record.receipts.is_empty()
                {
                    return Err(invalid(
                        "admitted capability has rejected, unsupported, untrusted, or receipt-free evidence",
                    ));
                }
            }
            ModuleResearchCapabilityDisposition::Rejected => {
                if record.rejection_reason.is_none()
                    || record.evidence_boundary != ModuleResearchEvidenceBoundary::Untrusted
                {
                    return Err(invalid(
                        "rejected capability is missing its stable reason or untrusted boundary",
                    ));
                }
            }
            ModuleResearchCapabilityDisposition::Blocked
            | ModuleResearchCapabilityDisposition::Superseded => {}
        }
    }
    for record in &state.research_graphs {
        validate_record_schema(record.schema, "graph-v2")?;
        validate_nonempty(&record.id, "graph-v2 identity")?;
        validate_identity_kind(&record.target, ModuleResearchIdentityKind::Target)?;
        validate_identity_kind(&record.builder, ModuleResearchIdentityKind::RoleImplementation)?;
        if record.bounds.maximum_nodes < 8
            || record.bounds.maximum_nodes > 4096
            || record.bounds.maximum_edges < 8
            || record.bounds.maximum_edges > 16384
            || record.bounds.maximum_depth < 2
            || record.bounds.maximum_depth > 16
            || record.bounds.maximum_open_candidates == 0
            || record.bounds.maximum_open_candidates > 4096
            || record.bounds.maximum_cycles > 4
            || record.bounds.maximum_cost < 2
            || record.bounds.maximum_cost > 64
            || record.nodes.len() > record.bounds.maximum_nodes as usize
            || record.edges.len() > record.bounds.maximum_edges as usize
        {
            return Err(invalid(
                "graph-v2 search bounds or retained collections are outside the safe range",
            ));
        }
        let mut excluded = BTreeSet::new();
        for capability in &record.excluded_capabilities {
            validate_nonempty(capability, "graph-v2 excluded capability")?;
            if !excluded.insert(capability.as_str()) {
                return Err(invalid("graph-v2 excluded capability identities are duplicated"));
            }
        }
        let mut nodes = BTreeSet::new();
        let mut capability_nodes = BTreeSet::new();
        for node in &record.nodes {
            validate_nonempty(&node.id, "graph-v2 node identity")?;
            validate_identity_kind(&node.target, ModuleResearchIdentityKind::Target)?;
            validate_nonempty(&node.label, "graph-v2 node label")?;
            if !nodes.insert(node.id.as_str()) {
                return Err(invalid("graph-v2 node identities are duplicated"));
            }
            if let Some(capability) = &node.capability_id {
                validate_nonempty(capability, "graph-v2 node capability identity")?;
                capability_nodes.insert(capability.as_str());
            }
        }
        let mut edges = BTreeMap::new();
        for edge in &record.edges {
            validate_nonempty(&edge.id, "graph-v2 edge identity")?;
            validate_nonempty(&edge.from, "graph-v2 edge source")?;
            validate_nonempty(&edge.to, "graph-v2 edge destination")?;
            validate_nonempty(&edge.detail, "graph-v2 edge detail")?;
            validate_identity_kind(&edge.relation, ModuleResearchIdentityKind::GraphRelation)?;
            if !nodes.contains(edge.from.as_str()) || !nodes.contains(edge.to.as_str()) {
                return Err(invalid("graph-v2 edge references an unknown node"));
            }
            if edges.insert(edge.id.as_str(), edge.disposition).is_some() {
                return Err(invalid("graph-v2 edge identities are duplicated"));
            }
            for receipt in &edge.receipts {
                validate_identity_kind(receipt, ModuleResearchIdentityKind::Receipt)?;
            }
            match edge.disposition {
                ModuleResearchGraphEdgeDisposition::Rejected => {
                    if edge.rejection_reason.is_none() {
                        return Err(invalid("rejected graph-v2 edge has no stable reason"));
                    }
                }
                ModuleResearchGraphEdgeDisposition::Supported
                | ModuleResearchGraphEdgeDisposition::Unresolved => {
                    if edge.rejection_reason.is_some() || edge.receipts.is_empty() {
                        return Err(invalid(
                            "supported or unresolved graph-v2 edge lacks exact receipts or carries a rejection",
                        ));
                    }
                }
                ModuleResearchGraphEdgeDisposition::Proposed
                | ModuleResearchGraphEdgeDisposition::Broken
                | ModuleResearchGraphEdgeDisposition::Blocked
                | ModuleResearchGraphEdgeDisposition::Superseded => {
                    if edge.rejection_reason.is_some() {
                        return Err(invalid(
                            "non-rejected graph-v2 edge carries a rejection reason",
                        ));
                    }
                }
            }
        }
        let mut experiments = BTreeSet::new();
        for experiment in &record.experiments {
            validate_record_schema(experiment.schema, "graph-v2 experiment specification")?;
            validate_nonempty(&experiment.id, "graph-v2 experiment identity")?;
            validate_identity_kind(&experiment.target, ModuleResearchIdentityKind::Target)?;
            validate_nonempty(
                &experiment.from_capability,
                "graph-v2 experiment producer capability",
            )?;
            validate_nonempty(
                &experiment.to_capability,
                "graph-v2 experiment consumer capability",
            )?;
            validate_identity_kind(
                &experiment.relation,
                ModuleResearchIdentityKind::GraphRelation,
            )?;
            validate_identity_kind(&experiment.oracle, ModuleResearchIdentityKind::Oracle)?;
            validate_nonempty(
                &experiment.adapter_operation,
                "graph-v2 experiment adapter operation",
            )?;
            validate_nonempty(
                &experiment.changed_dimension,
                "graph-v2 experiment changed dimension",
            )?;
            validate_nonempty(&experiment.detail, "graph-v2 experiment detail")?;
            if experiment.maximum_operations == 0 || !experiments.insert(experiment.id.as_str()) {
                return Err(invalid(
                    "graph-v2 experiment has no operation budget or duplicates an identity",
                ));
            }
            if !capability_nodes.contains(experiment.from_capability.as_str())
                || !capability_nodes.contains(experiment.to_capability.as_str())
            {
                return Err(invalid(
                    "graph-v2 experiment references a capability absent from the graph",
                ));
            }
        }
        let mut chains = BTreeSet::new();
        for chain in &record.chains {
            validate_nonempty(&chain.id, "graph-v2 chain identity")?;
            validate_nonempty(&chain.detail, "graph-v2 chain detail")?;
            if !chains.insert(chain.id.as_str()) {
                return Err(invalid("graph-v2 chain identities are duplicated"));
            }
            if chain.nodes.len() < 2
                || chain.edges.len().saturating_add(1) != chain.nodes.len()
                || chain.nodes.iter().any(|node| !nodes.contains(node.as_str()))
                || chain.edges.iter().any(|edge| !edges.contains_key(edge.as_str()))
                || chain.cost == 0
                || chain.cost > record.bounds.maximum_cost
                || chain.nodes.len() > usize::from(record.bounds.maximum_depth)
            {
                return Err(invalid("graph-v2 chain structure is inconsistent"));
            }
            let adapter_count =
                chain.adapter_families.iter().map(String::as_str).collect::<BTreeSet<_>>().len();
            let missing_experiment_count =
                chain.missing_experiments.iter().map(String::as_str).collect::<BTreeSet<_>>().len();
            if adapter_count != chain.adapter_families.len()
                || missing_experiment_count != chain.missing_experiments.len()
                || chain.missing_experiments.iter().any(|id| !experiments.contains(id.as_str()))
            {
                return Err(invalid(
                    "graph-v2 chain adapter or experiment identities are inconsistent",
                ));
            }
            let edge_dispositions = chain
                .edges
                .iter()
                .filter_map(|edge| edges.get(edge.as_str()))
                .copied()
                .collect::<Vec<_>>();
            match chain.disposition {
                ModuleResearchChainDisposition::Candidate => {
                    if chain.replay.is_some()
                        || edge_dispositions.iter().any(|disposition| {
                            matches!(
                                disposition,
                                ModuleResearchGraphEdgeDisposition::Rejected
                                    | ModuleResearchGraphEdgeDisposition::Broken
                                    | ModuleResearchGraphEdgeDisposition::Blocked
                            )
                        })
                    {
                        return Err(invalid(
                            "graph-v2 candidate carries replay evidence or an illegal edge",
                        ));
                    }
                }
                ModuleResearchChainDisposition::Confirmed => {
                    if chain.replay.is_none()
                        || edge_dispositions
                            .iter()
                            .any(|value| *value != ModuleResearchGraphEdgeDisposition::Supported)
                    {
                        return Err(invalid(
                            "confirmed graph-v2 chain lacks replay or fully supported edges",
                        ));
                    }
                }
                ModuleResearchChainDisposition::Broken => {
                    if !edge_dispositions.contains(&ModuleResearchGraphEdgeDisposition::Broken) {
                        return Err(invalid("broken graph-v2 chain has no broken edge"));
                    }
                }
                ModuleResearchChainDisposition::Rejected => {
                    if !edge_dispositions.contains(&ModuleResearchGraphEdgeDisposition::Rejected) {
                        return Err(invalid("rejected graph-v2 chain has no rejected edge"));
                    }
                }
                ModuleResearchChainDisposition::Blocked => {
                    if !edge_dispositions.contains(&ModuleResearchGraphEdgeDisposition::Blocked) {
                        return Err(invalid("blocked graph-v2 chain has no blocked edge"));
                    }
                }
                ModuleResearchChainDisposition::Superseded => {}
            }
            if let Some(replay) = &chain.replay {
                validate_identity_kind(replay, ModuleResearchIdentityKind::Receipt)?;
            }
        }
        if record.summary.candidates_expanded > record.bounds.maximum_open_candidates {
            return Err(invalid("graph-v2 search summary exceeds the configured frontier bound"));
        }
        if record.gaps.is_empty() {
            return Err(invalid("graph-v2 record has no explicit limitation statement"));
        }
        for gap in &record.gaps {
            validate_nonempty(gap, "graph-v2 gap")?;
        }
    }
    if state
        .research_active_graph
        .as_ref()
        .is_some_and(|selected| !state.research_graphs.iter().any(|graph| graph.id == *selected))
    {
        return Err(invalid("selected graph-v2 identity is absent from immutable history"));
    }
    let mut artifact_paths = BTreeSet::new();
    for artifact in &state.research_artifacts {
        validate_artifact(artifact)?;
        if !artifact_paths.insert(artifact.relative_private_path.as_str()) {
            return Err(invalid("research artifact paths are duplicated"));
        }
    }
    let mut bundle_ids = BTreeSet::new();
    for bundle in &state.research_poc_bundles {
        validate_record_schema(bundle.schema, "PoC bundle")?;
        validate_nonempty(&bundle.id, "PoC bundle identity")?;
        validate_nonempty(&bundle.chain_id, "PoC bundle chain identity")?;
        if !bundle_ids.insert(bundle.id.as_str()) || !has_digest_id(&bundle.id, "poc-") {
            return Err(invalid("PoC bundle identities are duplicated"));
        }
        validate_identity_kind(&bundle.minimizer, ModuleResearchIdentityKind::Minimizer)?;
        if let Some(replay) = &bundle.replay {
            validate_identity_kind(replay, ModuleResearchIdentityKind::Receipt)?;
        }
        for artifact in &bundle.artifacts {
            validate_artifact(artifact)?;
            if !state.research_artifacts.iter().any(|retained| retained == artifact) {
                return Err(invalid("PoC bundle references an artifact absent from durable state"));
            }
        }
        if bundle.limitations.is_empty() {
            return Err(invalid("PoC bundle has no explicit safety or coverage limitation"));
        }
        let confirmed_chain = state.research_graphs.iter().any(|graph| {
            graph.chains.iter().any(|chain| {
                chain.id == bundle.chain_id
                    && chain.disposition == ModuleResearchChainDisposition::Confirmed
                    && chain.replay.is_some()
            })
        });
        match bundle.state {
            ModuleResearchPocState::Planned | ModuleResearchPocState::Blocked => {
                if bundle.replay.is_some() || !bundle.artifacts.is_empty() {
                    return Err(invalid(
                        "planned or blocked PoC bundle carries replay or artifact evidence",
                    ));
                }
            }
            ModuleResearchPocState::Generated => {
                if bundle.replay.is_some() || bundle.artifacts.is_empty() {
                    return Err(invalid(
                        "generated PoC bundle lacks artifacts or prematurely carries replay",
                    ));
                }
            }
            ModuleResearchPocState::Verified => {
                let vendor = bundle.artifacts.iter().any(|artifact| {
                    artifact.classification
                        == ModuleResearchArtifactClassification::PrivateVendorPoc
                });
                let regression = bundle.artifacts.iter().any(|artifact| {
                    artifact.classification
                        == ModuleResearchArtifactClassification::MinimalRegressionPoc
                });
                if bundle.replay.is_none() || !confirmed_chain || !vendor || !regression {
                    return Err(invalid(
                        "verified PoC bundle lacks confirmed replay or both private PoC projections",
                    ));
                }
            }
            ModuleResearchPocState::Superseded => {}
        }
    }
    let mut repair_ids = BTreeSet::new();
    for bundle in &state.research_repair_bundles {
        validate_record_schema(bundle.schema, "repair bundle")?;
        validate_nonempty(&bundle.id, "repair bundle identity")?;
        validate_nonempty(&bundle.chain_id, "repair chain identity")?;
        validate_nonempty(&bundle.poc_bundle_id, "repair PoC bundle identity")?;
        if !repair_ids.insert(bundle.id.as_str())
            || !has_digest_id(&bundle.id, "repair-")
            || !is_sha256(&bundle.source_snapshot)
            || !state.research_poc_bundles.iter().any(|poc| {
                poc.id == bundle.poc_bundle_id
                    && poc.chain_id == bundle.chain_id
                    && poc.state == ModuleResearchPocState::Verified
            })
        {
            return Err(invalid(
                "repair bundle identity, source, or verified PoC binding is invalid",
            ));
        }
        if bundle.limitations.is_empty() {
            return Err(invalid("repair bundle has no explicit bypass or coverage limitation"));
        }
        for artifact in &bundle.artifacts {
            validate_artifact(artifact)?;
            if !state.research_artifacts.iter().any(|retained| retained == artifact) {
                return Err(invalid(
                    "repair bundle references an artifact absent from durable state",
                ));
            }
        }
        if let Some(replay) = &bundle.replay {
            validate_identity_kind(replay, ModuleResearchIdentityKind::Receipt)?;
        }
        if let Some(patch) = &bundle.patch {
            validate_nonempty(&patch.target_path, "repair target path")?;
            validate_nonempty(&patch.root_cause_group, "repair root-cause group")?;
            validate_nonempty(&patch.earliest_prerequisite, "repair earliest prerequisite")?;
            if !is_sha256(&patch.original_digest)
                || !is_sha256(&patch.patched_digest)
                || !is_sha256(&patch.patch_digest)
                || !is_sha256(&patch.diff_digest)
                || patch.original_digest == patch.patched_digest
            {
                return Err(invalid("repair patch digest or exact-preimage identity is invalid"));
            }
        }
        if let Some(review) = &bundle.review
            && (review.reviewer.is_empty()
                || review.detail.is_empty()
                || review.rejected_strategies.is_empty()
                || review.rejected_strategies.iter().any(|rejection| {
                    rejection.strategy.is_empty()
                        || rejection.reason.is_empty()
                        || !rejection.rejected
                }))
        {
            return Err(invalid("repair reviewer evidence is incomplete"));
        }
        let complete_replay = bundle.patch.is_some()
            && !bundle.artifacts.is_empty()
            && bundle.replay.is_some()
            && bundle.review.as_ref().is_some_and(|review| {
                review.accepted
                    && review.exact_preimage
                    && review.root_cause_repaired
                    && review.legitimate_behavior_preserved
                    && review.oracle_preserved
                    && review.target_preserved
                    && review.complete_matrix
            });
        let has_patch = bundle.artifacts.iter().any(|artifact| {
            artifact.classification == ModuleResearchArtifactClassification::PrivateRepairPatch
        });
        let has_regression = bundle.artifacts.iter().any(|artifact| {
            artifact.classification
                == ModuleResearchArtifactClassification::PrivateRegressionEvidence
        });
        match bundle.state {
            ModuleResearchRepairState::Planned | ModuleResearchRepairState::Blocked => {
                if bundle.patch.is_some()
                    || !bundle.artifacts.is_empty()
                    || bundle.replay.is_some()
                    || bundle.review.is_some()
                    || bundle.original_verification.is_some()
                {
                    return Err(invalid(
                        "planned or blocked repair bundle carries replay or patch evidence",
                    ));
                }
            }
            ModuleResearchRepairState::Replayed => {
                if !complete_replay
                    || !has_patch
                    || !has_regression
                    || bundle.original_verification.is_some()
                {
                    return Err(invalid(
                        "replayed repair lacks patch, regression, review, or awaits no source verification",
                    ));
                }
            }
            ModuleResearchRepairState::Verified => {
                if !complete_replay
                    || !has_patch
                    || !has_regression
                    || !bundle.original_verification.as_ref().is_some_and(|verification| {
                        verification.unchanged
                            && verification.changed_paths.is_empty()
                            && verification.added_paths.is_empty()
                            && verification.removed_paths.is_empty()
                    })
                {
                    return Err(invalid(
                        "verified repair lacks accepted replay or unchanged-original proof",
                    ));
                }
            }
            ModuleResearchRepairState::Rejected => {
                if !complete_replay || !has_patch || !has_regression {
                    return Err(invalid(
                        "rejected repair lacks the replay evidence explaining rejection",
                    ));
                }
            }
            ModuleResearchRepairState::Superseded => {}
        }
    }
    let mut disclosure_ids = BTreeSet::new();
    for package in &state.research_disclosure_packages {
        validate_record_schema(package.schema, "disclosure package")?;
        validate_nonempty(&package.id, "disclosure package identity")?;
        validate_nonempty(&package.chain_id, "disclosure package chain identity")?;
        validate_nonempty(&package.repair_bundle_id, "disclosure repair bundle identity")?;
        if !disclosure_ids.insert(package.id.as_str())
            || !crate::disclosure::valid_package_id(&package.id)
            || !is_sha256(&package.source_snapshot)
            || !is_sha256(&package.advisory_digest)
        {
            return Err(invalid("disclosure package identity or digest is invalid"));
        }
        validate_identity_kind(&package.template, ModuleResearchIdentityKind::Template)?;
        let repair = state
            .research_repair_bundles
            .iter()
            .find(|repair| repair.id == package.repair_bundle_id)
            .ok_or_else(|| invalid("disclosure package names an unknown repair bundle"))?;
        if repair.state != ModuleResearchRepairState::Verified
            || repair.chain_id != package.chain_id
            || repair.source_snapshot != package.source_snapshot
            || package.poc_bundle_id.as_deref() != Some(repair.poc_bundle_id.as_str())
        {
            return Err(invalid("disclosure package is not bound to one verified Stage 6 repair"));
        }
        if let Some(contact) = &package.contact {
            validate_nonempty(&contact.path, "disclosure contact path")?;
            if !crate::disclosure::CONTACT_PATHS.contains(&contact.path.as_str())
                || !is_sha256(&contact.source_digest)
                || !is_sha256(&contact.range_artifact)
            {
                return Err(invalid("disclosure contact source identity is invalid"));
            }
            validate_identity_kind(&contact.provenance, ModuleResearchIdentityKind::Receipt)?;
            if contact.recipient.as_ref().is_some_and(|value| {
                value.trim().is_empty()
                    || value.len() > 320
                    || value.chars().any(char::is_control)
                    || value.bytes().filter(|byte| *byte == b'@').count() != 1
            }) || contact.policy_url.as_ref().is_some_and(|value| {
                value.trim().is_empty()
                    || value.len() > 2_048
                    || value.chars().any(char::is_control)
                    || !value.to_ascii_lowercase().starts_with("https://")
            }) {
                return Err(invalid("disclosure contact fact is empty"));
            }
            let has_fact = contact.recipient.is_some() || contact.policy_url.is_some();
            if has_fact
                && !contact.source_excerpt.as_ref().is_some_and(|excerpt| {
                    !excerpt.is_empty()
                        && excerpt.len() <= 512
                        && !excerpt.chars().any(char::is_control)
                        && (contact.recipient.as_ref().is_some_and(|value| excerpt.contains(value))
                            || contact
                                .policy_url
                                .as_ref()
                                .is_some_and(|value| excerpt.contains(value)))
                })
            {
                return Err(invalid(
                    "disclosure contact fact lacks an exact bounded source excerpt",
                ));
            }
            if !has_fact && contact.source_excerpt.is_some() {
                return Err(invalid(
                    "unresolved disclosure contact carries an unsupported source excerpt",
                ));
            }
            if contact.recipient.is_none()
                && contact.policy_url.is_none()
                && !package
                    .placeholders
                    .iter()
                    .any(|value| value.starts_with("security_contact_unresolved:"))
            {
                return Err(invalid(
                    "disclosure contact without usable facts lacks an unresolved placeholder",
                ));
            }
        } else if !package
            .placeholders
            .iter()
            .any(|value| value.starts_with("security_contact_unresolved:"))
        {
            return Err(invalid(
                "disclosure package without contact provenance lacks an unresolved placeholder",
            ));
        }
        if let Some(review) = &package.redaction_review {
            validate_identity_kind(review, ModuleResearchIdentityKind::Receipt)?;
        }
        if let Some(proof) = &package.no_delivery_proof {
            validate_identity_kind(proof, ModuleResearchIdentityKind::Receipt)?;
        }
        if package.placeholders.is_empty()
            || package.placeholders.iter().any(|value| value.trim().is_empty())
        {
            return Err(invalid("disclosure package has no explicit unresolved facts"));
        }
        if package.timeline.is_empty() {
            return Err(invalid("disclosure package timeline is empty"));
        }
        let mut expected_sequence = 1_u32;
        for entry in &package.timeline {
            if entry.sequence != expected_sequence {
                return Err(invalid("disclosure timeline sequence is not contiguous from one"));
            }
            expected_sequence = expected_sequence.saturating_add(1);
            if entry.occurred_at.is_some() || entry.receipt.is_some() {
                return Err(invalid(
                    "autonomous Stage 7 timeline contains an external time or receipt fact",
                ));
            }
        }
        if package.timeline.last().map(|entry| entry.state) != Some(package.state) {
            return Err(invalid(
                "disclosure package state does not match its final timeline entry",
            ));
        }
        for artifact in &package.artifacts {
            validate_artifact(artifact)?;
            if !state.research_artifacts.iter().any(|retained| retained == artifact)
                || !artifact
                    .relative_private_path
                    .starts_with(&format!("research-artifacts/{}/", package.id))
            {
                return Err(invalid(
                    "disclosure package references an artifact absent from durable private state",
                ));
            }
        }
        let states = package.timeline.iter().map(|entry| entry.state).collect::<Vec<_>>();
        let artifact_prefix = format!("research-artifacts/{}/", package.id);
        let artifact_names = package
            .artifacts
            .iter()
            .filter_map(|artifact| artifact.relative_private_path.strip_prefix(&artifact_prefix))
            .collect::<BTreeSet<_>>();
        let exact_artifact_names =
            crate::disclosure::DISCLOSURE_ARTIFACT_NAMES.iter().copied().collect::<BTreeSet<_>>();
        let reviewed = package.artifacts.len() == exact_artifact_names.len()
            && artifact_names == exact_artifact_names
            && package.redaction_review.is_some()
            && package.no_delivery_proof.is_some()
            && !package.artifacts.is_empty()
            && package.artifacts.iter().any(|artifact| {
                artifact.relative_private_path.ends_with("/advisory.json")
                    && artifact.identity.digest == package.advisory_digest
            })
            && package.artifacts.iter().any(|artifact| {
                artifact.classification
                    == ModuleResearchArtifactClassification::PrivateDisclosurePackage
            })
            && package.artifacts.iter().any(|artifact| {
                artifact.classification
                    == ModuleResearchArtifactClassification::SanitizedPublicationDraft
            })
            && package.artifacts.iter().any(|artifact| {
                artifact.relative_private_path.ends_with("/redaction-review.json")
                    && package
                        .redaction_review
                        .as_ref()
                        .is_some_and(|review| review.digest == artifact.identity.digest)
            })
            && package.artifacts.iter().any(|artifact| {
                artifact.relative_private_path.ends_with("/no-delivery.json")
                    && package
                        .no_delivery_proof
                        .as_ref()
                        .is_some_and(|proof| proof.digest == artifact.identity.digest)
            })
            && package
                .artifacts
                .iter()
                .any(|artifact| artifact.relative_private_path.ends_with("/export-manifest.json"));
        match package.state {
            ModuleResearchDisclosureState::Draft => {
                if states != [ModuleResearchDisclosureState::Draft]
                    || !package.artifacts.is_empty()
                    || package.redaction_review.is_some()
                    || package.no_delivery_proof.is_some()
                {
                    return Err(invalid("draft disclosure package carries reviewed export state"));
                }
            }
            ModuleResearchDisclosureState::PackageReviewed => {
                if states
                    != [
                        ModuleResearchDisclosureState::Draft,
                        ModuleResearchDisclosureState::PackageReviewed,
                    ]
                    || !reviewed
                {
                    return Err(invalid(
                        "reviewed disclosure package lacks complete local evidence",
                    ));
                }
            }
            ModuleResearchDisclosureState::AwaitingUserAuthorization => {
                if states
                    != [
                        ModuleResearchDisclosureState::Draft,
                        ModuleResearchDisclosureState::PackageReviewed,
                        ModuleResearchDisclosureState::AwaitingUserAuthorization,
                    ]
                    || !reviewed
                {
                    return Err(invalid(
                        "awaiting disclosure package has an invalid local timeline",
                    ));
                }
            }
            ModuleResearchDisclosureState::Exported => {
                if states
                    != [
                        ModuleResearchDisclosureState::Draft,
                        ModuleResearchDisclosureState::PackageReviewed,
                        ModuleResearchDisclosureState::AwaitingUserAuthorization,
                        ModuleResearchDisclosureState::Exported,
                    ]
                    || !reviewed
                {
                    return Err(invalid(
                        "exported disclosure package lacks complete review evidence",
                    ));
                }
            }
            _ => {
                return Err(invalid(
                    "Stage 7 cannot retain submission, vendor, CVE, remediation, or publication states",
                ));
            }
        }
    }
    validate_research_autonomy(state, &experiment_ids)?;
    Ok(())
}

fn validate_research_autonomy(state: &State, experiment_ids: &BTreeSet<&str>) -> Result<(), Error> {
    let autonomy = &state.research_autonomy;
    if autonomy.schema != MODULE_RESEARCH_CONTRACT_VERSION
        || !(1..=64).contains(&autonomy.budgets.maximum_model_turns)
        || !(1..=32).contains(&autonomy.budgets.maximum_experiments)
        || !(1..=128).contains(&autonomy.budgets.maximum_cost)
        || autonomy.turn > autonomy.budgets.maximum_model_turns
        || autonomy.experiments_started > autonomy.budgets.maximum_experiments
        || autonomy.cost_spent > autonomy.budgets.maximum_cost
        || autonomy.role_index >= 9
        || autonomy.frontier.len() > 128
        || autonomy.steering.len() > 32
        || autonomy.recipe_seeds.len() > 16
    {
        return Err(invalid("Stage 4 autonomy state or finite budgets are outside hard bounds"));
    }
    if autonomy.phase == ResearchAutonomyPhase::Inactive {
        if !autonomy.campaign_id.is_empty()
            || !autonomy.graph_id.is_empty()
            || !autonomy.target_digest.is_empty()
            || !autonomy.frontier.is_empty()
            || autonomy.active_experiment.is_some()
            || !autonomy.recipe_seeds.is_empty()
        {
            return Err(invalid("inactive Stage 4 state retains an active campaign or frontier"));
        }
        return Ok(());
    }
    validate_nonempty(&autonomy.campaign_id, "Stage 4 campaign identity")?;
    validate_nonempty(&autonomy.graph_id, "Stage 4 graph identity")?;
    if !is_sha256(&autonomy.target_digest)
        || !state.research_graphs.iter().any(|graph| graph.id == autonomy.graph_id)
    {
        return Err(invalid("Stage 4 target or graph identity is absent from graph-v2 history"));
    }
    let mut recipe_ids = BTreeSet::new();
    for seed in &autonomy.recipe_seeds {
        let recipe = crate::emulation_recipes::find(&seed.recipe_id)?
            .ok_or_else(|| invalid("Stage 4 selected recipe is absent from this module"))?;
        if seed.schema != MODULE_RESEARCH_CONTRACT_VERSION
            || !recipe_ids.insert(seed.recipe_id.as_str())
            || seed.recipe_digest != recipe.record_digest
            || seed.evidence_class != recipe.evidence_class
            || seed.selected_turn > autonomy.turn
            || seed.selection_digest
                != crate::emulation_recipes::selection_digest(
                    &autonomy.campaign_id,
                    &seed.recipe_id,
                    &seed.recipe_digest,
                    seed.selected_turn,
                )
        {
            return Err(invalid(
                "Stage 4 emulation-recipe selection identity or evidence class is invalid",
            ));
        }
    }
    let mut proposal_ids = BTreeSet::new();
    let mut running = Vec::new();
    for proposal in &autonomy.frontier {
        validate_nonempty(&proposal.id, "Stage 4 proposal identity")?;
        validate_nonempty(&proposal.experiment_id, "Stage 4 proposal experiment identity")?;
        validate_nonempty(&proposal.adapter_operation, "Stage 4 adapter operation")?;
        validate_nonempty(&proposal.changed_dimension, "Stage 4 changed dimension")?;
        validate_nonempty(&proposal.detail, "Stage 4 proposal detail")?;
        if !proposal_ids.insert(proposal.id.as_str())
            || !experiment_ids.contains(proposal.experiment_id.as_str())
            || proposal.created_turn > autonomy.turn
            || (matches!(
                proposal.disposition,
                ResearchProposalDisposition::Admitted
                    | ResearchProposalDisposition::Running
                    | ResearchProposalDisposition::Observed
            ) && proposal.cost > autonomy.budgets.maximum_cost)
            || !is_sha256(&proposal.rationale_digest)
            || proposal
                .baseline_capabilities
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                .len()
                != proposal.baseline_capabilities.len()
        {
            return Err(invalid(
                "Stage 4 proposal identity, budget, provenance, or baseline is inconsistent",
            ));
        }
        if proposal.disposition == ResearchProposalDisposition::Running {
            running.push(proposal.experiment_id.as_str());
        }
    }
    let preferred =
        autonomy.preferred_operations.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let excluded = autonomy.excluded_operations.iter().map(String::as_str).collect::<BTreeSet<_>>();
    if preferred.len() != autonomy.preferred_operations.len()
        || excluded.len() != autonomy.excluded_operations.len()
        || !preferred.is_disjoint(&excluded)
        || autonomy
            .steering
            .iter()
            .chain(&autonomy.failures)
            .any(|value| value.is_empty() || value.len() > 8_192 || value.contains('\0'))
    {
        return Err(invalid("Stage 4 steering, ranking, exclusion, or failure state is invalid"));
    }
    match (&autonomy.active_experiment, &state.pending, autonomy.phase) {
        (
            Some(active),
            Some(PendingRequest::ResearchExperimentExecute { experiment_id, .. }),
            ResearchAutonomyPhase::Executing | ResearchAutonomyPhase::Paused,
        ) if active == experiment_id && running == [active.as_str()] => {}
        (Some(active), None, ResearchAutonomyPhase::Executing) if running == [active.as_str()] => {}
        (None, Some(PendingRequest::ResearchExperimentExecute { .. }), _) => {
            return Err(invalid("Stage 4 pending experiment has no active lifecycle owner"));
        }
        (Some(_), _, _) => {
            return Err(invalid(
                "Stage 4 active experiment lacks the exact executing pending request",
            ));
        }
        (None, _, _) if !running.is_empty() => {
            return Err(invalid("Stage 4 frontier has an unowned running experiment"));
        }
        _ => {}
    }
    Ok(())
}

fn validate_record_schema(schema: u16, label: &str) -> Result<(), Error> {
    if schema != MODULE_RESEARCH_CONTRACT_VERSION {
        return Err(invalid(format!(
            "unsupported {label} schema {schema}; expected {MODULE_RESEARCH_CONTRACT_VERSION}"
        )));
    }
    Ok(())
}

fn validate_identity(identity: &ModuleResearchIdentity) -> Result<(), Error> {
    validate_record_schema(identity.schema, "research identity")?;
    validate_nonempty(&identity.value, "research identity value")?;
    if !is_sha256(&identity.digest) {
        return Err(invalid("research identity digest is not an exact lowercase SHA-256 digest"));
    }
    Ok(())
}

fn validate_capability_fact(fact: &ModuleResearchCapabilityFact) -> Result<(), Error> {
    validate_record_schema(fact.schema, "capability fact")?;
    validate_nonempty(&fact.value, "capability fact value")?;
    if !is_sha256(&fact.digest) {
        return Err(invalid("capability fact digest is not an exact lowercase SHA-256 digest"));
    }
    Ok(())
}

fn validate_identity_kind(
    identity: &ModuleResearchIdentity,
    expected: ModuleResearchIdentityKind,
) -> Result<(), Error> {
    validate_identity(identity)?;
    if identity.kind != expected {
        return Err(invalid(format!(
            "research identity `{}` has kind {:?}; expected {:?}",
            identity.value, identity.kind, expected
        )));
    }
    Ok(())
}

fn validate_artifact(artifact: &ModuleResearchArtifactIdentity) -> Result<(), Error> {
    validate_record_schema(artifact.schema, "research artifact")?;
    validate_identity_kind(&artifact.identity, ModuleResearchIdentityKind::Artifact)?;
    if !artifact.owner_only {
        return Err(invalid("research artifact metadata must remain owner-only"));
    }
    validate_nonempty(&artifact.media_type, "research artifact media type")?;
    let path = Path::new(&artifact.relative_private_path);
    if artifact.relative_private_path.is_empty()
        || path.is_absolute()
        || path.components().any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(invalid(
            "research artifact path must be a normalized module-private relative path",
        ));
    }
    Ok(())
}

fn validate_nonempty(value: &str, label: &str) -> Result<(), Error> {
    if value.trim().is_empty() {
        return Err(invalid(format!("{label} is empty")));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn has_digest_id(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(is_sha256)
}

fn state_path(parameters: &serde_json::Value) -> Result<PathBuf, Error> {
    Ok(private_root(parameters)?.join("red-team-state-v19.json"))
}

fn migrate_phase_twenty(parameters: &serde_json::Value) -> Result<State, Error> {
    let legacy = private_root(parameters)?.join("red-team-state-v18.json");
    match fs::read(legacy) {
        Ok(bytes) => {
            let mut state: State = serde_json::from_slice(&bytes).map_err(|error| {
                invalid(format!(
                    "Red Team schema-18 state is unreadable ({error}); the original bytes remain unchanged"
                ))
            })?;
            if state.schema != 18 || state.phase != 20 {
                return Err(invalid("unsupported Red Team Phase 20 state"));
            }
            state.schema = STATE_SCHEMA;
            state.phase = PHASE;
            state.module_version = env!("CARGO_PKG_VERSION").into();
            Ok(state)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            migrate_phase_nineteen(parameters)
        }
        Err(error) => Err(error.into()),
    }
}

fn migrate_phase_nineteen(parameters: &serde_json::Value) -> Result<State, Error> {
    let legacy = private_root(parameters)?.join("red-team-state-v17.json");
    match fs::read(legacy) {
        Ok(bytes) => {
            let mut state: State = serde_json::from_slice(&bytes)?;
            if state.schema != 17 || state.phase != 19 {
                return Err(invalid("unsupported Red Team Phase 19 state"));
            }
            state.schema = STATE_SCHEMA;
            state.phase = PHASE;
            state.module_version = env!("CARGO_PKG_VERSION").into();
            Ok(state)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            migrate_phase_eighteen(parameters)
        }
        Err(error) => Err(error.into()),
    }
}

fn migrate_phase_eighteen(parameters: &serde_json::Value) -> Result<State, Error> {
    let legacy = private_root(parameters)?.join("red-team-state-v16.json");
    match fs::read(legacy) {
        Ok(bytes) => {
            let mut state: State = serde_json::from_slice(&bytes)?;
            if state.schema != 16 || state.phase != 18 {
                return Err(invalid("unsupported Red Team Phase 18 state"));
            }
            state.schema = STATE_SCHEMA;
            state.phase = PHASE;
            state.module_version = env!("CARGO_PKG_VERSION").into();
            Ok(state)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            migrate_phase_seventeen(parameters)
        }
        Err(error) => Err(error.into()),
    }
}

fn migrate_phase_seventeen(parameters: &serde_json::Value) -> Result<State, Error> {
    let legacy = private_root(parameters)?.join("red-team-state-v15.json");
    match fs::read(legacy) {
        Ok(bytes) => {
            let mut state: State = serde_json::from_slice(&bytes)?;
            if state.schema != 15 || state.phase != 17 {
                return Err(invalid("unsupported Red Team Phase 17 state"));
            }
            state.schema = STATE_SCHEMA;
            state.phase = PHASE;
            state.module_version = env!("CARGO_PKG_VERSION").into();
            Ok(state)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            migrate_phase_sixteen(parameters)
        }
        Err(error) => Err(error.into()),
    }
}

fn migrate_phase_sixteen(parameters: &serde_json::Value) -> Result<State, Error> {
    let legacy = private_root(parameters)?.join("red-team-state-v14.json");
    match fs::read(legacy) {
        Ok(bytes) => {
            let mut state: State = serde_json::from_slice(&bytes)?;
            if state.schema != 14 || state.phase != 16 {
                return Err(invalid("unsupported Red Team Phase 16 state"));
            }
            state.schema = STATE_SCHEMA;
            state.phase = PHASE;
            state.module_version = env!("CARGO_PKG_VERSION").into();
            Ok(state)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            migrate_phase_fifteen(parameters)
        }
        Err(error) => Err(error.into()),
    }
}

fn migrate_phase_fifteen(parameters: &serde_json::Value) -> Result<State, Error> {
    let legacy = private_root(parameters)?.join("red-team-state-v13.json");
    match fs::read(legacy) {
        Ok(bytes) => {
            let mut state: State = serde_json::from_slice(&bytes)?;
            if state.schema != 13 || state.phase != 15 {
                return Err(invalid("unsupported Red Team Phase 15 state"));
            }
            state.schema = STATE_SCHEMA;
            state.phase = PHASE;
            state.module_version = env!("CARGO_PKG_VERSION").into();
            Ok(state)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            migrate_phase_fourteen(parameters)
        }
        Err(error) => Err(error.into()),
    }
}

fn migrate_phase_fourteen(parameters: &serde_json::Value) -> Result<State, Error> {
    let legacy = private_root(parameters)?.join("red-team-state-v12.json");
    match fs::read(legacy) {
        Ok(bytes) => {
            let mut state: State = serde_json::from_slice(&bytes)?;
            if state.schema != 12 || state.phase != 14 {
                return Err(invalid("unsupported Red Team Phase 14 state"));
            }
            state.schema = STATE_SCHEMA;
            state.phase = PHASE;
            state.module_version = env!("CARGO_PKG_VERSION").into();
            Ok(state)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            migrate_phase_thirteen(parameters)
        }
        Err(error) => Err(error.into()),
    }
}

fn migrate_phase_thirteen(parameters: &serde_json::Value) -> Result<State, Error> {
    let legacy = private_root(parameters)?.join("red-team-state-v11.json");
    match fs::read(legacy) {
        Ok(bytes) => {
            let mut state: State = serde_json::from_slice(&bytes)?;
            if state.schema != 11 || state.phase != 13 {
                return Err(invalid("unsupported Red Team Phase 13 state"));
            }
            state.schema = STATE_SCHEMA;
            state.phase = PHASE;
            state.module_version = env!("CARGO_PKG_VERSION").into();
            Ok(state)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            migrate_phase_twelve(parameters)
        }
        Err(error) => Err(error.into()),
    }
}

fn migrate_phase_twelve(parameters: &serde_json::Value) -> Result<State, Error> {
    let legacy = private_root(parameters)?.join("red-team-state-v10.json");
    match fs::read(legacy) {
        Ok(bytes) => {
            let mut state: State = serde_json::from_slice(&bytes)?;
            if state.schema != 10 || state.phase != 12 {
                return Err(invalid("unsupported Red Team Phase 12 state"));
            }
            state.schema = STATE_SCHEMA;
            state.phase = PHASE;
            state.module_version = env!("CARGO_PKG_VERSION").into();
            Ok(state)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            migrate_phase_eleven(parameters)
        }
        Err(error) => Err(error.into()),
    }
}

fn migrate_phase_eleven(parameters: &serde_json::Value) -> Result<State, Error> {
    let legacy = private_root(parameters)?.join("red-team-state-v9.json");
    match fs::read(legacy) {
        Ok(bytes) => {
            let mut state: State = serde_json::from_slice(&bytes)?;
            if state.schema != 9 || state.phase != 11 {
                return Err(invalid("unsupported Red Team Phase 11 state"));
            }
            state.schema = STATE_SCHEMA;
            state.phase = PHASE;
            state.module_version = env!("CARGO_PKG_VERSION").into();
            Ok(state)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => migrate_phase_ten(parameters),
        Err(error) => Err(error.into()),
    }
}

fn migrate_phase_ten(parameters: &serde_json::Value) -> Result<State, Error> {
    let legacy = private_root(parameters)?.join("red-team-state-v8.json");
    match fs::read(legacy) {
        Ok(bytes) => {
            let mut state: State = serde_json::from_slice(&bytes)?;
            if state.schema != 8 || state.phase != 10 {
                return Err(invalid("unsupported Red Team Phase 10 state"));
            }
            state.schema = STATE_SCHEMA;
            state.phase = PHASE;
            state.module_version = env!("CARGO_PKG_VERSION").into();
            Ok(state)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            migrate_phase_nine(parameters)
        }
        Err(error) => Err(error.into()),
    }
}

fn migrate_phase_nine(parameters: &serde_json::Value) -> Result<State, Error> {
    let legacy = private_root(parameters)?.join("red-team-state-v7.json");
    match fs::read(legacy) {
        Ok(bytes) => {
            let mut state: State = serde_json::from_slice(&bytes)?;
            if state.schema != 7 || state.phase != 9 {
                return Err(invalid("unsupported Red Team Phase 9 state"));
            }
            state.schema = STATE_SCHEMA;
            state.phase = PHASE;
            state.module_version = env!("CARGO_PKG_VERSION").into();
            Ok(state)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => migrate_phase_six(parameters),
        Err(error) => Err(error.into()),
    }
}

fn migrate_phase_six(parameters: &serde_json::Value) -> Result<State, Error> {
    let legacy = private_root(parameters)?.join("red-team-state-v6.json");
    match fs::read(legacy) {
        Ok(bytes) => {
            let mut state: State = serde_json::from_slice(&bytes)?;
            if state.schema != 6 || state.phase != 6 {
                return Err(invalid("unsupported Red Team Phase 6 state"));
            }
            state.schema = STATE_SCHEMA;
            state.phase = PHASE;
            state.module_version = env!("CARGO_PKG_VERSION").into();
            Ok(state)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            migrate_phase_five(parameters)
        }
        Err(error) => Err(error.into()),
    }
}

fn migrate_phase_five(parameters: &serde_json::Value) -> Result<State, Error> {
    let legacy = private_root(parameters)?.join("red-team-state-v5.json");
    match fs::read(legacy) {
        Ok(bytes) => {
            let mut state: State = serde_json::from_slice(&bytes)?;
            if state.schema != 5 || state.phase != 5 {
                return Err(invalid("unsupported Red Team Phase 5 state"));
            }
            state.schema = STATE_SCHEMA;
            state.phase = PHASE;
            state.module_version = env!("CARGO_PKG_VERSION").into();
            Ok(state)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            migrate_phase_three(parameters)
        }
        Err(error) => Err(error.into()),
    }
}

fn migrate_phase_three(parameters: &serde_json::Value) -> Result<State, Error> {
    let legacy = private_root(parameters)?.join("red-team-state-v3.json");
    match fs::read(legacy) {
        Ok(bytes) => {
            let mut state: State = serde_json::from_slice(&bytes)?;
            if state.schema != 3 || state.phase != 3 {
                return Err(invalid("unsupported Red Team Phase 3 state"));
            }
            state.schema = STATE_SCHEMA;
            state.phase = PHASE;
            state.module_version = env!("CARGO_PKG_VERSION").into();
            Ok(state)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => migrate_phase_two(parameters),
        Err(error) => Err(error.into()),
    }
}

fn migrate_phase_two(parameters: &serde_json::Value) -> Result<State, Error> {
    let legacy = private_root(parameters)?.join("red-team-state-v2.json");
    match fs::read(legacy) {
        Ok(bytes) => {
            let mut state: State = serde_json::from_slice(&bytes)?;
            if state.schema != 2 || state.phase != 2 {
                return Err(invalid("unsupported Red Team Phase 2 state"));
            }
            state.schema = STATE_SCHEMA;
            state.phase = PHASE;
            state.module_version = env!("CARGO_PKG_VERSION").into();
            Ok(state)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => migrate_phase_one(parameters),
        Err(error) => Err(error.into()),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PhaseOneState {
    schema: u16,
    phase: u8,
    module_version: String,
    checkpoint: Option<SkeletonCheckpoint>,
}

fn migrate_phase_one(parameters: &serde_json::Value) -> Result<State, Error> {
    let mut state = State::default();
    let legacy = private_root(parameters)?.join("red-team-skeleton-v1.json");
    match fs::read(legacy) {
        Ok(bytes) => {
            let legacy: PhaseOneState = serde_json::from_slice(&bytes)?;
            if legacy.schema != 1 || legacy.phase != 1 {
                return Err(invalid("unsupported Red Team Phase 1 state"));
            }
            state.checkpoint = legacy.checkpoint;
            let _ = legacy.module_version;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(state)
}

pub(crate) fn security_families() -> [&'static str; 15] {
    [
        "input_interpretation_and_injection",
        "authentication_and_sessions",
        "authorization_and_tenancy",
        "files_paths_archives_and_uploads",
        "browser_and_client_trust",
        "network_and_protocol_boundaries",
        "cryptography_and_key_lifecycle",
        "memory_integers_and_unsafe_interfaces",
        "concurrency_and_state_consistency",
        "availability_and_resource_use",
        "business_logic_and_workflow",
        "dependencies_and_supply_chain",
        "configuration_secrets_and_observability",
        "privilege_sandbox_and_platform",
        "agent_prompt_and_tool_authority",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const EMPTY_RESEARCH_DIGEST: &str =
        "a9ad68ccfc35608208f98980174c90efd826cc8578b8754c42d768fe375028ef";

    fn parameters(root: &Path) -> serde_json::Value {
        json!({"state_directory": root})
    }

    #[test]
    fn schema_eighteen_migration_preserves_rollback_file() {
        let directory = tempfile::tempdir().expect("temporary state directory");
        let legacy_path = directory.path().join("red-team-state-v18.json");
        let legacy = include_bytes!("../resources/phase20-state-v18.json");
        fs::write(&legacy_path, legacy).expect("write schema-18 fixture");

        let state = load(&parameters(directory.path())).expect("migrate schema-18 fixture");

        assert_eq!(state.schema, STATE_SCHEMA);
        assert_eq!(state.phase, PHASE);
        assert_eq!(state.research_records_digest, EMPTY_RESEARCH_DIGEST);
        assert!(state.research_experiments.is_empty());
        assert!(state.research_capabilities.is_empty());
        assert!(state.research_graphs.is_empty());
        assert!(state.research_artifacts.is_empty());
        assert!(state.research_poc_bundles.is_empty());
        assert!(state.research_repair_bundles.is_empty());
        assert!(state.research_disclosure_packages.is_empty());
        assert_eq!(fs::read(&legacy_path).expect("read rollback fixture"), legacy);
        assert!(directory.path().join("red-team-state-v19.json").is_file());
    }

    #[test]
    fn canonical_schema_nineteen_fixture_opens_without_rewrite() {
        let directory = tempfile::tempdir().expect("temporary state directory");
        let path = directory.path().join("red-team-state-v19.json");
        let fixture = include_bytes!("../resources/phase22-state-v19.json");
        fs::write(&path, fixture).expect("write schema-19 fixture");

        let state = load(&parameters(directory.path())).expect("open schema-19 fixture");

        assert_eq!(state.research_records_digest, EMPTY_RESEARCH_DIGEST);
        assert_eq!(fs::read(path).expect("read schema-19 fixture"), fixture);
    }

    #[test]
    fn research_digest_mismatch_fails_closed_without_rewrite() {
        let directory = tempfile::tempdir().expect("temporary state directory");
        let path = directory.path().join("red-team-state-v19.json");
        let mut fixture: serde_json::Value =
            serde_json::from_str(include_str!("../resources/phase22-state-v19.json"))
                .expect("decode schema-19 fixture");
        fixture["research_records_digest"] = serde_json::Value::String("0".repeat(64));
        let bytes = serde_json::to_vec_pretty(&fixture).expect("encode mismatched fixture");
        fs::write(&path, &bytes).expect("write mismatched fixture");

        let error = load(&parameters(directory.path())).expect_err("reject mismatched digest");

        assert!(error.to_string().contains("research-record digest mismatch"));
        assert_eq!(fs::read(path).expect("read mismatched fixture"), bytes);
    }
}
