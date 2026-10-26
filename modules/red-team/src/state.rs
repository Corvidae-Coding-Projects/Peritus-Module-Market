//! Small durable campaign checkpoint; large source and report bytes live in separate artifacts.

use crate::{Error, invalid, records::*};
use peritus_plugin_sdk::{
    ModuleAdapterCancelRequest, ModuleAdapterCatalog, ModuleAdapterCompleteRequest,
    ModuleAdapterExecuteRequest, ModuleAdapterExecutionReceipt, ModuleAdapterPreparationHandle,
    ModuleAdapterPrepareRequest, ModuleAdapterRemoveRequest, ModuleAdapterStatus,
    ModuleAdapterStatusRequest, ModuleAttackGraphObservation, ModuleBoundaryObservation,
    ModuleBrowserObservation, ModuleFileFuzzObservation, ModuleHttpApiObservation,
    ModuleIdentityAccessObservation, ModuleJobCancelRequest, ModuleJobLogRequest, ModuleJobReceipt,
    ModuleJobRequest, ModuleJobStatusRequest, ModuleLaboratoryCatalog,
    ModuleLaboratoryCreateRequest, ModuleLaboratoryInvokeRequest, ModuleLaboratoryLifecycleRequest,
    ModuleLaboratoryReceipt, ModuleLaboratorySourceCreateRequest, ModuleLaboratoryStatus,
    ModulePatchReceipt, ModuleSourceAnalysisObservation, ModuleWorkflowObservation,
    ScopedSourceAuthority, ScopedSourceEntry, ScopedSourceHandle, ScopedSourceVerification,
    ScopedSourceVerifyRequest,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

pub(crate) const STATE_SCHEMA: u16 = 18;
pub(crate) const PHASE: u8 = 20;

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
            | Self::LaboratoryCatalog { key }
            | Self::LaboratoryCreate { key, .. }
            | Self::LaboratorySourceCreate { key, .. }
            | Self::LaboratoryLifecycle { key, .. }
            | Self::LaboratoryInvoke { key, .. }
            | Self::Capture { key, .. }
            | Self::Manifest { key, .. }
            | Self::Read { key, .. }
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
            (migrate_phase_nineteen(parameters)?, true)
        }
        Err(error) => return Err(error.into()),
    };
    if state.schema != STATE_SCHEMA || state.phase != PHASE {
        return Err(invalid(format!(
            "unsupported Red Team state schema {} phase {}",
            state.schema, state.phase
        )));
    }
    state.module_version = env!("CARGO_PKG_VERSION").into();
    if state.active_snapshot().is_some() {
        crate::coverage::initialize_methods(&mut state);
    }
    if migrated {
        publish(&path, &state)?;
    }
    Ok(state)
}

pub(crate) fn save(parameters: &serde_json::Value, state: &State) -> Result<(), Error> {
    publish(&state_path(parameters)?, state)
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

fn state_path(parameters: &serde_json::Value) -> Result<PathBuf, Error> {
    Ok(private_root(parameters)?.join("red-team-state-v18.json"))
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
