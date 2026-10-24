//! Small durable campaign checkpoint; large source and report bytes live in separate artifacts.

use crate::{Error, invalid, records::*};
use peritus_plugin_sdk::{
    ModuleJobCancelRequest, ModuleJobLogRequest, ModuleJobReceipt, ModuleJobRequest,
    ModuleJobStatusRequest, ModulePatchReceipt, ScopedSourceAuthority, ScopedSourceEntry,
    ScopedSourceHandle, ScopedSourceVerification, ScopedSourceVerifyRequest,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

pub(crate) const STATE_SCHEMA: u16 = 6;
pub(crate) const PHASE: u8 = 6;

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
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FamilyRoute {
    pub(crate) family: String,
    pub(crate) state: CoverageState,
    pub(crate) reason: String,
    pub(crate) surfaces: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HypothesisPlan {
    pub(crate) hypothesis_id: String,
    pub(crate) family: String,
    pub(crate) origin: HypothesisOrigin,
    pub(crate) source_evidence: Vec<RecordId>,
    pub(crate) target_path: Option<String>,
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
            Self::Capture { key, .. }
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
            attacker_model: "The selected source authority permits digest-pinned dependency preparation and literal input only to host-owned contained proof adapters."
                .into(),
            allowed_effects: vec![
                "inert_source_capture".into(),
                "bounded_source_read".into(),
                "credential_free_dependency_preparation".into(),
                "contained_canary_disclosure_proof".into(),
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
        self.scopes.push(scope);
        self.snapshots.push(snapshot);
        self.campaign.scope_revision = Some(scope_id.clone());
        self.campaign.source_snapshot = Some(snapshot_id);
        self.campaign.state = CampaignState::Active;
        self.investigation = InvestigationState::default();
        self.repair = RepairState::default();
        self.original_verification = None;
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
        Ok(())
    }
}

pub(crate) fn load(parameters: &serde_json::Value) -> Result<State, Error> {
    let path = state_path(parameters)?;
    let mut state = match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            migrate_phase_five(parameters)?
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
    Ok(private_root(parameters)?.join("red-team-state-v6.json"))
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
