//! Version-one durable record identities and dependency contracts.
//!
//! These records define future persistence boundaries. They do not select source, authorize an
//! effect, establish a finding, or prove that an artifact exists.

use serde::{Deserialize, Serialize};

/// Initial Red Team durable-record schema version.
pub const RECORD_SCHEMA_VERSION: u16 = 1;

/// Stable kind encoded into every durable record identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    /// One user-authorized investigation campaign.
    Campaign,
    /// One immutable revision of campaign scope and allowed effects.
    ScopeRevision,
    /// One immutable snapshot of explicitly selected source.
    SourceSnapshot,
    /// One security-family and application-surface coverage statement.
    Coverage,
    /// One versioned target profile compiled from retained source evidence.
    TargetProfile,
    /// One application component owned by a target profile.
    Component,
    /// One concrete entry surface of an application component.
    Surface,
    /// One directed trust boundary between application components.
    TrustBoundary,
    /// One attacker identity and application configuration pairing.
    IdentityConfiguration,
    /// One security property, with versioned standards mappings where available.
    SecurityProperty,
    /// One source or runtime examination method advertised by the coordinator.
    Method,
    /// One surface-by-identity-by-property-by-method coverage obligation.
    CoverageCell,
    /// One falsifiable security claim awaiting or carrying evidence.
    Hypothesis,
    /// One retained module worker operation.
    Job,
    /// One content-addressed observation or receipt.
    Evidence,
    /// One adjudicated security claim revision.
    Finding,
    /// One copy-only candidate patch revision.
    Patch,
    /// One independent review of an exact subject revision.
    Review,
    /// One report revision over exact retained records.
    Report,
}

/// Versioned durable record identity, unique within its campaign store.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordId {
    /// Identity schema version.
    pub schema: u16,
    /// Record family.
    pub kind: RecordKind,
    /// Opaque lowercase ASCII identity allocated by the coordinator.
    pub value: String,
}

impl RecordId {
    /// Creates and validates a version-one durable record identity.
    ///
    /// # Errors
    ///
    /// Returns a stable detail for an unsupported schema or malformed opaque value.
    pub fn new(kind: RecordKind, value: impl Into<String>) -> Result<Self, &'static str> {
        Self { schema: RECORD_SCHEMA_VERSION, kind, value: value.into() }.validate()
    }

    /// Validates a decoded identity before it is used as a dependency.
    ///
    /// # Errors
    ///
    /// Returns a stable detail for an unsupported schema or malformed opaque value.
    pub fn validate(self) -> Result<Self, &'static str> {
        if self.schema != RECORD_SCHEMA_VERSION {
            return Err("unsupported Red Team record identity schema");
        }
        let valid = !self.value.is_empty()
            && self.value.len() <= 160
            && self.value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'-' | b'_' | b'.' | b':')
            });
        if !valid {
            return Err("invalid Red Team record identity value");
        }
        Ok(self)
    }
}

/// Lifecycle of the overall campaign record.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignState {
    /// Created but not admitted to source or execution services.
    Draft,
    /// Admitted work may proceed within the retained scope revision.
    Active,
    /// No new work proceeds until an explicit resume.
    Paused,
    /// The campaign published its best current report.
    Completed,
    /// A named prerequisite prevents further progress.
    Blocked,
    /// The user cancelled owned work.
    Cancelled,
}

/// Root record for one authorized campaign and its current immutable dependencies.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CampaignRecord {
    /// Record schema version.
    pub schema: u16,
    /// Stable campaign identity.
    pub id: RecordId,
    /// Current lifecycle state.
    pub state: CampaignState,
    /// Current scope revision, when one has been explicitly selected.
    pub scope_revision: Option<RecordId>,
    /// Current source snapshot, when capture has completed.
    pub source_snapshot: Option<RecordId>,
    /// Superseded campaign record revision, if any.
    pub supersedes: Option<RecordId>,
}

/// Exact user-approved target boundary and effect policy revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeRevisionRecord {
    /// Record schema version.
    pub schema: u16,
    /// Stable scope-revision identity.
    pub id: RecordId,
    /// Owning campaign.
    pub campaign: RecordId,
    /// Monotonic campaign-local revision.
    pub revision: u64,
    /// User-facing source label; never a filesystem authority token.
    pub source_label: String,
    /// Attacker privileges and trust assumptions accepted for this revision.
    pub attacker_model: String,
    /// Explicitly permitted effect names.
    pub allowed_effects: Vec<String>,
    /// Explicit source-relative exclusions.
    pub exclusions: Vec<String>,
    /// Prior scope revision replaced by this one.
    pub supersedes: Option<RecordId>,
}

/// Immutable source identity returned by a future host scoped-source service.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshotRecord {
    /// Record schema version.
    pub schema: u16,
    /// Stable source-snapshot identity.
    pub id: RecordId,
    /// Owning campaign.
    pub campaign: RecordId,
    /// Exact scope revision authorizing capture.
    pub scope_revision: RecordId,
    /// Opaque host source handle; never interpreted as a path by the module.
    pub source_handle: String,
    /// Digest of captured source bytes and exclusions.
    pub snapshot_digest: String,
    /// Content-addressed capture-manifest artifact identity.
    pub manifest_artifact: String,
}

/// Honest investigation state for one family and application surface.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageState {
    /// No investigation has examined this surface yet.
    Unexamined,
    /// Named methods examined the surface; this is not a claim that it is secure.
    Examined,
    /// The family does not apply for a recorded reason.
    NotApplicable,
    /// A named prerequisite prevented examination.
    Blocked,
}

/// One revisioned family-by-surface coverage statement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageRecord {
    /// Record schema version.
    pub schema: u16,
    /// Stable coverage-record identity.
    pub id: RecordId,
    /// Owning campaign.
    pub campaign: RecordId,
    /// Exact scope revision.
    pub scope_revision: RecordId,
    /// Stable supported security-family name.
    pub family: String,
    /// Application surface, or `whole_application` before discovery.
    pub surface: String,
    /// Current bounded coverage state.
    pub state: CoverageState,
    /// Concrete method, applicability rationale, gap, or blocker.
    pub reason: String,
    /// Evidence supporting an examined state.
    pub evidence: Vec<RecordId>,
    /// Prior coverage revision replaced by this record.
    pub supersedes: Option<RecordId>,
}

/// Coarse application shape used to select compatible security methods.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetProfileKind {
    /// A command-line application.
    CommandLine,
    /// A native desktop or background application.
    NativeApplication,
    /// A browser-served web application.
    WebApplication,
    /// A machine-facing HTTP or RPC API.
    ApiService,
    /// A browser client with client-side trust boundaries.
    BrowserClient,
    /// Multiple cooperating services or clients.
    MultiService,
    /// A shape not represented by the current compiler vocabulary.
    Other,
}

/// Versioned external or module-owned property identifier.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StandardReference {
    /// Catalog name: `ASVS`, `WSTG`, `CWE`, or `PERITUS`.
    pub catalog: String,
    /// Exact catalog/schema version.
    pub version: String,
    /// Identifier in that version of the catalog.
    pub identifier: String,
}

/// One current target profile derived from retained source evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetProfileRecord {
    pub schema: u16,
    pub id: RecordId,
    pub campaign: RecordId,
    pub scope_revision: RecordId,
    pub name: String,
    pub kind: TargetProfileKind,
    pub operating_systems: Vec<String>,
    pub languages: Vec<String>,
    pub services: Vec<String>,
    pub stores: Vec<String>,
    pub interfaces: Vec<String>,
    pub unavailable_claims: Vec<String>,
    pub evidence: Vec<RecordId>,
}

/// One source-owning application component.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationComponentRecord {
    pub schema: u16,
    pub id: RecordId,
    pub campaign: RecordId,
    pub scope_revision: RecordId,
    pub profile: RecordId,
    pub name: String,
    pub kind: String,
    pub source_paths: Vec<String>,
}

/// Lifecycle of a discovered surface across source refreshes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceState {
    Current,
    NeedsRefresh,
    Removed,
}

/// Interface class used for method compatibility checks.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceKind {
    CommandLine,
    Native,
    Web,
    Api,
    Browser,
    Service,
    File,
    Library,
    Other,
}

/// One concrete application entry surface.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationSurfaceRecord {
    pub schema: u16,
    pub id: RecordId,
    pub campaign: RecordId,
    pub scope_revision: RecordId,
    pub profile: RecordId,
    pub component: RecordId,
    pub name: String,
    pub kind: SurfaceKind,
    pub entry_point: String,
    pub source_paths: Vec<String>,
    pub state: SurfaceState,
    pub invalidated_by: Option<String>,
}

/// One directed trust boundary in the target graph.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustBoundaryRecord {
    pub schema: u16,
    pub id: RecordId,
    pub campaign: RecordId,
    pub scope_revision: RecordId,
    pub profile: RecordId,
    pub name: String,
    pub from_component: RecordId,
    pub to_component: RecordId,
    pub protected_assets: Vec<String>,
}

/// One attacker identity and target configuration combination.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfigurationRecord {
    pub schema: u16,
    pub id: RecordId,
    pub campaign: RecordId,
    pub scope_revision: RecordId,
    pub profile: RecordId,
    pub name: String,
    pub attacker: String,
    pub privileges: Vec<String>,
    pub configuration: Vec<String>,
}

/// One security property independently addressable by coverage cells.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityPropertyRecord {
    pub schema: u16,
    pub id: RecordId,
    pub campaign: RecordId,
    pub family: String,
    pub statement: String,
    pub standards: Vec<StandardReference>,
}

/// Whether a method can presently produce evidence on this host/module generation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MethodAvailability {
    Available,
    Unsupported,
}

/// One coordinator-owned source or runtime examination method.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MethodRecord {
    pub schema: u16,
    pub id: RecordId,
    pub campaign: RecordId,
    pub name: String,
    pub availability: MethodAvailability,
    pub operation: Option<String>,
    pub required_capability: Option<String>,
    pub limitation: String,
}

/// One compiled coverage obligation. `Examined` means only that this exact method ran.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageCellRecord {
    pub schema: u16,
    pub id: RecordId,
    pub campaign: RecordId,
    pub scope_revision: RecordId,
    pub profile: RecordId,
    pub surface: RecordId,
    pub identity_configuration: RecordId,
    pub security_property: RecordId,
    pub method: RecordId,
    pub family: String,
    pub state: CoverageState,
    pub reason: String,
    pub source_paths: Vec<String>,
    pub evidence: Vec<RecordId>,
    pub invalidated_by: Option<String>,
    pub supersedes: Option<RecordId>,
}

/// Lifecycle of a falsifiable security hypothesis.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisState {
    /// Registered but not yet investigated.
    Proposed,
    /// Investigation has begun but has no final classification.
    Investigating,
    /// A finding revision classifies this exact hypothesis.
    Adjudicated,
    /// A named prerequisite currently prevents investigation.
    Blocked,
}

/// One concrete, falsifiable security claim bound to exact source.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HypothesisRecord {
    /// Record schema version.
    pub schema: u16,
    /// Stable hypothesis identity.
    pub id: RecordId,
    /// Owning campaign.
    pub campaign: RecordId,
    /// Exact source snapshot being investigated.
    pub source_snapshot: RecordId,
    /// Attacker privileges and controlled input or action.
    pub attacker: String,
    /// Reachable application entry point.
    pub entry_point: String,
    /// Necessary assumptions that must hold.
    pub prerequisites: Vec<String>,
    /// Security property expected to hold.
    pub security_property: String,
    /// Observation that would distinguish violation from non-violation.
    pub falsifiable_observation: String,
    /// Current lifecycle state.
    pub state: HypothesisState,
    /// Prior hypothesis revision replaced by this record.
    pub supersedes: Option<RecordId>,
}

/// Observed lifecycle of one module worker operation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    /// Accepted but not started.
    Queued,
    /// Running under host ownership.
    Running,
    /// Completed with a retained observation.
    Completed,
    /// Failed with retained diagnostics.
    Failed,
    /// Cancellation completed.
    Cancelled,
    /// Recovery cannot determine whether the effect completed.
    Indeterminate,
}

/// Durable observation of one future module worker operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobRecord {
    /// Record schema version.
    pub schema: u16,
    /// Stable job-record identity.
    pub id: RecordId,
    /// Owning campaign.
    pub campaign: RecordId,
    /// Scope revision admitted for this job.
    pub scope_revision: RecordId,
    /// Source snapshot used by this job.
    pub source_snapshot: RecordId,
    /// Opaque host job identity.
    pub host_job_id: String,
    /// Validated operation/adapter name.
    pub operation: String,
    /// Digest of the admitted request and limits.
    pub request_digest: String,
    /// Observed job lifecycle state.
    pub state: JobState,
    /// Retained execution receipt, when available.
    pub receipt: Option<RecordId>,
}

/// Provenance class for one retained evidence record.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// Exact source file/range observation.
    Source,
    /// Module-authored deterministic analysis over exact immutable source bytes.
    Analysis,
    /// Module-captured HTTP/API traffic and copied-state oracle evidence.
    HttpApi,
    /// Module-captured real-browser, client-state, traffic, screenshot and trace evidence.
    BrowserClient,
    /// Module-captured authentication, session, authorization, tenancy, and redaction evidence.
    IdentityAccess,
    /// Module-captured filesystem, archive, parser, fuzzing, and native-fault evidence.
    FileFuzz,
    /// Module-captured stateful workflow, schedule, retry, and business-invariant evidence.
    WorkflowState,
    /// Module-captured private-network, TLS, privilege-policy, and delegated-authority evidence.
    BoundaryAuthority,
    /// Host-composed cross-adapter graph, counterfactual, and repair replay evidence.
    AttackGraph,
    /// Build or preparation observation.
    Build,
    /// Trusted controller/evaluator execution receipt.
    Execution,
    /// Counterevidence that challenges a necessary premise.
    Counterevidence,
    /// Legitimate behavior control result.
    LegitimateControl,
}

/// Immutable evidence metadata; large bytes remain in a content-addressed artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRecord {
    /// Record schema version.
    pub schema: u16,
    /// Stable evidence identity.
    pub id: RecordId,
    /// Owning campaign.
    pub campaign: RecordId,
    /// Exact scope revision.
    pub scope_revision: RecordId,
    /// Evidence provenance class.
    pub kind: EvidenceKind,
    /// Concise observation, not a model conclusion.
    pub observation: String,
    /// Content-addressed artifact digest holding exact bytes.
    pub artifact_digest: String,
    /// Exact records on which this evidence depends.
    pub dependencies: Vec<RecordId>,
}

/// Honest decision state for one bound security claim.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingClassification {
    /// Trusted execution showed the specified security-property violation.
    Confirmed,
    /// Source/configuration evidence supports the weakness without runtime proof.
    AnalysisSupported,
    /// Counterevidence disproved a necessary premise for this bound claim.
    Refuted,
    /// Legal attempts did not demonstrate the claimed violation.
    NotReproduced,
    /// Available evidence does not settle the claim.
    Inconclusive,
    /// A named prerequisite prevented the required investigation.
    Blocked,
}

/// One immutable adjudicated finding revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FindingRecord {
    /// Record schema version.
    pub schema: u16,
    /// Stable finding identity.
    pub id: RecordId,
    /// Owning campaign.
    pub campaign: RecordId,
    /// Exact source snapshot assessed.
    pub source_snapshot: RecordId,
    /// Stable hypothesis identity within the campaign ledger.
    pub hypothesis_id: String,
    /// Current evidence-bounded classification.
    pub classification: FindingClassification,
    /// Evidence admitted into this decision.
    pub evidence: Vec<RecordId>,
    /// Independent review binding this decision, when required.
    pub review: Option<RecordId>,
    /// Prior finding revision replaced by this one.
    pub supersedes: Option<RecordId>,
}

/// Copy-only lifecycle state of a proposed patch.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchState {
    /// Patch text exists but has not been applied.
    Proposed,
    /// Applied to a disposable copy only.
    AppliedToCopy,
    /// Passed the named retained cases and legitimate controls.
    ValidatedForRecordedCases,
    /// A named replay or legitimate control failed.
    Failed,
    /// A named prerequisite prevented validation.
    Blocked,
}

/// One immutable copy-only patch revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PatchRecord {
    /// Record schema version.
    pub schema: u16,
    /// Stable patch identity.
    pub id: RecordId,
    /// Owning campaign.
    pub campaign: RecordId,
    /// Exact source snapshot to which the patch applies.
    pub source_snapshot: RecordId,
    /// Finding revisions addressed by this patch.
    pub findings: Vec<RecordId>,
    /// Content-addressed unified-diff artifact.
    pub diff_artifact: String,
    /// Current copy-only patch state.
    pub state: PatchState,
    /// Exact validation evidence records.
    pub validations: Vec<RecordId>,
    /// Prior patch revision replaced by this one.
    pub supersedes: Option<RecordId>,
}

/// Independent review disposition for an exact retained subject.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDecision {
    /// Exact subject and admitted evidence support its bounded conclusion.
    Accepted,
    /// Concrete corrections or further observations are required.
    Rejected,
    /// Review could not be completed for a named reason.
    Blocked,
}

/// One immutable independent review revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewRecord {
    /// Record schema version.
    pub schema: u16,
    /// Stable review identity.
    pub id: RecordId,
    /// Owning campaign.
    pub campaign: RecordId,
    /// Exact finding, patch, or report revision reviewed.
    pub subject: RecordId,
    /// Review disposition.
    pub decision: ReviewDecision,
    /// Evidence actually inspected by the reviewer.
    pub evidence: Vec<RecordId>,
    /// Concrete corrections, limitations, or blocked reason.
    pub detail: String,
    /// Prior review revision replaced by this one.
    pub supersedes: Option<RecordId>,
}

/// One immutable human- and machine-readable report revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReportRecord {
    /// Record schema version.
    pub schema: u16,
    /// Stable report identity.
    pub id: RecordId,
    /// Owning campaign.
    pub campaign: RecordId,
    /// Monotonic campaign-local report revision.
    pub revision: u64,
    /// Exact finding revisions presented by this report.
    pub findings: Vec<RecordId>,
    /// Exact review revisions on which presentation relies.
    pub reviews: Vec<RecordId>,
    /// Content-addressed Markdown report artifact.
    pub markdown_artifact: String,
    /// Content-addressed structured JSON report artifact.
    pub json_artifact: String,
    /// Content-addressed SARIF 2.1.0 projection artifact.
    #[serde(default)]
    pub sarif_artifact: Option<String>,
    /// Content-addressed replay bundle, when the report includes Phase-six delivery artifacts.
    #[serde(default)]
    pub reproduction_bundle_artifact: Option<String>,
    /// Content identities of exact unified-diff files in application order.
    #[serde(default)]
    pub patch_artifacts: Vec<String>,
    /// Explicit unresolved work and coverage limitations.
    pub limitations: Vec<String>,
    /// Prior report revision replaced by this one.
    pub supersedes: Option<RecordId>,
}
