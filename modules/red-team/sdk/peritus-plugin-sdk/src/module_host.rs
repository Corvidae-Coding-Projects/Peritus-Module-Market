//! Versioned native-module host-service contracts.
//!
//! These data types describe requests and observations; possessing one never grants authority.
//! The host rechecks current user authority, package identity, scope, and lifecycle ownership before
//! performing an effect.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Version of the module-host profile and service-envelope contract.
pub const MODULE_HOST_CONTRACT_VERSION: u16 = 1;

/// Capability discovery through [`ModuleHostRequest`].
pub const HOST_CAPABILITY_PROFILE: &str = "module.host-profile";
/// Private per-run state directory supplied to native module calls.
pub const HOST_CAPABILITY_PRIVATE_STATE: &str = "module.private-state";
/// Durable continuing module checkpoints.
pub const HOST_CAPABILITY_CHECKPOINT: &str = "module.checkpoint";
/// Host-owned provider invocation requested by a module.
pub const HOST_CAPABILITY_MODEL: &str = "module.model";
/// Explicit private artifact attachment.
pub const HOST_CAPABILITY_ATTACHMENT: &str = "module.attachment";
/// Explicit, revocable source selection and immutable source handles.
pub const HOST_CAPABILITY_SCOPED_SOURCE: &str = "module.scoped-source";
/// Pinned source discovery, local compilation, and inert installation.
pub const HOST_CAPABILITY_SOURCE_BUILD: &str = "module.source-build";
/// Module-owned worker execution in an isolated copy of explicitly scoped source.
pub const HOST_CAPABILITY_WORKER: &str = "module.worker";
/// Host-owned disposable application laboratory lifecycle and observations.
pub const HOST_CAPABILITY_APPLICATION_LABORATORY: &str = "module.application-laboratory";

/// Generic managed browser/Python runtime available to an isolated module worker.
///
/// This grants no browser operation or target authority. The module owns its driver and request
/// semantics; the host only provisions and mounts the credential-free runtime files.
pub const MODULE_WORKER_FEATURE_BROWSER_AUTOMATION: &str = "browser-automation-v1";

/// Credential-free Bun runtime and read-only package cache for an isolated module worker.
///
/// The host projects only generic runtime resources. The module still owns source entry points,
/// commands, target behavior, evidence, and interpretation.
pub const MODULE_WORKER_FEATURE_BUN_RUNTIME: &str = "bun-runtime-v1";
pub const MODULE_WORKER_FEATURE_JAVASCRIPT_RUNTIME: &str = "javascript-runtime-v1";

/// Locked Cargo registry dependencies prepared for an isolated module worker.
///
/// The host reads the disposable source copy's `Cargo.lock`, downloads checksum-pinned crates
/// during preparation, and exposes only that private vendored set to the network-denied worker.
/// The module still owns every command, target recipe, and interpretation of its output.
pub const MODULE_WORKER_FEATURE_CARGO_DEPENDENCIES: &str = "cargo-dependencies-v1";

/// One versioned host service currently available to a native module.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleHostCapability {
    /// Stable lowercase capability name.
    pub name: String,
    /// Highest contract version supported for this capability.
    pub version: u16,
}

/// Additive profile supplied by an updated host on every module call.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleHostProfile {
    /// Profile schema; currently [`MODULE_HOST_CONTRACT_VERSION`].
    pub schema: u16,
    /// Available services. Absence means unsupported, not temporarily failed.
    pub capabilities: Vec<ModuleHostCapability>,
}

impl ModuleHostProfile {
    /// Returns whether the profile supports at least the requested service version.
    #[must_use]
    pub fn supports(&self, name: &str, version: u16) -> bool {
        self.schema == MODULE_HOST_CONTRACT_VERSION
            && self
                .capabilities
                .iter()
                .any(|capability| capability.name == name && capability.version >= version)
    }
}

/// One coordinator-to-host request carried by `ModuleAction::HostService`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleHostRequest {
    /// Durable module-owned request key.
    pub key: String,
    /// Capability named in the host profile.
    pub capability: String,
    /// Exact service contract version requested.
    pub version: u16,
    /// Capability-specific operation name.
    pub operation: String,
    /// Capability-specific structured input; never authority by itself.
    pub input: Value,
}

impl ModuleHostRequest {
    /// Validates the generic envelope before capability-specific input is inspected.
    ///
    /// # Errors
    ///
    /// Returns a stable detail when the request key, capability, version, or operation is not a
    /// valid host-service identity.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !key(&self.key) {
            return Err("invalid module host request key");
        }
        if !name(&self.capability, true) || self.version == 0 {
            return Err("invalid module host capability or version");
        }
        if !name(&self.operation, false) {
            return Err("invalid module host operation");
        }
        Ok(())
    }
}

/// Host observation returned through the coordinator's `host_result` method.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleHostResult {
    /// Exact request key being answered.
    pub key: String,
    /// Exact requested capability.
    pub capability: String,
    /// Exact requested service version.
    pub version: u16,
    /// Typed observed outcome.
    pub outcome: ModuleHostOutcome,
}

/// Result of one host-service request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ModuleHostOutcome {
    /// The host completed the operation.
    Success {
        /// Capability-specific result.
        output: Value,
    },
    /// The capability, version, or operation is unavailable.
    Unsupported {
        /// Actionable compatibility detail.
        detail: String,
    },
    /// Current authority or input validation rejected the operation before its effect.
    Rejected {
        /// Stable rejection code.
        code: String,
        /// Actionable rejection detail.
        detail: String,
    },
    /// Host infrastructure attempted but did not complete the operation.
    Failed {
        /// Stable failure code.
        code: String,
        /// Causal failure detail.
        detail: String,
        /// Whether a fresh authorized action may retry.
        retryable_with_new_action: bool,
    },
}

/// Version-one request to let the user explicitly select application source.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedSourceRequest {
    /// Contract schema, currently one.
    pub schema: u16,
    /// Human-readable reason displayed during selection.
    pub purpose: String,
    /// Whether an immutable content snapshot is required.
    pub immutable_snapshot: bool,
    /// Explicit source-relative paths omitted from the capture.
    pub exclusions: Vec<String>,
    /// Prior authority to refresh. A successful refresh revokes this exact revision.
    pub refresh: Option<ScopedSourceAuthority>,
}

/// Exact opaque source authority supplied back to the host for revalidation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedSourceAuthority {
    /// Opaque host-issued source handle.
    pub handle: String,
    /// Exact authority revision issued with the handle.
    pub scope_revision: String,
}

/// Opaque, revocable source identity returned by the host.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedSourceHandle {
    /// Contract schema, currently one.
    pub schema: u16,
    /// Opaque host handle; it is not a filesystem path.
    pub handle: String,
    /// Authority revision against which access is rechecked.
    pub scope_revision: String,
    /// Digest of captured source bytes and exclusions.
    pub snapshot_digest: String,
    /// Safe host-selected display label.
    pub display_name: String,
    /// Content-addressed identity of the complete original-project byte manifest.
    pub manifest_artifact: String,
    /// Number of included regular files.
    pub file_count: u64,
    /// Number of included source bytes.
    pub total_bytes: u64,
    /// Included files whose verified artifact was reused without rereading source bytes.
    pub reused_files: u64,
    /// Included bytes reused without rereading source bytes.
    pub reused_bytes: u64,
    /// Paths whose content identity differs from the refreshed snapshot.
    pub changed_paths: Vec<String>,
    /// Paths present in the refreshed snapshot's predecessor but no longer included.
    pub removed_paths: Vec<String>,
    /// Effective source-relative exclusions bound into the snapshot identity.
    pub exclusions: Vec<String>,
}

/// Request for one bounded page of an immutable source manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedSourceManifestRequest {
    /// Contract schema, currently one.
    pub schema: u16,
    /// Exact source authority.
    pub authority: ScopedSourceAuthority,
    /// Return entries lexically after this path, or from the beginning when absent.
    pub after: Option<String>,
    /// Requested entry count; the host applies its own upper bound.
    pub maximum_entries: u16,
}

/// One immutable regular-file entry in an original-project byte manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedSourceEntry {
    /// Canonical source-relative path.
    pub path: String,
    /// SHA-256 of the complete file bytes.
    pub digest: String,
    /// Exact byte length.
    pub bytes: u64,
    /// Whether any executable mode bit was observed on supported Unix hosts.
    pub executable: bool,
}

/// Bounded manifest observation returned by the scoped-source broker.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedSourceManifestPage {
    /// Contract schema, currently one.
    pub schema: u16,
    /// Snapshot identity whose entries were returned.
    pub snapshot_digest: String,
    /// Complete manifest artifact identity.
    pub manifest_artifact: String,
    /// Entries in canonical path order.
    pub entries: Vec<ScopedSourceEntry>,
    /// Last returned path when another page exists.
    pub next_after: Option<String>,
    /// Effective exclusions bound into the snapshot.
    pub exclusions: Vec<String>,
}

/// Request for one bounded byte range from an immutable source snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedSourceReadRequest {
    /// Contract schema, currently one.
    pub schema: u16,
    /// Exact source authority.
    pub authority: ScopedSourceAuthority,
    /// Canonical source-relative regular-file path.
    pub path: String,
    /// Zero-based starting byte offset.
    pub offset: u64,
    /// Maximum bytes to return.
    pub maximum_bytes: u64,
}

/// Exact retained observation of one immutable source byte range.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedSourceReadResult {
    /// Contract schema, currently one.
    pub schema: u16,
    /// Snapshot identity used for the read.
    pub snapshot_digest: String,
    /// Canonical source-relative path.
    pub path: String,
    /// Complete source-file digest.
    pub source_digest: String,
    /// Complete source-file byte length.
    pub source_bytes: u64,
    /// Inclusive selected start offset.
    pub range_start: u64,
    /// Exclusive selected end offset.
    pub range_end: u64,
    /// Content-addressed artifact identity for exactly the returned bytes.
    pub range_artifact: String,
    /// Exactly the selected bytes, represented by the enclosing JSON codec.
    pub bytes: Vec<u8>,
    /// Whether an identical durable range receipt already existed.
    pub reused: bool,
}

/// Request to revoke one exact source authority revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedSourceRevokeRequest {
    /// Contract schema, currently one.
    pub schema: u16,
    /// Exact source authority to revoke.
    pub authority: ScopedSourceAuthority,
}

/// Durable revocation observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedSourceRevocation {
    /// Contract schema, currently one.
    pub schema: u16,
    /// Revoked opaque handle.
    pub handle: String,
    /// Revoked scope revision.
    pub scope_revision: String,
    /// Whether this request changed retained authority state.
    pub newly_revoked: bool,
}

/// Request for an exact byte comparison between a retained snapshot and the selected workspace.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedSourceVerifyRequest {
    /// Contract schema, currently one.
    pub schema: u16,
    /// Exact retained authority whose manifest is the comparison baseline.
    pub authority: ScopedSourceAuthority,
}

/// Host-observed before/after proof for the selected original workspace.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedSourceVerification {
    /// Contract schema, currently one.
    pub schema: u16,
    /// Retained source snapshot used as the baseline.
    pub snapshot_digest: String,
    /// Content identity of the newly observed path/digest/mode manifest.
    pub observed_manifest_digest: String,
    /// Whether every included original-project byte and executable bit is unchanged.
    pub unchanged: bool,
    /// Included paths whose bytes or executable bit changed.
    pub changed_paths: Vec<String>,
    /// Newly present, non-excluded regular-file paths.
    pub added_paths: Vec<String>,
    /// Baseline paths no longer present as regular files.
    pub removed_paths: Vec<String>,
}

/// Requested maximum resources for a module-owned job; the host may only narrow them.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleJobLimits {
    /// Maximum aggregate memory in bytes.
    pub memory_bytes: u64,
    /// Maximum disposable storage in bytes.
    pub storage_bytes: u64,
    /// Maximum aggregate CPU time in milliseconds.
    pub cpu_millis: u64,
    /// Maximum elapsed time in milliseconds.
    pub wall_millis: u64,
    /// Maximum owned process count.
    pub processes: u32,
}

/// Version-one request for a module-owned operation in a scoped disposable copy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleJobRequest {
    /// Contract schema, currently one.
    pub schema: u16,
    /// Opaque host-issued source handle.
    pub source_handle: String,
    /// Exact scope revision authorizing the request.
    pub scope_revision: String,
    /// Stable adapter/recipe interpreted and validated by the host.
    pub operation: String,
    /// Adapter-specific structured specification.
    pub specification: Value,
    /// Requested ceilings, narrowed and recorded by the host.
    pub limits: ModuleJobLimits,
}

/// Opaque identity of one accepted module-owned job.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleJobHandle {
    /// Contract schema, currently one.
    pub schema: u16,
    /// Opaque module-owned job identity.
    pub job_id: String,
    /// Source handle bound to the job.
    pub source_handle: String,
    /// Scope revision bound to the job.
    pub scope_revision: String,
}

/// Lifecycle state observed by the host for one accepted job.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleJobPhase {
    /// The request is durably accepted but execution has not started.
    Queued,
    /// A native process is running under host ownership.
    Running,
    /// The trusted controller produced a retained receipt.
    Completed,
    /// Preparation or execution failed with retained diagnostics.
    Failed,
    /// Cancellation completed and descendants were reaped.
    Cancelled,
    /// Restart recovery cannot prove the prior process outcome.
    Indeterminate,
}

/// Retained stream selected for a bounded job-log read.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleJobStream {
    /// Target standard output.
    Stdout,
    /// Target standard error.
    Stderr,
    /// Host controller diagnostics, never target-supplied proof.
    Controller,
}

/// Trusted controller classification for one exact proof case.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleJobVerdict {
    /// The independently selected oracle observed the specified violation.
    ViolationObserved,
    /// The selected case completed without the oracle observing that violation.
    PropertyHeldForCase,
    /// Infrastructure or lifecycle facts do not support either conclusion.
    Indeterminate,
}

/// Module-authored identity and exact diff for a copy-only target patch.
///
/// The host constructs this receipt from the immutable source artifact and replacement bytes. A
/// module cannot use it to write the selected source checkout.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModulePatchReceipt {
    /// Content identity of the patch, independent of any individual replay case.
    pub patch_digest: String,
    /// Canonical source-relative path changed in the disposable copy.
    pub source_path: String,
    /// Digest of the immutable source file before the patch.
    pub original_digest: String,
    /// Digest of the replacement bytes executed by the host.
    pub patched_digest: String,
    /// Content identity of the exact unified diff.
    pub diff_artifact: String,
    /// Exact bounded unified diff bytes retained for export and independent review.
    pub diff_bytes: Vec<u8>,
    /// Stable module-owned replay case identity.
    pub case_id: String,
    /// Finding identities the patch claims to address.
    pub findings: Vec<String>,
    /// Declared prerequisites bound into the patch identity.
    pub prerequisites: Vec<String>,
    /// Application order within a multi-patch plan.
    pub order: u32,
    /// Earlier patch identities required by this patch.
    pub dependencies: Vec<String>,
}

/// Poll request for one exact opaque job identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleJobStatusRequest {
    /// Contract schema, currently one.
    pub schema: u16,
    /// Opaque module-owned job identity.
    pub job_id: String,
    /// Optional bounded long-poll duration; the host may narrow it.
    pub wait_millis: u64,
}

/// Bounded retained-stream request for one exact job.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleJobLogRequest {
    /// Contract schema, currently one.
    pub schema: u16,
    /// Opaque module-owned job identity.
    pub job_id: String,
    /// Exact retained stream.
    pub stream: ModuleJobStream,
    /// Zero-based byte offset.
    pub offset: u64,
    /// Requested byte count; the host applies its own upper bound.
    pub maximum_bytes: u64,
}

/// Idempotent cancellation request for one exact job.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleJobCancelRequest {
    /// Contract schema, currently one.
    pub schema: u16,
    /// Opaque module-owned job identity.
    pub job_id: String,
    /// Bounded user-facing reason retained by the host.
    pub reason: String,
}

/// Module-authored execution receipt. Target output cannot construct this value.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleJobReceipt {
    /// Contract schema, currently one.
    pub schema: u16,
    /// Opaque job identity.
    pub job_id: String,
    /// Stable validated module adapter.
    pub operation: String,
    /// Digest of the admitted request and narrowed limits.
    pub request_digest: String,
    /// Digest of the exact enabled native module package.
    pub module_digest: String,
    /// Opaque source authority used by the job.
    pub source_handle: String,
    /// Exact source authority revision.
    pub scope_revision: String,
    /// Immutable selected-source snapshot identity.
    pub snapshot_digest: String,
    /// Digest of the exact launched target bytes.
    pub target_digest: String,
    /// Native sandbox backend name and version.
    pub backend: String,
    /// Digest of the checked execution plan.
    pub execution_plan_digest: String,
    /// Digest of the module-selected oracle inputs and comparison rule.
    pub oracle_digest: String,
    /// Independent controller classification.
    pub verdict: ModuleJobVerdict,
    /// Stable terminal disposition observed by the process owner.
    pub terminal_disposition: String,
    /// Numeric exit status when the platform supplied one.
    pub exit_code: Option<i32>,
    /// Complete retained stdout artifact identity.
    pub stdout_artifact: String,
    /// Complete retained stderr artifact identity.
    pub stderr_artifact: String,
    /// Effective host-narrowed limits.
    pub limits: ModuleJobLimits,
    /// Whether the complete target tree and support tasks were observed stopped.
    pub cleanup_complete: bool,
    /// Enforced network policy name.
    pub network_policy: String,
    /// Dependency-preparation provenance, absent for proof execution jobs.
    pub preparation: Option<ModulePreparationReceipt>,
    /// Copy-only patch identity and diff, present only for a patched replay adapter.
    #[serde(default)]
    pub patch: Option<ModulePatchReceipt>,
}

/// Module-authored provenance for one constrained dependency retrieval.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModulePreparationReceipt {
    /// Original declared HTTPS URL.
    pub requested_url: String,
    /// Final HTTPS URL after bounded, independently revalidated redirects.
    pub final_url: String,
    /// Ordered redirect targets, excluding the original request.
    pub redirects: Vec<String>,
    /// Public socket addresses pinned for each attempted HTTPS origin.
    pub resolved_addresses: Vec<String>,
    /// Exact retained dependency byte length.
    pub bytes: u64,
    /// Content-addressed artifact identity for the retained dependency.
    pub artifact_digest: String,
}

/// Current retained observation of one module-owned job.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleJobStatus {
    /// Contract schema, currently one.
    pub schema: u16,
    /// Opaque job identity.
    pub job_id: String,
    /// Current lifecycle phase.
    pub phase: ModuleJobPhase,
    /// Stable validated module adapter.
    pub operation: String,
    /// Digest of the admitted request and narrowed limits.
    pub request_digest: String,
    /// Effective host-narrowed limits.
    pub limits: ModuleJobLimits,
    /// Terminal trusted receipt, when one exists.
    pub receipt: Option<ModuleJobReceipt>,
    /// Module-authored diagnostic; never a proof verdict by itself.
    pub detail: String,
}

/// One bounded retained-stream page.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleJobLogPage {
    /// Contract schema, currently one.
    pub schema: u16,
    /// Opaque job identity.
    pub job_id: String,
    /// Exact retained stream.
    pub stream: ModuleJobStream,
    /// Inclusive returned start offset.
    pub range_start: u64,
    /// Exclusive returned end offset.
    pub range_end: u64,
    /// Total retained bytes observed for this stream.
    pub total_bytes: u64,
    /// Exact returned bytes.
    pub bytes: Vec<u8>,
}

/// Pinned source identity for one locally built market package.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePackageRequest {
    /// Contract schema, currently one.
    pub schema: u16,
    /// Stable module identifier.
    pub module_id: String,
    /// Immutable source commit.
    pub source_commit: String,
    /// Digest of the selected source tree.
    pub source_digest: String,
    /// Safe repository-relative module path.
    pub module_path: String,
    /// Digest of the exact dependency lockfile.
    pub lockfile_digest: String,
    /// Pinned toolchain identity.
    pub toolchain: String,
    /// Requested compilation target.
    pub target: String,
}

/// Distinct source, recipe, executable, and package identities from a local source build.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalPackageIdentity {
    /// Contract schema, currently one.
    pub schema: u16,
    /// Stable module identifier.
    pub module_id: String,
    /// Digest of the source inputs.
    pub source_digest: String,
    /// Digest of the validated build recipe.
    pub recipe_digest: String,
    /// Actual compilation target.
    pub target: String,
    /// Digest of the produced executable.
    pub executable_digest: String,
    /// Digest of the installed local package.
    pub package_digest: String,
}

/// Resource ceilings requested for one module-owned worker; the host may only narrow them.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleWorkerLimits {
    /// Maximum elapsed execution time in milliseconds.
    pub wall_millis: u64,
    /// Maximum aggregate memory in bytes.
    pub memory_bytes: u64,
    /// Maximum disposable storage in bytes.
    pub storage_bytes: u64,
    /// Maximum owned process count.
    pub processes: u32,
    /// Maximum simultaneously open file descriptors across each worker process.
    pub open_handles: u32,
}

/// Generic request to execute the selected module's own worker against disposable source.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleWorkerRequest {
    /// Request schema, currently one.
    pub schema: u16,
    /// Exact source authority selected by the user.
    pub source: ScopedSourceAuthority,
    /// Module-defined worker name; the host does not interpret its meaning.
    pub worker: String,
    /// Opaque module-owned JSON input serialized to the worker's standard input.
    pub input: Value,
    /// Optional named host runtime features. Names are generic execution resources rather than
    /// module, adapter, or vulnerability identities. Unknown features are rejected.
    #[serde(default)]
    pub runtime_features: Vec<String>,
    /// Requested ceilings narrowed by the host.
    pub limits: ModuleWorkerLimits,
}

/// Raw host observation from one isolated module-owned worker.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleWorkerResult {
    /// Result schema, currently one.
    pub schema: u16,
    /// Exact module-defined worker name.
    pub worker: String,
    /// Stable terminal disposition observed by the host process owner.
    pub terminal_disposition: String,
    /// Numeric exit code when the platform supplied one.
    pub exit_code: Option<i32>,
    /// Bounded raw standard output.
    pub stdout: Vec<u8>,
    /// Bounded raw standard error.
    pub stderr: Vec<u8>,
    /// Digest of the checked execution plan.
    pub execution_plan_digest: String,
    /// Whether the complete owned process tree and support tasks stopped.
    pub cleanup_complete: bool,
    /// Whether the selected original source still matches its retained snapshot.
    pub original_source_unchanged: bool,
}

/// Exact operating-system and architecture identity admitted for an adapter runtime.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAdapterPlatform {
    /// Rust-style operating-system name such as `linux`.
    pub os: String,
    /// Rust-style architecture name such as `x86_64`.
    pub architecture: String,
}

/// One operation and its versioned input/receipt schemas in an allowlisted adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAdapterOperation {
    /// Stable operation name interpreted by the host registry.
    pub name: String,
    /// Stable input schema identity.
    pub input_schema: String,
    /// Stable host receipt schema identity.
    pub receipt_schema: String,
}

/// Complete immutable descriptor that must exactly match the host registry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAdapterDescriptor {
    /// Descriptor schema, currently one.
    pub schema: u16,
    /// Stable adapter identifier.
    pub adapter_id: String,
    /// Adapter implementation version.
    pub version: String,
    /// Only platform on which this descriptor may be prepared.
    pub platform: ModuleAdapterPlatform,
    /// SHA-256 of the exact managed artifact bytes.
    pub artifact_digest: String,
    /// Exact artifact byte length.
    pub artifact_bytes: u64,
    /// License identifier retained in provenance.
    pub license: String,
    /// Exact allowlisted operation set.
    pub operations: Vec<ModuleAdapterOperation>,
    /// Stable decoder used for every module-authored receipt.
    pub receipt_decoder: String,
}

/// Host registry projection available without preparing an adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAdapterCatalog {
    /// Catalog schema, currently one.
    pub schema: u16,
    /// Descriptors available on this exact host platform.
    pub descriptors: Vec<ModuleAdapterDescriptor>,
}

/// Request to stage one exact registered adapter artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAdapterPrepareRequest {
    /// Request schema, currently one.
    pub schema: u16,
    /// Complete descriptor expected by the module.
    pub descriptor: ModuleAdapterDescriptor,
}

/// Opaque preparation identity returned after durable staging.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAdapterPreparationHandle {
    /// Handle schema, currently one.
    pub schema: u16,
    /// Opaque content-bound preparation identity.
    pub preparation_id: String,
    /// Digest of the exact admitted descriptor.
    pub descriptor_digest: String,
}

/// Request to finish a previously staged preparation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAdapterCompleteRequest {
    /// Request schema, currently one.
    pub schema: u16,
    /// Exact opaque preparation identity.
    pub preparation_id: String,
}

/// Request to cancel a previously staged preparation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAdapterCancelRequest {
    /// Request schema, currently one.
    pub schema: u16,
    /// Exact opaque preparation identity.
    pub preparation_id: String,
    /// Bounded human-readable reason retained by the host.
    pub reason: String,
}

/// Lifecycle state retained for an adapter preparation or runtime.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleAdapterPhase {
    /// No preparation or installed runtime exists for this adapter.
    NotInstalled,
    /// Exact artifact bytes are staged but are not available for execution.
    Staged,
    /// Exact bytes were verified and installed privately.
    Installed,
    /// Staging was cancelled and its bytes were removed.
    Cancelled,
    /// Preparation or recovery failed with retained detail.
    Failed,
    /// The installed bytes were removed; historical identity remains readable.
    Removed,
}

/// Content-addressed identity required for every adapter execution and removal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAdapterRuntimeIdentity {
    /// Identity schema, currently one.
    pub schema: u16,
    /// Stable adapter identifier.
    pub adapter_id: String,
    /// Exact adapter version.
    pub version: String,
    /// Digest of the registered descriptor.
    pub descriptor_digest: String,
    /// Digest of the installed artifact bytes.
    pub artifact_digest: String,
    /// Exact admitted platform.
    pub platform: ModuleAdapterPlatform,
    /// Digest binding all runtime identity dimensions.
    pub runtime_digest: String,
}

/// Module-authored provenance for exact prepared and installed bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAdapterProvenanceReceipt {
    /// Receipt schema, currently one.
    pub schema: u16,
    /// Digest of the exact registered descriptor.
    pub descriptor_digest: String,
    /// Digest of the exact installed bytes.
    pub artifact_digest: String,
    /// Exact installed byte count.
    pub artifact_bytes: u64,
    /// Host registry source identity; never a caller-controlled path.
    pub source: String,
    /// Retained license identifier.
    pub license: String,
}

/// Current durable adapter status returned after lifecycle operations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAdapterStatus {
    /// Status schema, currently one.
    pub schema: u16,
    /// Stable adapter identifier.
    pub adapter_id: String,
    /// Most recent preparation identity, when one exists.
    pub preparation_id: Option<String>,
    /// Current lifecycle phase.
    pub phase: ModuleAdapterPhase,
    /// Installed content identity, when available or retained historically.
    pub runtime: Option<ModuleAdapterRuntimeIdentity>,
    /// Module-authored provenance, when exact bytes were admitted.
    pub provenance: Option<ModuleAdapterProvenanceReceipt>,
    /// Whether an identical installed runtime was reused.
    pub reused: bool,
    /// Actionable host lifecycle detail.
    pub detail: String,
    /// Retained causal error, if recovery or preparation failed.
    pub retained_error: Option<String>,
}

/// Request for current status by stable registered adapter identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAdapterStatusRequest {
    /// Request schema, currently one.
    pub schema: u16,
    /// Stable registered adapter identifier.
    pub adapter_id: String,
}

/// Request to remove one exact content-addressed runtime.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAdapterRemoveRequest {
    /// Request schema, currently one.
    pub schema: u16,
    /// Exact runtime identity previously returned by the host.
    pub runtime: ModuleAdapterRuntimeIdentity,
}

/// Request to execute one registered operation through its trusted module implementation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAdapterExecuteRequest {
    /// Request schema, currently one.
    pub schema: u16,
    /// Exact installed runtime identity.
    pub runtime: ModuleAdapterRuntimeIdentity,
    /// Exact operation registered by the descriptor.
    pub operation: String,
    /// Operation input validated against the registered schema.
    pub input: Value,
}

/// Module-authored receipt from one exact registered adapter operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAdapterExecutionReceipt {
    /// Receipt schema, currently one.
    pub schema: u16,
    /// Exact runtime digest.
    pub runtime_digest: String,
    /// Exact registered operation.
    pub operation: String,
    /// Digest of canonical admitted input bytes.
    pub input_digest: String,
    /// Stable registered receipt decoder.
    pub receipt_decoder: String,
    /// Typed operation observation.
    pub observation: Value,
    /// Trusted implementation identity that produced the observation.
    pub executed_by: String,
}

/// Bounded source inputs accepted by the registered static-analysis adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleSourceAnalysisLimits {
    /// Maximum number of immutable source files examined.
    pub maximum_files: u32,
    /// Maximum bytes read from any one immutable source file.
    pub maximum_file_bytes: u64,
    /// Maximum aggregate immutable source bytes examined.
    pub maximum_total_bytes: u64,
}

/// Request for deterministic analysis of one exact scoped-source snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleSourceAnalysisRequest {
    /// Request schema, currently one.
    pub schema: u16,
    /// Exact revocable immutable source authority selected by the user.
    pub source: ScopedSourceAuthority,
    /// Host-enforced scan bounds.
    pub limits: ModuleSourceAnalysisLimits,
}

/// One pinned analysis implementation contributing to an observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleSourceAnalysisTool {
    /// Stable analyzer identifier.
    pub id: String,
    /// Exact analyzer version.
    pub version: String,
    /// Analysis kind, such as language discovery or pattern matching.
    pub kind: String,
    /// Languages or configuration formats this analyzer handles.
    pub supports: Vec<String>,
}

/// Observed source-language inventory for one immutable snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleSourceLanguageObservation {
    /// Stable language name.
    pub language: String,
    /// Number of files recognized as this language.
    pub files: u64,
    /// Bytes examined for this language.
    pub bytes: u64,
    /// Highest analysis depth available for this language.
    pub support: String,
}

/// One discovered package or infrastructure manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleSourceManifestObservation {
    /// Source-relative manifest path.
    pub path: String,
    /// Ecosystem or configuration family.
    pub ecosystem: String,
    /// Digest of the immutable manifest bytes.
    pub digest: String,
    /// Parser disposition retained for coverage reporting.
    pub status: String,
}

/// Reachability classification for dependency and source leads.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleSourceReachability {
    /// Referenced by non-test source in the captured snapshot.
    RuntimeReferenced,
    /// Referenced only by test, example, fixture, or development configuration.
    TestOnly,
    /// Declared but not referenced by recognized source in the snapshot.
    Unreachable,
    /// The bounded analyzer could not establish reachability.
    Unknown,
}

/// One normalized component in the deterministic source SBOM.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleSourceComponentObservation {
    /// Package ecosystem.
    pub ecosystem: String,
    /// Declared component name.
    pub name: String,
    /// Resolved or declared version, when available.
    pub version: Option<String>,
    /// Manifest or lockfile that supplied this component.
    pub source_path: String,
    /// Runtime, development, test, or unresolved dependency scope.
    pub scope: String,
    /// Bounded source-reference classification.
    pub reachability: ModuleSourceReachability,
    /// Pinned advisory identifiers associated with this exact component version.
    pub advisories: Vec<String>,
}

/// Normalized severity for deterministic source leads.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleSourceSeverity {
    /// Informational hardening or inventory lead.
    Informational,
    /// Low-impact weakness requiring contextual review.
    Low,
    /// Material weakness that is not runtime-confirmed.
    Medium,
    /// High-impact source lead that is not runtime-confirmed.
    High,
    /// Critical source lead that is not runtime-confirmed.
    Critical,
}

/// One deduplicated source-only lead emitted by the module analyzer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleSourceFindingObservation {
    /// Stable content-derived lead identity.
    pub id: String,
    /// Security family or source-analysis category.
    pub category: String,
    /// Exact pinned rule identifier.
    pub rule_id: String,
    /// Normalized lead severity.
    pub severity: ModuleSourceSeverity,
    /// Source-relative file containing the observation.
    pub path: String,
    /// One-based source line when applicable.
    pub line: Option<u64>,
    /// Redacted human-readable observation.
    pub message: String,
    /// Stable root-cause grouping key.
    pub root_cause: String,
    /// Digest of the exact normalized evidence, never secret material.
    pub evidence_digest: String,
    /// Whether potentially sensitive matched bytes were removed from the observation.
    pub redacted: bool,
    /// Bounded reachability classification.
    pub reachability: ModuleSourceReachability,
    /// Evidence boundary, always `source_lead` for this contract version.
    pub evidence_state: String,
    /// Standards or weakness mappings attached by the pinned rule.
    pub standards: Vec<String>,
    /// Total number of raw matches grouped into this root cause.
    pub deduplicated_from: u64,
}

/// One exact redacted analyzer match retained before root-cause deduplication.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleSourceRawFindingObservation {
    /// Stable content-derived raw match identity.
    pub id: String,
    /// Exact pinned analyzer identity that produced the match.
    pub tool_id: String,
    /// Exact pinned rule identifier.
    pub rule_id: String,
    /// Source-relative file containing the match.
    pub path: String,
    /// One-based source line when applicable.
    pub line: Option<u64>,
    /// Redacted analyzer message.
    pub message: String,
    /// Digest of the matched evidence, never secret material.
    pub evidence_digest: String,
    /// Whether potentially sensitive matched bytes were removed.
    pub redacted: bool,
    /// Bounded reachability classification.
    pub reachability: ModuleSourceReachability,
    /// Evidence boundary, always `source_lead` for this contract version.
    pub evidence_state: String,
}

/// Complete module-authored result of one deterministic immutable-source scan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleSourceAnalysisObservation {
    /// Observation schema, currently one.
    pub schema: u16,
    /// Exact immutable source snapshot analyzed.
    pub source_snapshot: String,
    /// Pinned analyzer-set identity.
    pub analyzer_set_version: String,
    /// Pinned rule-set identity.
    pub rule_set_version: String,
    /// Pinned advisory dataset identity.
    pub advisory_dataset_version: String,
    /// Exact participating tool identities and support declarations.
    pub tools: Vec<ModuleSourceAnalysisTool>,
    /// Language inventory.
    pub languages: Vec<ModuleSourceLanguageObservation>,
    /// Discovered package and configuration manifests.
    pub manifests: Vec<ModuleSourceManifestObservation>,
    /// Normalized deterministic source SBOM.
    pub components: Vec<ModuleSourceComponentObservation>,
    /// Exact redacted pre-deduplication analyzer matches.
    pub raw_findings: Vec<ModuleSourceRawFindingObservation>,
    /// Root-cause-deduplicated source leads.
    pub findings: Vec<ModuleSourceFindingObservation>,
    /// Number of immutable files examined.
    pub scanned_files: u64,
    /// Number of immutable bytes examined.
    pub scanned_bytes: u64,
    /// Files skipped because they exceeded the per-file bound.
    pub skipped_oversized_files: u64,
    /// Files skipped because they were not supported text inputs.
    pub skipped_binary_files: u64,
    /// Whether the aggregate file or byte bound stopped traversal early.
    pub truncated: bool,
    /// Digest of the canonical raw pre-deduplication result stream.
    pub raw_result_digest: String,
    /// Explicit limitations that remain after this scan.
    pub gaps: Vec<String>,
}

/// Bounded request for the registered HTTP and API campaign adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleHttpApiCampaignRequest {
    /// Request schema, currently one.
    pub schema: u16,
    /// Exact ready disposable laboratory identity.
    pub laboratory_id: String,
    /// Opaque endpoint issued for that laboratory.
    pub endpoint_handle: String,
    /// Pinned module campaign profile.
    pub profile: String,
    /// Maximum network exchanges admitted for this campaign.
    pub maximum_requests: u32,
    /// Maximum serialized bytes in any request.
    pub maximum_request_bytes: u64,
    /// Maximum serialized bytes retained from any response.
    pub maximum_response_bytes: u64,
}

/// Protocol family exercised by one API observation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleHttpApiProtocol {
    /// Ordinary HTTP REST behavior.
    Rest,
    /// `OpenAPI` discovery and schema import.
    OpenApi,
    /// GraphQL request behavior.
    GraphQl,
    /// WebSocket upgrade and framed exchange.
    WebSocket,
    /// JSON-RPC over HTTP.
    JsonRpc,
}

/// Module-oracle disposition for one executed API case.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleHttpApiDisposition {
    /// Required ordinary behavior was observed.
    Passed,
    /// The target rejected an intentionally invalid or unauthorized input.
    Rejected,
    /// The discovered or probed route was not reachable.
    Unreachable,
    /// A pinned independent oracle observed a security violation.
    Violation,
}

/// One normalized HTTP header without credential material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleHttpHeader {
    /// Lowercase header name.
    pub name: String,
    /// Bounded redacted header value.
    pub value: String,
}

/// Exact replayable request admitted by the host.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleHttpRequestObservation {
    /// HTTP method.
    pub method: String,
    /// Origin-form request target.
    pub target: String,
    /// Bounded non-secret request headers.
    pub headers: Vec<ModuleHttpHeader>,
    /// Exact UTF-8 request body; empty when no body was sent.
    pub body: String,
    /// SHA-256 of the complete serialized request bytes.
    pub digest: String,
    /// Complete serialized request byte count.
    pub bytes: u64,
}

/// Bounded response observed directly by the host transport.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleHttpResponseObservation {
    /// HTTP status code.
    pub status: u16,
    /// Bounded redacted response headers.
    pub headers: Vec<ModuleHttpHeader>,
    /// Bounded UTF-8 response preview with target-only values redacted.
    pub body: String,
    /// SHA-256 of the exact unredacted response bytes observed by the host.
    pub digest: String,
    /// Exact response byte count observed by the host.
    pub bytes: u64,
    /// Whether target-only bytes were removed before this observation was returned.
    pub redacted: bool,
}

/// Imported route and parameter inventory item.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleHttpRouteObservation {
    /// Route template.
    pub path: String,
    /// Declared methods in canonical order.
    pub methods: Vec<String>,
    /// Declared parameter names in canonical order.
    pub parameters: Vec<String>,
    /// Discovery source, such as `openapi-live-response`.
    pub source: String,
}

/// One real request/response and state-oracle observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleHttpApiCaseObservation {
    /// Stable case identity from the pinned suite.
    pub id: String,
    /// Protocol family.
    pub protocol: ModuleHttpApiProtocol,
    /// Security or compatibility dimension.
    pub category: String,
    /// Module-oracle disposition.
    pub disposition: ModuleHttpApiDisposition,
    /// Exact request suitable for replay.
    pub request: ModuleHttpRequestObservation,
    /// Direct host-observed response.
    pub response: ModuleHttpResponseObservation,
    /// Copied target-store digest before the request.
    pub state_before_digest: String,
    /// Copied target-store digest after the request.
    pub state_after_digest: String,
    /// State keys whose values changed, without their values.
    pub changed_state_keys: Vec<String>,
    /// Independent pinned oracle and its result.
    pub oracle: String,
    /// Whether the retained request is the minimized reproducer for this case.
    pub minimized: bool,
}

/// One runtime-confirmed violation with its exact replay request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleHttpApiFindingObservation {
    /// Stable content-derived finding identity.
    pub id: String,
    /// Case that established the violation.
    pub case_id: String,
    /// Security category.
    pub category: String,
    /// Normalized severity.
    pub severity: ModuleSourceSeverity,
    /// Redacted factual observation.
    pub message: String,
    /// Evidence boundary, always `runtime_confirmed` for this type.
    pub evidence_state: String,
    /// Whether copied target state independently changed.
    pub state_change_observed: bool,
    /// Standards or weakness mappings attached by the pinned oracle.
    pub standards: Vec<String>,
    /// Exact minimized request digest.
    pub replay_request_digest: String,
}

/// Complete module-authored HTTP/API campaign observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleHttpApiObservation {
    /// Observation schema, currently one.
    pub schema: u16,
    /// Exact disposable laboratory identity.
    pub laboratory_id: String,
    /// Immutable source snapshot executed in the laboratory.
    pub source_snapshot: String,
    /// Pinned adapter implementation identity.
    pub adapter_version: String,
    /// Pinned request suite and oracle identity.
    pub suite_version: String,
    /// Digest of the imported live `OpenAPI` document, when available.
    pub imported_schema_digest: Option<String>,
    /// Imported route and parameter inventory.
    pub routes: Vec<ModuleHttpRouteObservation>,
    /// Executed real-interface cases.
    pub cases: Vec<ModuleHttpApiCaseObservation>,
    /// Runtime-confirmed violations only.
    pub findings: Vec<ModuleHttpApiFindingObservation>,
    /// Digest of the ordered request/response receipt stream.
    pub traffic_digest: String,
    /// Total real network exchanges.
    pub requests_executed: u64,
    /// Total serialized request bytes.
    pub request_bytes: u64,
    /// Total serialized response bytes.
    pub response_bytes: u64,
    /// Final copied target-store digest.
    pub final_state_digest: String,
    /// Explicit protocol and oracle gaps.
    pub gaps: Vec<String>,
}

/// Bounded request for the registered real-browser client campaign adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleBrowserCampaignRequest {
    /// Request schema, currently one.
    pub schema: u16,
    /// Exact ready disposable laboratory identity.
    pub laboratory_id: String,
    /// Opaque endpoint issued for that laboratory.
    pub endpoint_handle: String,
    /// Pinned module campaign profile.
    pub profile: String,
    /// Maximum browser actions admitted for this campaign.
    pub maximum_actions: u32,
    /// Maximum browser-originated requests admitted for this campaign.
    pub maximum_requests: u32,
    /// Maximum aggregate retained artifact bytes.
    pub maximum_artifact_bytes: u64,
}

/// Module-oracle disposition for one executed browser case.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleBrowserDisposition {
    /// Required ordinary client behavior was observed.
    Passed,
    /// The safe twin rejected or neutralized the attack behavior.
    Rejected,
    /// A pinned independent oracle observed a security violation.
    Violation,
    /// Browser infrastructure could not establish a conclusion.
    Indeterminate,
}

/// One route or client-rendered destination discovered through the real browser.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleBrowserCoverageNode {
    /// Origin-form path, without credentials or a host address.
    pub path: String,
    /// Discovery kind such as `document`, `anchor`, or `client_rendered_anchor`.
    pub kind: String,
    /// Exact case that discovered the node.
    pub discovered_by: String,
}

/// One content-addressed browser artifact retained by the host.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleBrowserArtifact {
    /// Artifact kind such as `screenshot`, `trace`, `traffic`, `download`, or `upload`.
    pub kind: String,
    /// SHA-256 of the complete retained bytes.
    pub digest: String,
    /// Exact retained byte length.
    pub bytes: u64,
    /// Stable case identity associated with the artifact, when applicable.
    pub case_id: Option<String>,
}

/// One real-browser action sequence and independent copied-state observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleBrowserCaseObservation {
    /// Stable case identity from the pinned suite.
    pub id: String,
    /// Security or coverage dimension.
    pub category: String,
    /// Module-oracle disposition.
    pub disposition: ModuleBrowserDisposition,
    /// Redacted browser-observed effect.
    pub browser_effect: String,
    /// Redacted host-observed copied-state effect.
    pub server_effect: String,
    /// Origin-form request paths correlated to this case.
    pub request_paths: Vec<String>,
    /// Digest of the retained replay inputs and expected oracle.
    pub replay_digest: String,
    /// Whether the case was repeated in a fresh isolated browser context.
    pub replayed_after_reset: bool,
}

/// One runtime-confirmed client-side violation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleBrowserFindingObservation {
    /// Stable content-derived finding identity.
    pub id: String,
    /// Case that established the violation.
    pub case_id: String,
    /// Security category.
    pub category: String,
    /// Normalized severity.
    pub severity: ModuleSourceSeverity,
    /// Redacted factual observation.
    pub message: String,
    /// Evidence boundary, always `runtime_confirmed` for this type.
    pub evidence_state: String,
    /// Whether copied target state independently corroborated the browser effect.
    pub state_change_observed: bool,
    /// Standards or weakness mappings attached by the pinned oracle.
    pub standards: Vec<String>,
    /// Digest of the exact replay inputs and oracle.
    pub replay_digest: String,
}

/// Complete module-authored real-browser campaign observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleBrowserObservation {
    /// Observation schema, currently one.
    pub schema: u16,
    /// Exact disposable laboratory identity.
    pub laboratory_id: String,
    /// Immutable source snapshot executed in the laboratory.
    pub source_snapshot: String,
    /// Pinned browser adapter implementation identity.
    pub adapter_version: String,
    /// Pinned action suite and oracle identity.
    pub suite_version: String,
    /// Exact browser engine/version observed by the controller.
    pub browser_identity: String,
    /// Executed real-browser cases.
    pub cases: Vec<ModuleBrowserCaseObservation>,
    /// Runtime-confirmed violations only.
    pub findings: Vec<ModuleBrowserFindingObservation>,
    /// Traditional and client-rendered coverage graph nodes.
    pub coverage: Vec<ModuleBrowserCoverageNode>,
    /// Content-addressed retained artifacts.
    pub artifacts: Vec<ModuleBrowserArtifact>,
    /// Digest of the ordered browser request/response stream.
    pub traffic_digest: String,
    /// Total browser-originated requests admitted by the controller.
    pub requests_observed: u64,
    /// Total browser actions performed by the pinned suite.
    pub actions_executed: u64,
    /// Final copied target-store digest observed outside the browser.
    pub final_state_digest: String,
    /// Whether a fresh context began without prior cookies or storage.
    pub context_isolation_observed: bool,
    /// Number of off-scope browser requests blocked by the host controller.
    pub off_scope_requests_blocked: u64,
    /// Explicit client, platform, and oracle gaps.
    pub gaps: Vec<String>,
}

/// Bounded request for the registered authentication and authorization campaign adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleIdentityAccessCampaignRequest {
    /// Request schema, currently one.
    pub schema: u16,
    /// Exact ready disposable laboratory identity.
    pub laboratory_id: String,
    /// Opaque endpoint issued for that laboratory.
    pub endpoint_handle: String,
    /// Pinned module campaign profile.
    pub profile: String,
    /// Pinned laboratory identity topology selected for this campaign.
    pub identity_profile: String,
    /// Maximum real application operations admitted for this campaign.
    pub maximum_operations: u32,
    /// Maximum serialized bytes retained from any target response.
    pub maximum_response_bytes: u64,
}

/// Module-oracle disposition for one identity or access-control case.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleIdentityAccessDisposition {
    /// Required legitimate identity behavior was observed.
    Passed,
    /// The target rejected the unauthorized or invalid action.
    Rejected,
    /// A pinned differential or lifecycle oracle observed a security violation.
    Violation,
    /// The host could not establish a conclusion.
    Indeterminate,
}

/// Credential-free identity and tenant projection created by the host.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleIdentityRoleObservation {
    /// Opaque identity handle; never a login name or credential.
    pub identity_handle: String,
    /// Normalized role used by the differential oracle.
    pub role: String,
    /// Opaque tenant membership, absent for anonymous identities.
    pub tenant_handle: Option<String>,
    /// Whether the identity is expected to hold privileged application authority.
    pub privileged: bool,
    /// Host-controlled credential source, such as `laboratory_generated`.
    pub credential_source: String,
}

/// Durable lifecycle state for one opaque application session.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleIdentitySessionPhase {
    /// No authenticated session exists.
    Anonymous,
    /// The target issued an MFA or recovery challenge.
    ChallengeIssued,
    /// A current authenticated session exists.
    Authenticated,
    /// A replacement token was issued.
    Rotated,
    /// Logout was requested and the old token was checked.
    LoggedOut,
    /// Expiry was requested and the expired token was checked.
    Expired,
    /// Revocation was requested and the revoked token was checked.
    Revoked,
    /// Recovery completed and the prior session was checked.
    Recovered,
}

/// One credential-free transition in the host-observed session state graph.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleIdentitySessionTransition {
    /// Stable case that caused or checked the transition.
    pub case_id: String,
    /// Opaque identity whose session changed.
    pub identity_handle: String,
    /// Starting lifecycle state.
    pub from: ModuleIdentitySessionPhase,
    /// Ending lifecycle state.
    pub to: ModuleIdentitySessionPhase,
    /// Redacted application operation.
    pub operation: String,
}

/// One real authentication, session, authorization, or tenancy observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleIdentityAccessCaseObservation {
    /// Stable case identity from the pinned suite.
    pub id: String,
    /// Security or lifecycle dimension.
    pub category: String,
    /// Module-oracle disposition.
    pub disposition: ModuleIdentityAccessDisposition,
    /// Opaque actor identity.
    pub actor_identity: String,
    /// Opaque target identity, when the operation targets another principal.
    pub target_identity: Option<String>,
    /// Redacted method and origin-form route.
    pub operation: String,
    /// Direct target response status.
    pub response_status: u16,
    /// Whether the copied target state independently changed.
    pub state_change_observed: bool,
    /// Independent differential or lifecycle oracle and result.
    pub oracle: String,
    /// Digest of credential-free replay semantics.
    pub replay_digest: String,
}

/// One runtime-confirmed identity or access-control violation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleIdentityAccessFindingObservation {
    /// Stable content-derived finding identity.
    pub id: String,
    /// Case that established the violation.
    pub case_id: String,
    /// Security category.
    pub category: String,
    /// Normalized severity.
    pub severity: ModuleSourceSeverity,
    /// Redacted factual observation.
    pub message: String,
    /// Evidence boundary, always `runtime_confirmed` for this type.
    pub evidence_state: String,
    /// Standards or weakness mappings attached by the pinned oracle.
    pub standards: Vec<String>,
    /// Digest of credential-free replay semantics.
    pub replay_digest: String,
}

/// Module-authored proof that credential material was withheld from module-visible output.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleIdentityRedactionObservation {
    /// Number of distinct credential values held only by the host during execution.
    pub credential_values_checked: u64,
    /// Request authorization or credential fields omitted from the projection.
    pub request_fields_redacted: u64,
    /// Response credential fields consumed and omitted by the host.
    pub response_fields_redacted: u64,
    /// Whether the complete serialized module-visible observation contains none of those values.
    pub provider_projection_clean: bool,
    /// Digest of the credential-free provider projection.
    pub projection_digest: String,
}

/// Complete module-authored authentication, session, authorization, and tenancy campaign.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleIdentityAccessObservation {
    /// Observation schema, currently one.
    pub schema: u16,
    /// Exact disposable laboratory identity.
    pub laboratory_id: String,
    /// Immutable source snapshot executed in the laboratory.
    pub source_snapshot: String,
    /// Pinned adapter implementation identity.
    pub adapter_version: String,
    /// Pinned identity topology, operation suite, and oracle identity.
    pub suite_version: String,
    /// Credential-free role and tenant topology.
    pub identities: Vec<ModuleIdentityRoleObservation>,
    /// Host-observed session lifecycle graph.
    pub session_transitions: Vec<ModuleIdentitySessionTransition>,
    /// Executed real-interface cases.
    pub cases: Vec<ModuleIdentityAccessCaseObservation>,
    /// Runtime-confirmed violations only.
    pub findings: Vec<ModuleIdentityAccessFindingObservation>,
    /// Credential-redaction proof for the complete provider-visible projection.
    pub redaction: ModuleIdentityRedactionObservation,
    /// Digest of the ordered private request/response receipt stream.
    pub traffic_digest: String,
    /// Total real application operations.
    pub operations_executed: u64,
    /// Final copied target-store digest.
    pub final_state_digest: String,
    /// Explicit identity, protocol, and oracle gaps.
    pub gaps: Vec<String>,
}

/// Bounded request for the registered file, archive, parser, and native-fault campaign.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleFileFuzzCampaignRequest {
    /// Request schema, currently one.
    pub schema: u16,
    /// Exact ready disposable laboratory identity.
    pub laboratory_id: String,
    /// Opaque endpoint issued for that laboratory.
    pub endpoint_handle: String,
    /// Pinned module campaign profile.
    pub profile: String,
    /// Deterministic generator seed retained for replay.
    pub seed: u64,
    /// Maximum real target operations admitted for the campaign.
    pub maximum_cases: u32,
    /// Maximum decoded bytes in one generated input.
    pub maximum_input_bytes: u64,
    /// Maximum serialized bytes retained from one target response.
    pub maximum_response_bytes: u64,
}

/// Module-oracle disposition for one file/parser/fuzz case.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleFileFuzzDisposition {
    /// Required legitimate behavior was observed.
    Passed,
    /// The target rejected a hostile or malformed input without a boundary effect.
    Rejected,
    /// A module-owned filesystem oracle observed a security-boundary violation.
    Violation,
    /// The isolated target process produced a native fault or parser crash observation.
    Crash,
    /// The controller or transport failed before target behavior could be classified.
    HarnessFailure,
    /// Required instrumentation is unavailable for this target/profile.
    InstrumentationUnavailable,
}

/// Exact generated or minimized input retained for replay.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleFileFuzzInputObservation {
    /// Input family such as `path`, `tar`, `structured_parser`, or `native_ffi`.
    pub kind: String,
    /// SHA-256 of the exact decoded input bytes.
    pub digest: String,
    /// Exact decoded input byte length.
    pub bytes: u64,
    /// Base64 encoding of the bounded exact input bytes.
    pub base64: String,
    /// Whether this input was minimized from a larger generated input.
    pub minimized: bool,
    /// Original byte length before minimization.
    pub original_bytes: u64,
}

/// One real file, archive, parser, or native-fault case and independent oracle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleFileFuzzCaseObservation {
    /// Stable case identity from the pinned suite or generator sequence.
    pub id: String,
    /// Security or coverage category.
    pub category: String,
    /// Module-oracle disposition.
    pub disposition: ModuleFileFuzzDisposition,
    /// Redacted real-interface operation.
    pub operation: String,
    /// Exact replay input.
    pub input: ModuleFileFuzzInputObservation,
    /// Direct target response status, absent for a harness failure.
    pub response_status: Option<u16>,
    /// Fixed module-owned boundary canary changed by the target, when observed.
    pub boundary_effect: Option<String>,
    /// POSIX signal observed by the target subprocess controller, when present.
    pub native_signal: Option<i32>,
    /// Number of controller coverage edges known before this case.
    pub coverage_before: u64,
    /// Number of controller coverage edges known after this case.
    pub coverage_after: u64,
    /// Independent oracle detail.
    pub oracle: String,
    /// Digest of exact input, operation, expected property, and observed effect.
    pub replay_digest: String,
}

/// One runtime-confirmed file, parser, or native-fault finding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleFileFuzzFindingObservation {
    /// Stable content-derived finding identity.
    pub id: String,
    /// Case that established the violation or crash.
    pub case_id: String,
    /// Security category.
    pub category: String,
    /// Normalized severity.
    pub severity: ModuleSourceSeverity,
    /// Redacted factual observation.
    pub message: String,
    /// Evidence boundary, always `runtime_confirmed` for this type.
    pub evidence_state: String,
    /// Standards or weakness mappings attached by the pinned oracle.
    pub standards: Vec<String>,
    /// Exact minimized input digest.
    pub minimized_input_digest: String,
    /// Digest of the exact replay semantics.
    pub replay_digest: String,
}

/// Module-authored instrumentation and coverage-controller receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleFileFuzzInstrumentationObservation {
    /// Deterministic controller implementation identity.
    pub controller: String,
    /// Coverage model used to guide and deduplicate cases.
    pub coverage_model: String,
    /// Number of unique controller-observed behavioral edges.
    pub coverage_edges: u64,
    /// Digest of the sorted final edge set.
    pub coverage_digest: String,
    /// Native fault instrumentation used by supported cases.
    pub native_fault_instrumentation: String,
    /// Whether a compiler sanitizer was active for this target profile.
    pub compiler_sanitizer_active: bool,
    /// Explicit reason when compiler sanitizer instrumentation was unavailable.
    pub compiler_sanitizer_gap: Option<String>,
}

/// Bounded resource facts measured by the campaign controller.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleFileFuzzResourceObservation {
    /// Total target operations attempted.
    pub operations: u64,
    /// Total request bytes emitted through the real interface.
    pub request_bytes: u64,
    /// Total response bytes admitted through the real interface.
    pub response_bytes: u64,
    /// Host-observed wall time for the campaign.
    pub wall_millis: u64,
    /// Maximum admitted decoded input bytes per case.
    pub maximum_input_bytes: u64,
    /// Whether the laboratory remained available after all nonterminal child faults.
    pub laboratory_remained_ready: bool,
}

/// Complete module-authored file, archive, parser, and native-fault campaign observation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleFileFuzzObservation {
    /// Observation schema, currently one.
    pub schema: u16,
    /// Exact disposable laboratory identity.
    pub laboratory_id: String,
    /// Immutable source snapshot executed in the laboratory.
    pub source_snapshot: String,
    /// Pinned adapter implementation identity.
    pub adapter_version: String,
    /// Pinned seed corpus, generator, minimizer, and oracle identity.
    pub suite_version: String,
    /// Deterministic generator seed.
    pub seed: u64,
    /// Digest of the initial seeds and dictionary.
    pub corpus_digest: String,
    /// Number of structure-aware generated cases in addition to the fixed suite.
    pub generated_cases: u64,
    /// Executed real-interface cases.
    pub cases: Vec<ModuleFileFuzzCaseObservation>,
    /// Runtime-confirmed violations and native faults only.
    pub findings: Vec<ModuleFileFuzzFindingObservation>,
    /// Instrumentation and coverage-controller record.
    pub instrumentation: ModuleFileFuzzInstrumentationObservation,
    /// Measured bounded resource facts.
    pub resources: ModuleFileFuzzResourceObservation,
    /// Number of deduplicated native crash signatures.
    pub crash_groups: u64,
    /// Digest of ordered request/response and filesystem-oracle evidence.
    pub campaign_digest: String,
    /// Final copied target-store digest.
    pub final_state_digest: String,
    /// Explicit platform, ABI, instrumentation, and oracle gaps.
    pub gaps: Vec<String>,
}

/// Bounded request for the registered stateful workflow and concurrency campaign.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleWorkflowCampaignRequest {
    /// Request schema, currently one.
    pub schema: u16,
    /// Exact ready disposable laboratory identity.
    pub laboratory_id: String,
    /// Opaque endpoint issued for that laboratory.
    pub endpoint_handle: String,
    /// Pinned module campaign profile.
    pub profile: String,
    /// Deterministic sequence-generation seed retained for replay.
    pub seed: u64,
    /// Maximum stateful sequences admitted for the campaign.
    pub maximum_sequences: u32,
    /// Maximum real application actions admitted for the campaign.
    pub maximum_actions: u32,
    /// Maximum serialized bytes retained from one target response.
    pub maximum_response_bytes: u64,
}

/// Provenance of an invariant evaluated by the workflow adapter.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleWorkflowInvariantOrigin {
    /// The invariant is an explicit user or application contract and may support a finding.
    Documented,
    /// The invariant is a model-proposed lead and cannot support a finding until promoted.
    ModelProposed,
}

/// Module-oracle result for one invariant.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleWorkflowInvariantDisposition {
    /// All exercised legal sequences preserved the invariant.
    Held,
    /// A legal sequence violated a documented invariant.
    Violated,
    /// An exercised legal sequence disproved a proposed invariant.
    Refuted,
    /// Available observations could not decide the invariant.
    Inconclusive,
}

/// Module-oracle result for one stateful sequence.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleWorkflowSequenceDisposition {
    /// The sequence preserved every applicable documented invariant.
    Passed,
    /// Host-observed state violated at least one documented invariant.
    Violation,
    /// The controller or transport failed before application behavior could be decided.
    HarnessFailure,
}

/// One explicit invariant and its independently evaluated status.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleWorkflowInvariantObservation {
    /// Stable invariant identity.
    pub id: String,
    /// Whether the invariant is documented or only proposed.
    pub origin: ModuleWorkflowInvariantOrigin,
    /// Human-readable contract statement.
    pub statement: String,
    /// Pinned module-oracle identity.
    pub oracle: String,
    /// Result over the executed sequences.
    pub disposition: ModuleWorkflowInvariantDisposition,
    /// Exact sequences that informed the result.
    pub sequence_ids: Vec<String>,
}

/// One real application action in an ordered stateful sequence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleWorkflowActionObservation {
    /// Stable action identity within the campaign.
    pub id: String,
    /// Zero-based position in the containing sequence.
    pub position: u32,
    /// Stable credential-free actor identity.
    pub actor: String,
    /// Redacted application operation.
    pub operation: String,
    /// Stable idempotency or business request identity.
    pub request_id: String,
    /// Requested deterministic schedule slot, when relevant.
    pub schedule_slot: Option<String>,
    /// Digest of the exact request semantics.
    pub request_digest: String,
    /// Direct target response status, absent for a transport failure.
    pub response_status: Option<u16>,
    /// Host-observed state digest before the action.
    pub state_before_digest: String,
    /// Host-observed state digest after the action.
    pub state_after_digest: String,
    /// Host-observed action duration.
    pub elapsed_millis: u64,
    /// Factual target/transport outcome without invariant interpretation.
    pub outcome: String,
}

/// One exact schedule retained for concurrency replay.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleWorkflowScheduleObservation {
    /// Stable schedule identity.
    pub id: String,
    /// Ordered deterministic schedule steps requested by the host.
    pub steps: Vec<String>,
    /// Number of exact replays performed.
    pub replay_count: u32,
    /// Number of replays with the same final state and response class.
    pub matching_replays: u32,
    /// Digest of the retained schedule semantics.
    pub schedule_digest: String,
}

/// One complete stateful sequence and its module-owned oracle result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleWorkflowSequenceObservation {
    /// Stable sequence identity.
    pub id: String,
    /// Workflow, retry, lifecycle, accounting, or concurrency category.
    pub category: String,
    /// Credential-free participating identities.
    pub identities: Vec<String>,
    /// Host-observed starting state digest.
    pub starting_snapshot_digest: String,
    /// Ordered real application actions.
    pub actions: Vec<ModuleWorkflowActionObservation>,
    /// Host-observed final state digest.
    pub final_state_digest: String,
    /// Applicable documented or proposed invariant identities.
    pub invariant_ids: Vec<String>,
    /// Sequence disposition established by module-owned oracles.
    pub disposition: ModuleWorkflowSequenceDisposition,
    /// Independent oracle detail.
    pub oracle: String,
    /// Exact schedule identity when the sequence exercises concurrency.
    pub schedule_id: Option<String>,
    /// Digest of the starting snapshot, actions, schedule, expected property, and final state.
    pub replay_digest: String,
}

/// One runtime-confirmed documented workflow violation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleWorkflowFindingObservation {
    /// Stable content-derived finding identity.
    pub id: String,
    /// Sequence that established the violation.
    pub sequence_id: String,
    /// Violated documented invariant.
    pub invariant_id: String,
    /// Normalized severity.
    pub severity: ModuleSourceSeverity,
    /// Redacted factual observation.
    pub message: String,
    /// Evidence boundary, always `runtime_confirmed` for this type.
    pub evidence_state: String,
    /// Standards or weakness mappings attached by the pinned oracle.
    pub standards: Vec<String>,
    /// Digest of the exact replay semantics.
    pub replay_digest: String,
}

/// Module-authored nondeterminism and replay record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleWorkflowNondeterminismObservation {
    /// Deterministic schedules retained for replay.
    pub schedules: Vec<ModuleWorkflowScheduleObservation>,
    /// Total exact schedule replays.
    pub replays: u64,
    /// Replays whose final state or response class diverged.
    pub divergent_replays: u64,
    /// Transport or controller failures excluded from domain findings.
    pub excluded_harness_failures: u64,
    /// Explicit nondeterminism limits or unexplained behavior.
    pub notes: Vec<String>,
}

/// Complete module-authored state, concurrency, and business-workflow campaign.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleWorkflowObservation {
    /// Observation schema, currently one.
    pub schema: u16,
    /// Exact disposable laboratory identity.
    pub laboratory_id: String,
    /// Immutable source snapshot executed in the laboratory.
    pub source_snapshot: String,
    /// Pinned adapter implementation identity.
    pub adapter_version: String,
    /// Pinned action generator, invariant set, and oracle identity.
    pub suite_version: String,
    /// Deterministic sequence-generation seed.
    pub seed: u64,
    /// Explicit invariants with documented and proposed provenance kept separate.
    pub invariants: Vec<ModuleWorkflowInvariantObservation>,
    /// Executed real-interface sequences.
    pub sequences: Vec<ModuleWorkflowSequenceObservation>,
    /// Runtime-confirmed documented invariant violations only.
    pub findings: Vec<ModuleWorkflowFindingObservation>,
    /// Deterministic schedule replay and nondeterminism report.
    pub nondeterminism: ModuleWorkflowNondeterminismObservation,
    /// Total real application actions attempted.
    pub actions_executed: u64,
    /// Digest of ordered requests, responses, schedules, and host snapshots.
    pub campaign_digest: String,
    /// Final copied target-store digest.
    pub final_state_digest: String,
    /// Explicit domain, schedule, platform, and oracle gaps.
    pub gaps: Vec<String>,
}

/// Bounded request for the registered private-network, TLS, policy, and authority campaign.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleBoundaryCampaignRequest {
    /// Request schema, currently one.
    pub schema: u16,
    /// Exact ready disposable laboratory identity.
    pub laboratory_id: String,
    /// Opaque endpoint issued for that laboratory.
    pub endpoint_handle: String,
    /// Pinned module campaign profile.
    pub profile: String,
    /// Maximum real target operations admitted for the campaign.
    pub maximum_operations: u32,
    /// Maximum serialized bytes retained from one target response.
    pub maximum_response_bytes: u64,
}

/// Security boundary exercised by one Phase 18 case.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleBoundaryClass {
    /// DNS, redirect, callback, proxy, protocol, or destination policy.
    PrivateNetwork,
    /// Certificate trust, hostname, expiry, downgrade, or connection state.
    Tls,
    /// Local container, `IaC`, sandbox, identity, or capability policy.
    PrivilegePolicy,
    /// Agent, prompt, plugin, delegated-tool, or confused-deputy authority.
    DelegatedAuthority,
    /// A class intentionally unavailable without a safe emulator.
    PlatformGap,
}

/// Module-oracle result for one boundary case.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleBoundaryDisposition {
    /// The target preserved the documented boundary.
    Passed,
    /// Host-observed effects violated the documented boundary.
    Violation,
    /// A required safe emulator or platform is unavailable.
    Blocked,
    /// Transport or controller failure prevented a domain conclusion.
    HarnessFailure,
}

/// One real target operation and module-owned boundary decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleBoundaryCaseObservation {
    /// Stable case identity.
    pub id: String,
    /// Boundary family exercised by this case.
    pub class: ModuleBoundaryClass,
    /// Redacted target operation.
    pub operation: String,
    /// Direct target status, absent for blocked or harness-failure cases.
    pub response_status: Option<u16>,
    /// Digest of the exact request semantics.
    pub request_digest: String,
    /// Host-observed copied-state digest before the operation.
    pub state_before_digest: String,
    /// Host-observed copied-state digest after the operation.
    pub state_after_digest: String,
    /// Host-observed state keys changed by the operation.
    pub changed_state_keys: Vec<String>,
    /// Independently evaluated case disposition.
    pub disposition: ModuleBoundaryDisposition,
    /// Pinned oracle identity.
    pub oracle: String,
    /// Factual module-oracle detail.
    pub detail: String,
    /// Digest binding the replay semantics.
    pub replay_digest: String,
}

/// One runtime-confirmed violation of a documented boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleBoundaryFindingObservation {
    /// Stable content-derived finding identity.
    pub id: String,
    /// Case that established the violation.
    pub case_id: String,
    /// Normalized severity.
    pub severity: ModuleSourceSeverity,
    /// Redacted factual observation.
    pub message: String,
    /// Evidence boundary, always `runtime_confirmed` here.
    pub evidence_state: String,
    /// Standards or weakness mappings attached by the oracle.
    pub standards: Vec<String>,
    /// Digest of the exact replay semantics.
    pub replay_digest: String,
}

/// Aggregate private-network and forbidden-destination evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleBoundaryNetworkObservation {
    /// Actual lab-private DNS exchanges.
    pub private_dns_queries: u64,
    /// Actual lab-private callback effects.
    pub private_callbacks: u64,
    /// Actual lab-private redirect hops.
    pub redirect_hops: u64,
    /// Actual lab-private proxy negotiations.
    pub proxy_requests: u64,
    /// Forbidden inputs accepted far enough to attempt a blind effect.
    pub forbidden_destination_attempts: u64,
    /// Effects reaching host loopback outside the laboratory.
    pub host_loopback_effects: u64,
    /// Effects reaching a LAN destination outside the laboratory.
    pub lan_effects: u64,
    /// Effects reaching a public destination outside the laboratory.
    pub external_effects: u64,
    /// Digest of module-owned protocol-peer receipts.
    pub peer_receipt_digest: String,
}

/// Aggregate certificate and connection-state evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleBoundaryTlsObservation {
    /// Completed handshakes with lab-private TLS peers.
    pub handshakes: u64,
    /// Oracle disposition for the trusted-certificate and matching-hostname case.
    pub trusted_hostname: ModuleBoundaryDisposition,
    /// Oracle disposition for the mismatched-hostname case.
    pub hostname_mismatch: ModuleBoundaryDisposition,
    /// Oracle disposition for the expired-certificate case.
    pub expired_certificate: ModuleBoundaryDisposition,
    /// Oracle disposition for the plaintext-downgrade case.
    pub downgrade: ModuleBoundaryDisposition,
    /// Oracle disposition for multiple messages on one authenticated connection.
    pub connection_reuse: ModuleBoundaryDisposition,
    /// Digest of the pinned laboratory certificate set.
    pub certificate_set_digest: String,
}

/// Aggregate local policy and contained privilege-probe evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleBoundaryPolicyObservation {
    /// Digest of the target-declared local policy.
    pub policy_digest: String,
    /// Target-declared runtime identity.
    pub run_as_user: String,
    /// Target-declared capabilities.
    pub requested_capabilities: Vec<String>,
    /// Whether no-new-privileges was declared.
    pub no_new_privileges: bool,
    /// Actual contained privilege attempts.
    pub privilege_attempts: u64,
    /// Privilege effects escaping the laboratory.
    pub host_privilege_effects: u64,
    /// Whether host files and identity elevation stayed blocked.
    pub containment_held: bool,
}

/// Aggregate prompt, plugin, and delegated-tool authority evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleBoundaryAuthorityObservation {
    /// Untrusted directives presented to the copied application.
    pub untrusted_directives: u64,
    /// Delegated tool actions attempted by the copied application.
    pub delegated_actions: u64,
    /// Privileged copied-application effects from under-scoped requests.
    pub privileged_effects: u64,
    /// Whether a confused-deputy transition was observed.
    pub confused_deputy_observed: bool,
    /// Whether host authority remained unchanged.
    pub host_authority_unchanged: bool,
}

/// Complete module-authored network, TLS, policy, and delegated-authority campaign.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleBoundaryObservation {
    /// Observation schema, currently one.
    pub schema: u16,
    /// Exact disposable laboratory identity.
    pub laboratory_id: String,
    /// Immutable source snapshot executed in the laboratory.
    pub source_snapshot: String,
    /// Pinned adapter implementation identity.
    pub adapter_version: String,
    /// Pinned protocol peers, certificates, policies, and oracles.
    pub suite_version: String,
    /// Executed real-interface and explicitly blocked cases.
    pub cases: Vec<ModuleBoundaryCaseObservation>,
    /// Runtime-confirmed documented boundary violations only.
    pub findings: Vec<ModuleBoundaryFindingObservation>,
    /// Private-network and forbidden-destination summary.
    pub network: ModuleBoundaryNetworkObservation,
    /// TLS and connection-state summary.
    pub tls: ModuleBoundaryTlsObservation,
    /// Local policy and contained privilege summary.
    pub policy: ModuleBoundaryPolicyObservation,
    /// Delegated-authority and confused-deputy summary.
    pub authority: ModuleBoundaryAuthorityObservation,
    /// Total real target operations attempted.
    pub operations_executed: u64,
    /// Digest of ordered target, peer, policy, and authority evidence.
    pub campaign_digest: String,
    /// Final copied target-state digest.
    pub final_state_digest: String,
    /// Explicit unavailable platform, cloud, protocol, and privilege gaps.
    pub gaps: Vec<String>,
}

/// Bounded request for one module-owned cross-adapter attack-graph and repair campaign.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAttackGraphCampaignRequest {
    /// Request schema, currently one.
    pub schema: u16,
    /// Exact immutable source authority containing both disposable twins.
    pub source: ScopedSourceAuthority,
    /// Ready vulnerable laboratory identity.
    pub vulnerable_laboratory_id: String,
    /// Opaque endpoint for the vulnerable laboratory.
    pub vulnerable_endpoint_handle: String,
    /// Ready repaired twin laboratory identity.
    pub repaired_laboratory_id: String,
    /// Opaque endpoint for the repaired twin laboratory.
    pub repaired_endpoint_handle: String,
    /// Pinned host graph, replay, skeptic, and reviewer profile.
    pub profile: String,
    /// Maximum real browser actions admitted across the campaign.
    pub maximum_browser_actions: u32,
    /// Maximum private HTTP/browser requests admitted across the campaign.
    pub maximum_requests: u32,
    /// Maximum retained graph and browser artifact bytes.
    pub maximum_artifact_bytes: u64,
}

/// Role of one independently evidenced node in an attack graph.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleAttackGraphNodeKind {
    /// Attacker-controlled application entry point.
    EntryPoint,
    /// Necessary source, configuration, or state prerequisite.
    Prerequisite,
    /// Host-observed intermediate copied-application effect.
    StateEffect,
    /// Host-observed security impact.
    Impact,
}

/// One attack-graph node bound to exact adapter evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAttackGraphNodeObservation {
    /// Stable node identity.
    pub id: String,
    /// Graph role.
    pub kind: ModuleAttackGraphNodeKind,
    /// Registered adapter family that established this fact.
    pub adapter_id: String,
    /// Factual redacted observation.
    pub label: String,
    /// Digest of the exact raw receipt supporting the node.
    pub evidence_digest: String,
}

/// One directed prerequisite/effect edge with explicit evidence provenance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAttackGraphEdgeObservation {
    /// Stable edge identity.
    pub id: String,
    /// Existing source node.
    pub from: String,
    /// Existing destination node.
    pub to: String,
    /// Versioned causal or prerequisite relation.
    pub relation: String,
    /// Registered adapter family that established the transition.
    pub adapter_id: String,
    /// Digest of the exact receipt or counterfactual supporting the edge.
    pub evidence_digest: String,
    /// False when the proposed edge was deliberately rejected for missing evidence.
    pub supported: bool,
}

/// Evidence-bounded disposition of a searched attack chain.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleAttackGraphDisposition {
    /// Every necessary edge was observed and the impact occurred.
    Confirmed,
    /// A named prerequisite was removed and the impact disappeared.
    Broken,
    /// At least one proposed edge lacked an admissible receipt.
    Rejected,
}

/// One exact searched path through the graph.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAttackGraphChainObservation {
    /// Stable chain identity.
    pub id: String,
    /// Ordered node identities.
    pub nodes: Vec<String>,
    /// Ordered edge identities.
    pub edges: Vec<String>,
    /// Distinct registered adapter families contributing evidence.
    pub adapter_families: Vec<String>,
    /// Module-oracle disposition.
    pub disposition: ModuleAttackGraphDisposition,
    /// Removed prerequisite for a broken chain, when applicable.
    pub removed_prerequisite: Option<String>,
    /// Digest of exact ordered replay semantics.
    pub replay_digest: String,
    /// Factual decision detail.
    pub detail: String,
}

/// Root-cause group that preserves distinct entry points and impacts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAttackGraphDeduplicationObservation {
    /// Stable root-cause identity.
    pub root_cause_id: String,
    /// Nodes consolidated under the same cause.
    pub member_nodes: Vec<String>,
    /// Entry nodes retained rather than collapsed away.
    pub retained_entry_points: Vec<String>,
    /// Impact nodes retained rather than collapsed away.
    pub retained_impacts: Vec<String>,
    /// Exact rule explaining the grouping.
    pub rationale: String,
}

/// Result of one adapter-specific repair replay.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAttackGraphReplayObservation {
    /// Registered adapter family replayed.
    pub adapter_id: String,
    /// Stable replay case identity.
    pub case_id: String,
    /// Whether the declared property held.
    pub passed: bool,
    /// Digest of the exact replay receipt.
    pub evidence_digest: String,
    /// Factual replay result.
    pub detail: String,
}

/// Independent skeptic decision over raw node and edge receipts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAttackGraphSkepticObservation {
    /// Versioned skeptic implementation identity.
    pub reviewer: String,
    /// Whether the confirmed chain has no unsupported edge.
    pub accepted: bool,
    /// Exact evidence digests independently inspected.
    pub inspected_evidence: Vec<String>,
    /// Proposed edge identities rejected for missing support.
    pub rejected_edges: Vec<String>,
    /// Factual decision detail.
    pub detail: String,
}

/// Copy-only repair plan and independently reviewed replay result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAttackGraphRepairObservation {
    /// Source-relative vulnerable file path.
    pub target_path: String,
    /// Exact immutable vulnerable preimage digest.
    pub original_digest: String,
    /// Digest of the replacement bytes exercised by the repaired twin.
    pub patched_digest: String,
    /// Digest of the exact unified diff.
    pub diff_artifact: String,
    /// Exact bounded unified diff bytes.
    pub diff_bytes: Vec<u8>,
    /// Confirmed chain identities addressed by the repair.
    pub addressed_chains: Vec<String>,
    /// Ordered prerequisites for applying and replaying the repair.
    pub prerequisites: Vec<String>,
    /// Adapter-specific replay plan and results.
    pub replays: Vec<ModuleAttackGraphReplayObservation>,
    /// Whether legitimate store/read behavior remained observable.
    pub legitimate_behavior_preserved: bool,
    /// Independent reviewer implementation identity.
    pub reviewer: String,
    /// Whether the exact diff and every required replay were accepted.
    pub review_accepted: bool,
    /// Factual review detail.
    pub review_detail: String,
}

/// Complete module-authored cross-adapter graph, counterfactual, and repair campaign.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleAttackGraphObservation {
    /// Observation schema, currently one.
    pub schema: u16,
    /// Immutable source snapshot shared by both laboratories.
    pub source_snapshot: String,
    /// Pinned adapter implementation identity.
    pub adapter_version: String,
    /// Pinned graph, replay, skeptic, and reviewer suite identity.
    pub suite_version: String,
    /// Ready vulnerable laboratory identity.
    pub vulnerable_laboratory_id: String,
    /// Ready repaired laboratory identity.
    pub repaired_laboratory_id: String,
    /// Independently evidenced graph nodes.
    pub nodes: Vec<ModuleAttackGraphNodeObservation>,
    /// Supported and deliberately rejected graph edges.
    pub edges: Vec<ModuleAttackGraphEdgeObservation>,
    /// Confirmed, broken, and rejected searched chains.
    pub chains: Vec<ModuleAttackGraphChainObservation>,
    /// Root-cause grouping that preserves distinct entry and impact facts.
    pub deduplication: Vec<ModuleAttackGraphDeduplicationObservation>,
    /// Independent skeptic decision.
    pub skeptic: ModuleAttackGraphSkepticObservation,
    /// Copy-only repair, adapter replay, and independent review.
    pub repair: ModuleAttackGraphRepairObservation,
    /// Total private application and browser operations.
    pub operations_executed: u64,
    /// Digest of ordered raw graph, counterfactual, and repair receipts.
    pub campaign_digest: String,
    /// Explicit unsupported families and generalization limits.
    pub gaps: Vec<String>,
}

/// One exact application shape supported by the host-owned laboratory controller.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleLaboratoryRecipe {
    /// Recipe schema, currently one.
    pub schema: u16,
    /// Stable recipe identity interpreted by the host.
    pub recipe_id: String,
    /// Exact recipe version.
    pub version: String,
    /// Supported host platform.
    pub platform: ModuleAdapterPlatform,
    /// Required source roles, in canonical order.
    pub source_roles: Vec<String>,
    /// Host-owned isolation backend required by this recipe.
    pub isolation_backend: String,
    /// Human-readable interface shape exposed through opaque handles.
    pub interface: String,
}

/// Host projection of currently supported laboratory recipes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleLaboratoryCatalog {
    /// Catalog schema, currently one.
    pub schema: u16,
    /// Recipes available on this exact host platform.
    pub recipes: Vec<ModuleLaboratoryRecipe>,
}

/// Request to create one laboratory bound to an immutable source authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleLaboratoryCreateRequest {
    /// Request schema, currently one.
    pub schema: u16,
    /// Exact immutable source authority selected by the user.
    pub source: ScopedSourceAuthority,
    /// Exact host recipe.
    pub recipe_id: String,
    /// Source-relative application service entry point.
    pub application_path: String,
    /// Source-relative backing service entry point.
    pub service_path: String,
}

/// Request to create a laboratory from the complete immutable source snapshot.
///
/// Unlike an exact compatibility recipe, this request does not require the target to implement a
/// Peritus protocol or place code in specially named files. The host copies the complete admitted
/// tree and exposes only generic, sandboxed process operations over it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleLaboratorySourceCreateRequest {
    /// Request schema, currently one.
    pub schema: u16,
    /// Exact immutable source authority selected by the user.
    pub source: ScopedSourceAuthority,
}

/// One generic process invocation against a complete disposable source copy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleLaboratoryProcessInput {
    /// Input schema, currently one.
    pub schema: u16,
    /// Host-resolved runtime family, for example `direct`, `python3`, `node`, or `cargo`.
    pub runtime: String,
    /// Canonical source-relative entry point or project manifest.
    pub entrypoint: String,
    /// Literal argument vector. No shell parsing or expansion is performed.
    pub arguments: Vec<String>,
    /// Bounded standard-input bytes supplied to the process.
    pub stdin: Vec<u8>,
    /// Credential-free literal environment entries selected for the copied target.
    pub environment: std::collections::BTreeMap<String, String>,
    /// Per-invocation wall-clock ceiling in milliseconds.
    pub wall_millis: u64,
    /// Exit codes accepted by the caller's predeclared oracle.
    pub expected_exit_codes: Vec<i32>,
    /// Literal stdout fragments required by the caller's predeclared oracle.
    pub stdout_contains: Vec<String>,
    /// Literal stderr fragments required by the caller's predeclared oracle.
    pub stderr_contains: Vec<String>,
}

/// Opaque identities returned for one laboratory. No resolved path, address, or credential appears.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleLaboratoryHandle {
    /// Handle schema, currently one.
    pub schema: u16,
    /// Content-bound laboratory identity.
    pub laboratory_id: String,
    /// Exact source revision.
    pub scope_revision: String,
    /// Immutable source snapshot.
    pub source_snapshot: String,
    /// Exact host recipe.
    pub recipe_id: String,
    /// Opaque application service identity.
    pub application_service: String,
    /// Opaque backing service identity.
    pub backing_service: String,
    /// Opaque endpoint resolved only by the host.
    pub endpoint_handle: String,
    /// Opaque test identity; this is not credential material.
    pub identity_handle: String,
    /// Opaque secret lease identity; this is not secret material.
    pub secret_handle: String,
}

/// Durable lifecycle phase for one disposable application laboratory.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleLaboratoryPhase {
    /// Identity exists but no source bytes have been materialized.
    Created,
    /// Exact copied source and private support data are prepared.
    Prepared,
    /// The copied application and backing service passed real readiness checks.
    Ready,
    /// The owned process tree stopped and retained state remains available.
    Stopped,
    /// The controller observed a recoverable or terminal failure.
    Failed,
    /// Cleanup, identity, or secret-output integrity could not be established.
    Quarantined,
    /// Disposable bytes were removed while identities and receipts remain readable.
    TornDown,
}

/// Bounded resource and activity facts authored by the laboratory controller.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleLaboratoryTelemetry {
    /// Requests admitted through the opaque endpoint.
    pub requests: u64,
    /// Bytes written through the host control channel.
    pub input_bytes: u64,
    /// Bytes admitted from target responses after secret filtering.
    pub output_bytes: u64,
    /// Latest host-observed copied-store digest.
    pub state_digest: String,
    /// Whether the host-loopback escape canary remained untouched.
    pub host_loopback_blocked: bool,
    /// Whether no credential value was admitted to a module-visible result.
    pub credential_output_blocked: bool,
}

/// Host-authored receipt for a laboratory lifecycle or application operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleLaboratoryReceipt {
    /// Receipt schema, currently one.
    pub schema: u16,
    /// Exact laboratory identity.
    pub laboratory_id: String,
    /// Stable operation name.
    pub operation: String,
    /// Digest of the exact admitted request.
    pub request_digest: String,
    /// Exact immutable source snapshot.
    pub source_snapshot: String,
    /// Digest of the copied application entry point.
    pub application_digest: String,
    /// Digest of the copied backing service entry point.
    pub service_digest: String,
    /// Host-owned isolation backend identity.
    pub isolation_backend: String,
    /// Network and service-routing policy identity.
    pub network_policy: String,
    /// Typed observation with secrets and resolved host paths excluded.
    pub observation: Value,
    /// Telemetry observed at this operation boundary.
    pub telemetry: ModuleLaboratoryTelemetry,
    /// Whether the complete owned target process tree was observed stopped.
    pub process_cleanup_complete: bool,
    /// Whether the selected original source still matches its retained snapshot.
    pub original_source_unchanged: Option<bool>,
}

/// Current durable laboratory status.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleLaboratoryStatus {
    /// Status schema, currently one.
    pub schema: u16,
    /// Opaque handle set.
    pub handle: ModuleLaboratoryHandle,
    /// Current lifecycle phase.
    pub phase: ModuleLaboratoryPhase,
    /// Latest controller telemetry.
    pub telemetry: ModuleLaboratoryTelemetry,
    /// Number of retained snapshots.
    pub snapshots: u64,
    /// Number of retained host-authored receipts.
    pub receipts: u64,
    /// Actionable lifecycle detail.
    pub detail: String,
    /// Retained causal failure, if one exists.
    pub retained_error: Option<String>,
    /// Whether disposable source, state, process, socket, and secret bytes were removed.
    pub cleanup_complete: bool,
}

/// Combined current status and optional new receipt returned by a laboratory operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleLaboratoryResult {
    /// Result schema, currently one.
    pub schema: u16,
    /// Current durable lifecycle state.
    pub status: ModuleLaboratoryStatus,
    /// New host-authored operation receipt, absent for a pure status read.
    pub receipt: Option<ModuleLaboratoryReceipt>,
}

/// Request for one exact laboratory lifecycle operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleLaboratoryLifecycleRequest {
    /// Request schema, currently one.
    pub schema: u16,
    /// Exact opaque laboratory identity.
    pub laboratory_id: String,
}

/// Request to operate one live application through its host-resolved endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleLaboratoryInvokeRequest {
    /// Request schema, currently one.
    pub schema: u16,
    /// Exact opaque laboratory identity.
    pub laboratory_id: String,
    /// Exact opaque endpoint returned at creation.
    pub endpoint_handle: String,
    /// Registered operation, currently `state.round-trip.v1`.
    pub operation: String,
    /// Bounded application input.
    pub input: Value,
}

fn key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn name(value: &str, dot: bool) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || byte == b'-'
                || byte == b'_'
                || (dot && byte == b'.')
        })
}
