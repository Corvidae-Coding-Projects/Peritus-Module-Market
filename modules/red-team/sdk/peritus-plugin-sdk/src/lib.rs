//! Stable contracts for isolated Peritus plugins.
//!
//! The SDK contains data and framing only. It has no daemon handles, policy evaluator, filesystem
//! access, process launcher, or authority-minting API.

mod canonical;
mod error;
mod framing;
mod identity;
mod manifest;
mod module;
mod module_host;
mod payload;
mod protocol;

pub use error::{SdkError, SdkErrorKind};
pub use framing::{decode_frame, encode_frame};
pub use identity::{ManifestDigest, PluginId, PluginVersion, RequestId};
pub use manifest::{
    CapabilityDeclaration, MANIFEST_VERSION, PluginEntrypoint, PluginKind, PluginManifest,
    PluginOperation, PluginQuotas, ProtocolRange, SignatureDeclaration, TrustMaterial,
};
pub use module::{
    ModuleAction, ModuleAgentRequest, ModuleAttachment, ModuleCyberAccessProgram, ModuleFunction,
    ModuleMenuAction,
};
pub use module_host::{
    HOST_CAPABILITY_APPLICATION_LABORATORY, HOST_CAPABILITY_ATTACHMENT, HOST_CAPABILITY_CHECKPOINT,
    HOST_CAPABILITY_MODEL, HOST_CAPABILITY_PRIVATE_STATE, HOST_CAPABILITY_PROFILE,
    HOST_CAPABILITY_SCOPED_SOURCE, HOST_CAPABILITY_SOURCE_BUILD, HOST_CAPABILITY_WORKER,
    LocalPackageIdentity, MODULE_HOST_CONTRACT_VERSION, MODULE_RESEARCH_CONTRACT_VERSION,
    MODULE_WORKER_FEATURE_BROWSER_AUTOMATION, MODULE_WORKER_FEATURE_BUN_RUNTIME,
    MODULE_WORKER_FEATURE_CARGO_DEPENDENCIES, MODULE_WORKER_FEATURE_JAVASCRIPT_RUNTIME,
    ModuleAdapterCancelRequest, ModuleAdapterCatalog, ModuleAdapterCompleteRequest,
    ModuleAdapterDescriptor, ModuleAdapterExecuteRequest, ModuleAdapterExecutionReceipt,
    ModuleAdapterOperation, ModuleAdapterPhase, ModuleAdapterPlatform,
    ModuleAdapterPreparationHandle, ModuleAdapterPrepareRequest, ModuleAdapterProvenanceReceipt,
    ModuleAdapterRemoveRequest, ModuleAdapterRuntimeIdentity, ModuleAdapterStatus,
    ModuleAdapterStatusRequest, ModuleAttackGraphCampaignRequest,
    ModuleAttackGraphChainObservation, ModuleAttackGraphDeduplicationObservation,
    ModuleAttackGraphDisposition, ModuleAttackGraphEdgeObservation, ModuleAttackGraphNodeKind,
    ModuleAttackGraphNodeObservation, ModuleAttackGraphObservation,
    ModuleAttackGraphRepairObservation, ModuleAttackGraphReplayObservation,
    ModuleAttackGraphSkepticObservation, ModuleBoundaryAuthorityObservation,
    ModuleBoundaryCampaignRequest, ModuleBoundaryCaseObservation, ModuleBoundaryClass,
    ModuleBoundaryDisposition, ModuleBoundaryFindingObservation, ModuleBoundaryNetworkObservation,
    ModuleBoundaryObservation, ModuleBoundaryPolicyObservation, ModuleBoundaryTlsObservation,
    ModuleBrowserArtifact, ModuleBrowserCampaignRequest, ModuleBrowserCaseObservation,
    ModuleBrowserCoverageNode, ModuleBrowserDisposition, ModuleBrowserFindingObservation,
    ModuleBrowserObservation, ModuleFileFuzzCampaignRequest, ModuleFileFuzzCaseObservation,
    ModuleFileFuzzDisposition, ModuleFileFuzzFindingObservation, ModuleFileFuzzInputObservation,
    ModuleFileFuzzInstrumentationObservation, ModuleFileFuzzObservation,
    ModuleFileFuzzResourceObservation, ModuleHostCapability, ModuleHostOutcome, ModuleHostProfile,
    ModuleHostRequest, ModuleHostResult, ModuleHttpApiCampaignRequest,
    ModuleHttpApiCaseObservation, ModuleHttpApiDisposition, ModuleHttpApiFindingObservation,
    ModuleHttpApiObservation, ModuleHttpApiProtocol, ModuleHttpHeader,
    ModuleHttpRequestObservation, ModuleHttpResponseObservation, ModuleHttpRouteObservation,
    ModuleIdentityAccessCampaignRequest, ModuleIdentityAccessCaseObservation,
    ModuleIdentityAccessDisposition, ModuleIdentityAccessFindingObservation,
    ModuleIdentityAccessObservation, ModuleIdentityRedactionObservation,
    ModuleIdentityRoleObservation, ModuleIdentitySessionPhase, ModuleIdentitySessionTransition,
    ModuleJobCancelRequest, ModuleJobHandle, ModuleJobLimits, ModuleJobLogPage,
    ModuleJobLogRequest, ModuleJobPhase, ModuleJobReceipt, ModuleJobRequest, ModuleJobStatus,
    ModuleJobStatusRequest, ModuleJobStream, ModuleJobVerdict, ModuleLaboratoryCatalog,
    ModuleLaboratoryCreateRequest, ModuleLaboratoryHandle, ModuleLaboratoryInvokeRequest,
    ModuleLaboratoryLifecycleRequest, ModuleLaboratoryPhase, ModuleLaboratoryProcessInput,
    ModuleLaboratoryReceipt, ModuleLaboratoryRecipe, ModuleLaboratoryResult,
    ModuleLaboratorySourceCreateRequest, ModuleLaboratoryStatus, ModuleLaboratoryTelemetry,
    ModulePatchReceipt, ModulePreparationReceipt, ModuleResearchArtifactClassification,
    ModuleResearchArtifactIdentity, ModuleResearchCapabilityDisposition,
    ModuleResearchCapabilityFact, ModuleResearchCapabilityFactKind, ModuleResearchCapabilityKind,
    ModuleResearchCapabilityRecord, ModuleResearchChainConfirmationObservation,
    ModuleResearchChainConfirmationRequest, ModuleResearchChainDisposition,
    ModuleResearchChainRecord, ModuleResearchDisclosureContact, ModuleResearchDisclosurePackage,
    ModuleResearchDisclosureState, ModuleResearchDisclosureTimelineEntry,
    ModuleResearchEmulationEvidenceClass, ModuleResearchEmulationProvenance,
    ModuleResearchEmulationRecipe, ModuleResearchEvidenceBoundary, ModuleResearchExperimentPhase,
    ModuleResearchExperimentRecord, ModuleResearchExperimentSpecification,
    ModuleResearchGraphEdgeDisposition, ModuleResearchGraphEdgeRecord, ModuleResearchGraphNodeKind,
    ModuleResearchGraphNodeRecord, ModuleResearchGraphRecord, ModuleResearchGraphRejection,
    ModuleResearchIdentity, ModuleResearchIdentityKind, ModuleResearchPatchIdentity,
    ModuleResearchPatchRejection, ModuleResearchPatchReview, ModuleResearchPocBundle,
    ModuleResearchPocReplayObservation, ModuleResearchPocState, ModuleResearchPocTargetIdentity,
    ModuleResearchProjectionRejection, ModuleResearchRegressionCase,
    ModuleResearchRegressionCategory, ModuleResearchRegressionObservation,
    ModuleResearchRepairBundle, ModuleResearchRepairObservation, ModuleResearchRepairRequest,
    ModuleResearchRepairState, ModuleResearchSearchBounds, ModuleResearchSearchSummary,
    ModuleSourceAnalysisLimits, ModuleSourceAnalysisObservation, ModuleSourceAnalysisRequest,
    ModuleSourceAnalysisTool, ModuleSourceComponentObservation, ModuleSourceFindingObservation,
    ModuleSourceLanguageObservation, ModuleSourceManifestObservation,
    ModuleSourceRawFindingObservation, ModuleSourceReachability, ModuleSourceSeverity,
    ModuleWorkerLimits, ModuleWorkerRequest, ModuleWorkerResult, ModuleWorkflowActionObservation,
    ModuleWorkflowCampaignRequest, ModuleWorkflowFindingObservation,
    ModuleWorkflowInvariantDisposition, ModuleWorkflowInvariantObservation,
    ModuleWorkflowInvariantOrigin, ModuleWorkflowNondeterminismObservation,
    ModuleWorkflowObservation, ModuleWorkflowScheduleObservation,
    ModuleWorkflowSequenceDisposition, ModuleWorkflowSequenceObservation, ScopedSourceAuthority,
    ScopedSourceEntry, ScopedSourceHandle, ScopedSourceManifestPage, ScopedSourceManifestRequest,
    ScopedSourceReadRequest, ScopedSourceReadResult, ScopedSourceRequest, ScopedSourceRevocation,
    ScopedSourceRevokeRequest, ScopedSourceVerification, ScopedSourceVerifyRequest,
    SourcePackageRequest,
};
pub use payload::{JsonBounds, JsonPayload};
pub use protocol::{
    FailureClass, HostRequest, InvocationContext, PROTOCOL_VERSION, PluginFailure,
    PluginRequestEnvelope, PluginResponse, PluginResponseEnvelope, PluginRole, PluginStatus,
};
