//! Stage 7 private responsible-disclosure drafting, review, and local export.

use crate::{Error, digest, invalid, reply, state, state::PendingRequest};
use peritus_plugin_sdk::{
    HOST_CAPABILITY_SCOPED_SOURCE, MODULE_RESEARCH_CONTRACT_VERSION, ModuleAction,
    ModuleHostProfile, ModuleHostRequest, ModuleResearchArtifactClassification,
    ModuleResearchArtifactIdentity, ModuleResearchDisclosureContact,
    ModuleResearchDisclosurePackage, ModuleResearchDisclosureState,
    ModuleResearchDisclosureTimelineEntry, ModuleResearchIdentity, ModuleResearchIdentityKind,
    ModuleResearchPocState, ModuleResearchRepairBundle, ModuleResearchRepairState,
    ScopedSourceAuthority, ScopedSourceEntry, ScopedSourceManifestPage,
    ScopedSourceManifestRequest, ScopedSourceReadRequest, ScopedSourceReadResult,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
};

const TEMPLATE_VERSION: &str = "peritus-responsible-disclosure-2026-10-30.1";
const PROJECTION_VERSION: &str = "peritus-disclosure-projection-2026-10-30.1";
const MAXIMUM_CONTACT_BYTES: u64 = 65_536;
const MAXIMUM_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const CONTACT_PATHS: [&str; 3] =
    ["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"];
pub(crate) const DISCLOSURE_ARTIFACT_NAMES: [&str; 17] = [
    "acknowledgement-follow-up.md",
    "advisory.json",
    "advisory.md",
    "bug-bounty-psirt-intake.md",
    "cna-cve-intake.md",
    "coordinated-publication-draft.md",
    "evidence-manifest.json",
    "export-manifest.json",
    "fix-verification-response.md",
    "github-private-advisory.md",
    "no-delivery.json",
    "redaction-review.json",
    "regression-matrix.json",
    "regression-poc.py",
    "repair.patch",
    "vendor-email.md",
    "vendor-poc.py",
];

#[derive(Clone)]
struct PreparedArtifact {
    name: &'static str,
    media_type: &'static str,
    classification: ModuleResearchArtifactClassification,
    bytes: Vec<u8>,
}

pub(crate) fn handles(command: &str) -> bool {
    matches!(
        command,
        "disclosure"
            | "disclosure-plan"
            | "disclosure-history"
            | "disclosure-start"
            | "disclosure-review"
            | "disclosure-export"
            | "disclosure-cancel"
    ) || command.starts_with("disclosure-start ")
        || command.starts_with("disclosure-review ")
        || command.starts_with("disclosure-export ")
        || command.starts_with("disclosure-show ")
}

pub(crate) fn command(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
    command: &str,
) -> Result<ModuleAction, Error> {
    match command {
        "disclosure" | "disclosure-plan" => {
            Ok(reply(plan(state), profile, super::actions(state), None))
        }
        "disclosure-history" => Ok(reply(history(state), profile, super::actions(state), None)),
        "disclosure-cancel" => cancel(parameters, profile, state),
        _ if command == "disclosure-start" || command.starts_with("disclosure-start ") => {
            let selected = command.strip_prefix("disclosure-start").unwrap_or_default().trim();
            start(parameters, profile, state, (!selected.is_empty()).then_some(selected))
        }
        _ if command == "disclosure-review" || command.starts_with("disclosure-review ") => {
            let selected = command.strip_prefix("disclosure-review").unwrap_or_default().trim();
            review(parameters, profile, state, (!selected.is_empty()).then_some(selected))
        }
        _ if command == "disclosure-export" || command.starts_with("disclosure-export ") => {
            let selected = command.strip_prefix("disclosure-export").unwrap_or_default().trim();
            export(parameters, profile, state, (!selected.is_empty()).then_some(selected))
        }
        _ => {
            let selected = command.strip_prefix("disclosure-show ").unwrap_or_default().trim();
            if selected.is_empty() {
                return Err(invalid("use `disclosure-show PACKAGE_ID`"));
            }
            let package = state
                .research_disclosure_packages
                .iter()
                .find(|package| package.id == selected)
                .ok_or_else(|| invalid("the selected disclosure package does not exist"))?;
            Ok(reply(render(package), profile, super::actions(state), None))
        }
    }
}

fn start(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
    selected_repair: Option<&str>,
) -> Result<ModuleAction, Error> {
    if state.pending.is_some() {
        return Err(invalid("settle or cancel the retained host request before starting Stage 7"));
    }
    let repair = select_repair(state, selected_repair)?.clone();
    if let Some(package) = state
        .research_disclosure_packages
        .iter()
        .find(|package| package.repair_bundle_id == repair.id)
    {
        return Ok(reply(render(package), profile, super::actions(state), None));
    }
    let Some(authority) = state.active_handle() else {
        return create_draft(
            parameters,
            profile,
            state,
            &repair.id,
            None,
            Some("security_contact_unresolved: scoped-source authority is unavailable".into()),
        );
    };
    if !crate::supports_source(profile) {
        return create_draft(
            parameters,
            profile,
            state,
            &repair.id,
            None,
            Some("security_contact_unresolved: host does not advertise scoped-source reads".into()),
        );
    }
    request_manifest(parameters, state, &repair.id, authority, None, Vec::new())
}

fn request_manifest(
    parameters: &Value,
    state: &mut state::State,
    repair_bundle_id: &str,
    authority: ScopedSourceAuthority,
    after: Option<String>,
    candidates: Vec<ScopedSourceEntry>,
) -> Result<ModuleAction, Error> {
    let suffix = repair_bundle_id.strip_prefix("repair-").unwrap_or(repair_bundle_id);
    let page = after.as_deref().map_or("first".into(), |value| digest(value.as_bytes()));
    let key = format!(
        "red-team-disclosure-manifest-{}-{}",
        &suffix[..suffix.len().min(20)],
        &page[..page.len().min(12)]
    );
    state.pending = Some(PendingRequest::DisclosureManifest {
        key: key.clone(),
        repair_bundle_id: repair_bundle_id.into(),
        authority: authority.clone(),
        after: after.clone(),
        candidates,
    });
    state::save(parameters, state)?;
    Ok(ModuleAction::HostService {
        request: ModuleHostRequest {
            key,
            capability: HOST_CAPABILITY_SCOPED_SOURCE.into(),
            version: 1,
            operation: "manifest".into(),
            input: serde_json::to_value(ScopedSourceManifestRequest {
                schema: 1,
                authority,
                after,
                maximum_entries: 100,
            })?,
        },
    })
}

pub(crate) fn manifest_result(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
    context: (String, ScopedSourceAuthority, Option<String>, Vec<ScopedSourceEntry>),
    page: ScopedSourceManifestPage,
) -> Result<ModuleAction, Error> {
    let (repair_bundle_id, authority, after, mut candidates) = context;
    let repair = verified_repair(state, &repair_bundle_id)?;
    let snapshot = state
        .active_snapshot()
        .ok_or_else(|| invalid("Stage 7 contact scan has no active source snapshot"))?;
    if page.schema != 1
        || page.snapshot_digest != repair.source_snapshot
        || page.snapshot_digest != snapshot.snapshot_digest
        || page.manifest_artifact != snapshot.manifest_artifact
        || page.entries.len() > 100
    {
        return Err(invalid(
            "Stage 7 contact manifest page does not match the verified repair source",
        ));
    }
    let mut prior = after.as_deref();
    for entry in &page.entries {
        if entry.path.is_empty()
            || entry.digest.len() != 64
            || prior.is_some_and(|value| entry.path.as_str() <= value)
        {
            return Err(invalid("Stage 7 contact manifest page is not canonical"));
        }
        prior = Some(entry.path.as_str());
        if CONTACT_PATHS.contains(&entry.path.as_str())
            && !candidates.iter().any(|candidate| candidate.path == entry.path)
        {
            candidates.push(entry.clone());
        }
    }
    if let Some(next_after) = page.next_after {
        if after.as_deref().is_some_and(|value| next_after.as_str() <= value)
            || prior.is_some_and(|value| next_after.as_str() < value)
        {
            return Err(invalid("Stage 7 contact manifest continuation did not advance"));
        }
        return request_manifest(
            parameters,
            state,
            &repair_bundle_id,
            authority,
            Some(next_after),
            candidates,
        );
    }
    let selected = CONTACT_PATHS
        .iter()
        .find_map(|path| candidates.iter().find(|entry| entry.path == *path).cloned());
    let Some(entry) = selected else {
        return create_draft(
            parameters,
            profile,
            state,
            &repair_bundle_id,
            None,
            Some("security_contact_unresolved: no supported SECURITY.md path exists in the exact source manifest".into()),
        );
    };
    if entry.bytes > MAXIMUM_CONTACT_BYTES {
        return create_draft(
            parameters,
            profile,
            state,
            &repair_bundle_id,
            None,
            Some(format!(
                "security_contact_unresolved: {} exceeds the {}-byte bounded contact reader",
                entry.path, MAXIMUM_CONTACT_BYTES
            )),
        );
    }
    request_contact_read(parameters, state, &repair_bundle_id, authority, entry)
}

fn request_contact_read(
    parameters: &Value,
    state: &mut state::State,
    repair_bundle_id: &str,
    authority: ScopedSourceAuthority,
    expected: ScopedSourceEntry,
) -> Result<ModuleAction, Error> {
    let suffix = repair_bundle_id.strip_prefix("repair-").unwrap_or(repair_bundle_id);
    let key = format!(
        "red-team-disclosure-contact-{}-{}",
        &suffix[..suffix.len().min(20)],
        &expected.digest[..expected.digest.len().min(12)]
    );
    state.pending = Some(PendingRequest::DisclosureContactRead {
        key: key.clone(),
        repair_bundle_id: repair_bundle_id.into(),
        authority: authority.clone(),
        expected: expected.clone(),
    });
    state::save(parameters, state)?;
    Ok(ModuleAction::HostService {
        request: ModuleHostRequest {
            key,
            capability: HOST_CAPABILITY_SCOPED_SOURCE.into(),
            version: 1,
            operation: "read".into(),
            input: serde_json::to_value(ScopedSourceReadRequest {
                schema: 1,
                authority,
                path: expected.path,
                offset: 0,
                maximum_bytes: expected.bytes,
            })?,
        },
    })
}

pub(crate) fn contact_result(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
    repair_bundle_id: String,
    expected: ScopedSourceEntry,
    read: ScopedSourceReadResult,
) -> Result<ModuleAction, Error> {
    let repair = verified_repair(state, &repair_bundle_id)?;
    if read.schema != 1
        || read.snapshot_digest != repair.source_snapshot
        || read.path != expected.path
        || read.source_digest != expected.digest
        || read.source_bytes != expected.bytes
        || read.range_start != 0
        || read.range_end != read.source_bytes
        || u64::try_from(read.bytes.len()).unwrap_or(u64::MAX) != read.source_bytes
        || digest(&read.bytes) != read.range_artifact
        || digest(&read.bytes) != read.source_digest
    {
        return Err(invalid(
            "Stage 7 SECURITY.md bytes do not match the exact complete source entry",
        ));
    }
    let Ok(text) = std::str::from_utf8(&read.bytes) else {
        return create_draft(
            parameters,
            profile,
            state,
            &repair_bundle_id,
            None,
            Some(format!("security_contact_unresolved: {} is not valid UTF-8", read.path)),
        );
    };
    let recipient = extract_mailto(text);
    let policy_url = extract_security_url(text);
    let source_excerpt = contact_excerpt(text, recipient.as_deref(), policy_url.as_deref());
    let provenance = identity(
        ModuleResearchIdentityKind::Receipt,
        format!("scoped-source-contact:{}", read.path),
        &json!({
            "schema": MODULE_RESEARCH_CONTRACT_VERSION,
            "snapshot": read.snapshot_digest,
            "path": read.path,
            "source_digest": read.source_digest,
            "range_artifact": read.range_artifact,
            "bytes": read.source_bytes,
        }),
    )?;
    let contact = ModuleResearchDisclosureContact {
        path: read.path,
        source_digest: read.source_digest,
        range_artifact: read.range_artifact,
        recipient,
        policy_url,
        source_excerpt,
        provenance,
    };
    let unresolved = (contact.recipient.is_none() && contact.policy_url.is_none()).then(|| {
        format!(
            "security_contact_unresolved: {} contains no exact mailto recipient or security HTTPS URL",
            contact.path
        )
    });
    create_draft(parameters, profile, state, &repair_bundle_id, Some(contact), unresolved)
}

pub(crate) fn contact_unavailable(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
    repair_bundle_id: &str,
    detail: &str,
) -> Result<ModuleAction, Error> {
    create_draft(
        parameters,
        profile,
        state,
        repair_bundle_id,
        None,
        Some(format!(
            "security_contact_unresolved: scoped-source contact lookup failed safely: {}",
            detail.chars().take(512).collect::<String>()
        )),
    )
}

fn create_draft(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
    repair_bundle_id: &str,
    contact: Option<ModuleResearchDisclosureContact>,
    contact_placeholder: Option<String>,
) -> Result<ModuleAction, Error> {
    let repair = verified_repair(state, repair_bundle_id)?.clone();
    let poc = state
        .research_poc_bundles
        .iter()
        .find(|poc| poc.id == repair.poc_bundle_id && poc.state == ModuleResearchPocState::Verified)
        .ok_or_else(|| invalid("Stage 7 package lost its verified Stage 5 PoC"))?
        .clone();
    let template = template_identity()?;
    let contact_digest = contact
        .as_ref()
        .map_or_else(|| "unresolved".into(), |value| value.provenance.digest.clone());
    let package_id = format!(
        "disclosure-{}",
        digest(
            format!(
                "peritus.red-team.disclosure-package.v1\0{}\0{}\0{}",
                repair.id, template.digest, contact_digest
            )
            .as_bytes()
        )
    );
    if let Some(existing) =
        state.research_disclosure_packages.iter().find(|package| package.id == package_id)
    {
        state.pending = None;
        state::save(parameters, state)?;
        return Ok(reply(render(existing), profile, super::actions(state), None));
    }
    let mut placeholders = vec![
        "affected_versions_unresolved: only the exact vulnerable source snapshot is established"
            .into(),
        "vendor_product_name_unresolved: no product identity was inferred from target behavior"
            .into(),
        "embargo_date_unresolved: coordinated dates require a later authorized human decision"
            .into(),
        "cve_identifier_unresolved: no CVE was requested or assigned".into(),
        "vendor_acknowledgement_unresolved: no external message was sent".into(),
        "discovery_date_unresolved: no trusted external or user-supplied date was provided".into(),
        "workarounds_unresolved: no independently verified workaround was established".into(),
    ];
    if let Some(value) = contact_placeholder {
        placeholders.push(value);
    }
    placeholders.sort();
    placeholders.dedup();
    let advisory = advisory_value(&package_id, &repair, &poc, contact.as_ref(), &placeholders)?;
    let advisory_digest = digest(&json_bytes(&advisory)?);
    let package = ModuleResearchDisclosurePackage {
        schema: MODULE_RESEARCH_CONTRACT_VERSION,
        id: package_id,
        chain_id: repair.chain_id.clone(),
        poc_bundle_id: Some(repair.poc_bundle_id.clone()),
        repair_bundle_id: repair.id.clone(),
        source_snapshot: repair.source_snapshot.clone(),
        template,
        advisory_digest,
        contact,
        redaction_review: None,
        no_delivery_proof: None,
        state: ModuleResearchDisclosureState::Draft,
        timeline: vec![ModuleResearchDisclosureTimelineEntry {
            sequence: 1,
            state: ModuleResearchDisclosureState::Draft,
            occurred_at: None,
            receipt: None,
            detail: "Deterministic private drafts were declared from one verified Stage 6 repair; no external operation ran.".into(),
        }],
        artifacts: Vec::new(),
        placeholders,
    };
    state.pending = None;
    state.research_disclosure_packages.push(package.clone());
    state::save(parameters, state)?;
    Ok(reply(
        format!(
            "# Stage 7 disclosure draft declared\n\n{}\n\nUse `disclosure-review {}` to generate and independently review the owner-only local package. No email, repository, issue, portal, CVE, network, or publication operation was exposed.",
            render(&package),
            package.id
        ),
        profile,
        super::actions(state),
        None,
    ))
}

fn review(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
    selected_package: Option<&str>,
) -> Result<ModuleAction, Error> {
    if state.pending.is_some() {
        return Err(invalid("settle or cancel the retained host request before Stage 7 review"));
    }
    let index =
        select_package_index(state, selected_package, ModuleResearchDisclosureState::Draft)?;
    let package = state.research_disclosure_packages[index].clone();
    let repair = verified_repair(state, &package.repair_bundle_id)?.clone();
    let poc = state
        .research_poc_bundles
        .iter()
        .find(|poc| {
            Some(poc.id.as_str()) == package.poc_bundle_id.as_deref()
                && poc.state == ModuleResearchPocState::Verified
        })
        .ok_or_else(|| invalid("Stage 7 package lost its verified Stage 5 PoC"))?
        .clone();
    let mut prepared = prepare_artifacts(parameters, &package, &repair, &poc)?;
    let no_delivery = no_delivery_bytes(&package)?;
    let no_delivery_proof = byte_identity(
        ModuleResearchIdentityKind::Receipt,
        format!("no-delivery-proof:{}", package.id),
        &no_delivery,
    );
    prepared.push(PreparedArtifact {
        name: "no-delivery.json",
        media_type: "application/json",
        classification: ModuleResearchArtifactClassification::PrivateDisclosurePackage,
        bytes: no_delivery,
    });
    let redaction = redaction_review_bytes(&package, &prepared)?;
    let redaction_review = byte_identity(
        ModuleResearchIdentityKind::Receipt,
        format!("redaction-review:{}", package.id),
        &redaction,
    );
    prepared.push(PreparedArtifact {
        name: "redaction-review.json",
        media_type: "application/json",
        classification: ModuleResearchArtifactClassification::PrivateDisclosurePackage,
        bytes: redaction,
    });
    let evidence_manifest = evidence_manifest_bytes(&package, &repair, &poc, &prepared)?;
    prepared.push(PreparedArtifact {
        name: "evidence-manifest.json",
        media_type: "application/json",
        classification: ModuleResearchArtifactClassification::PrivateDisclosurePackage,
        bytes: evidence_manifest,
    });
    let export_manifest = export_manifest_bytes(&package, &prepared)?;
    prepared.push(PreparedArtifact {
        name: "export-manifest.json",
        media_type: "application/json",
        classification: ModuleResearchArtifactClassification::PrivateDisclosurePackage,
        bytes: export_manifest,
    });
    let prepared_names = prepared.iter().map(|artifact| artifact.name).collect::<BTreeSet<_>>();
    let expected_names = DISCLOSURE_ARTIFACT_NAMES.into_iter().collect::<BTreeSet<_>>();
    if prepared.len() != expected_names.len() || prepared_names != expected_names {
        return Err(invalid("Stage 7 review did not produce the exact disclosure artifact set"));
    }
    if prepared
        .iter()
        .find(|artifact| artifact.name == "advisory.json")
        .is_none_or(|artifact| digest(&artifact.bytes) != package.advisory_digest)
    {
        return Err(invalid("Stage 7 advisory projection changed after draft declaration"));
    }
    let artifacts = publish_artifacts(parameters, &package.id, &prepared)?;
    for artifact in &artifacts {
        if !state.research_artifacts.iter().any(|existing| existing == artifact) {
            state.research_artifacts.push(artifact.clone());
        }
    }
    let package = &mut state.research_disclosure_packages[index];
    package.artifacts = artifacts;
    package.redaction_review = Some(redaction_review);
    package.no_delivery_proof = Some(no_delivery_proof);
    package.state = ModuleResearchDisclosureState::PackageReviewed;
    package.timeline.push(ModuleResearchDisclosureTimelineEntry {
        sequence: 2,
        state: ModuleResearchDisclosureState::PackageReviewed,
        occurred_at: None,
        receipt: None,
        detail: "Every private and sanitized artifact passed deterministic evidence-binding, classification, redaction, and no-delivery review.".into(),
    });
    let id = package.id.clone();
    let count = package.artifacts.len();
    state::save(parameters, state)?;
    Ok(reply(
        format!(
            "# Stage 7 package reviewed\n\n- Package: `{id}`\n- Owner-only artifacts: {count}\n- Redaction review: passed\n- Contact provenance: {}\n- Delivery operations: none\n\nUse `disclosure-export {id}` to mark this reviewed package as locally exported. This does not authorize or perform transport.",
            if package_contact_resolved(&state.research_disclosure_packages[index]) {
                "verified from scoped SECURITY.md"
            } else {
                "unresolved placeholder retained"
            }
        ),
        profile,
        super::actions(state),
        None,
    ))
}

fn export(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
    selected_package: Option<&str>,
) -> Result<ModuleAction, Error> {
    if state.pending.is_some() {
        return Err(invalid("settle or cancel the retained host request before Stage 7 export"));
    }
    let index = select_reviewed_package_index(state, selected_package)?;
    if state.research_disclosure_packages[index].state == ModuleResearchDisclosureState::Exported {
        let package = &state.research_disclosure_packages[index];
        return Ok(reply(render(package), profile, super::actions(state), None));
    }
    verify_published_artifacts(parameters, &state.research_disclosure_packages[index])?;
    let package = &mut state.research_disclosure_packages[index];
    package.timeline.push(ModuleResearchDisclosureTimelineEntry {
        sequence: 3,
        state: ModuleResearchDisclosureState::AwaitingUserAuthorization,
        occurred_at: None,
        receipt: None,
        detail: "The reviewed private package is ready for local export; any later transport still requires separate explicit authorization and an implementation outside this stage.".into(),
    });
    package.timeline.push(ModuleResearchDisclosureTimelineEntry {
        sequence: 4,
        state: ModuleResearchDisclosureState::Exported,
        occurred_at: None,
        receipt: None,
        detail: "Owner-only files were exported locally after digest verification; no recipient, network, repository, email, issue, portal, CVE, or publication state changed.".into(),
    });
    package.state = ModuleResearchDisclosureState::Exported;
    let rendered = render(package);
    state::save(parameters, state)?;
    Ok(reply(
        format!(
            "# Stage 7 private package exported locally\n\n{rendered}\n\nThe export is local and owner-only. Red Team exposes no send, submit, publish, repository, issue, portal, CVE-request, or disclosure transport operation."
        ),
        profile,
        super::actions(state),
        None,
    ))
}

fn prepare_artifacts(
    parameters: &Value,
    package: &ModuleResearchDisclosurePackage,
    repair: &ModuleResearchRepairBundle,
    poc: &peritus_plugin_sdk::ModuleResearchPocBundle,
) -> Result<Vec<PreparedArtifact>, Error> {
    let advisory =
        advisory_value(&package.id, repair, poc, package.contact.as_ref(), &package.placeholders)?;
    let advisory_json = json_bytes(&advisory)?;
    let advisory_markdown = advisory_markdown(package, repair);
    let recipient = package
        .contact
        .as_ref()
        .and_then(|contact| contact.recipient.as_deref())
        .unwrap_or("[UNRESOLVED SECURITY CONTACT]");
    let policy = package
        .contact
        .as_ref()
        .and_then(|contact| contact.policy_url.as_deref())
        .unwrap_or("[UNRESOLVED SECURITY POLICY URL]");
    let mut prepared = vec![
        text_artifact(
            "advisory.json",
            "application/json",
            ModuleResearchArtifactClassification::PrivateDisclosurePackage,
            advisory_json,
        ),
        text_artifact(
            "advisory.md",
            "text/markdown",
            ModuleResearchArtifactClassification::PrivateDisclosurePackage,
            advisory_markdown.into_bytes(),
        ),
        text_artifact(
            "vendor-email.md",
            "text/markdown",
            ModuleResearchArtifactClassification::PrivateDisclosurePackage,
            vendor_email(package, recipient, policy).into_bytes(),
        ),
        text_artifact(
            "github-private-advisory.md",
            "text/markdown",
            ModuleResearchArtifactClassification::PrivateDisclosurePackage,
            github_advisory(package).into_bytes(),
        ),
        text_artifact(
            "bug-bounty-psirt-intake.md",
            "text/markdown",
            ModuleResearchArtifactClassification::PrivateDisclosurePackage,
            psirt_intake(package, policy).into_bytes(),
        ),
        text_artifact(
            "cna-cve-intake.md",
            "text/markdown",
            ModuleResearchArtifactClassification::PrivateDisclosurePackage,
            cna_intake(package).into_bytes(),
        ),
        text_artifact(
            "acknowledgement-follow-up.md",
            "text/markdown",
            ModuleResearchArtifactClassification::PrivateDisclosurePackage,
            acknowledgement_follow_up(package, recipient).into_bytes(),
        ),
        text_artifact(
            "fix-verification-response.md",
            "text/markdown",
            ModuleResearchArtifactClassification::PrivateDisclosurePackage,
            fix_verification(package, repair).into_bytes(),
        ),
        text_artifact(
            "coordinated-publication-draft.md",
            "text/markdown",
            ModuleResearchArtifactClassification::SanitizedPublicationDraft,
            public_draft().into_bytes(),
        ),
    ];
    let vendor = poc
        .artifacts
        .iter()
        .find(|artifact| {
            artifact.classification == ModuleResearchArtifactClassification::PrivateVendorPoc
        })
        .ok_or_else(|| invalid("Stage 7 verified PoC bundle has no vendor PoC artifact"))?;
    let regression = poc
        .artifacts
        .iter()
        .find(|artifact| {
            artifact.classification == ModuleResearchArtifactClassification::MinimalRegressionPoc
        })
        .ok_or_else(|| invalid("Stage 7 verified PoC bundle has no regression PoC artifact"))?;
    let patch = repair
        .artifacts
        .iter()
        .find(|artifact| {
            artifact.classification == ModuleResearchArtifactClassification::PrivateRepairPatch
        })
        .ok_or_else(|| invalid("Stage 7 verified repair has no exact patch artifact"))?;
    let matrix = repair
        .artifacts
        .iter()
        .find(|artifact| artifact.relative_private_path.ends_with("/regression-matrix.json"))
        .ok_or_else(|| invalid("Stage 7 verified repair has no regression matrix artifact"))?;
    prepared.extend([
        copied_artifact(parameters, "vendor-poc.py", vendor)?,
        copied_artifact(parameters, "regression-poc.py", regression)?,
        copied_artifact(parameters, "repair.patch", patch)?,
        copied_artifact(parameters, "regression-matrix.json", matrix)?,
    ]);
    Ok(prepared)
}

fn advisory_value(
    package_id: &str,
    repair: &ModuleResearchRepairBundle,
    poc: &peritus_plugin_sdk::ModuleResearchPocBundle,
    contact: Option<&ModuleResearchDisclosureContact>,
    placeholders: &[String],
) -> Result<Value, Error> {
    let patch = repair
        .patch
        .as_ref()
        .ok_or_else(|| invalid("verified Stage 6 repair has no patch identity"))?;
    let replay = repair
        .replay
        .as_ref()
        .ok_or_else(|| invalid("verified Stage 6 repair has no replay identity"))?;
    let review =
        repair.review.as_ref().ok_or_else(|| invalid("verified Stage 6 repair has no review"))?;
    Ok(json!({
        "schema": MODULE_RESEARCH_CONTRACT_VERSION,
        "template_version": TEMPLATE_VERSION,
        "projection_version": PROJECTION_VERSION,
        "package_id": package_id,
        "title": "Stored content can execute client-side script in the verified application path",
        "summary": "A credential-free synthetic actor stored markup that a later real-browser navigation interpreted as active content in the exact disposable vulnerable target. The retained canary demonstrated client-script execution only; no credential, personal data, production system, or public destination was involved.",
        "evidence_boundary": "runtime_confirmed_private_laboratory",
        "source_snapshot": repair.source_snapshot,
        "product": {
            "name": Value::Null,
            "component": Value::Null,
            "status": "unresolved",
            "detail": "No product or component identity was inferred from private target behavior."
        },
        "discovery_date": {
            "value": Value::Null,
            "status": "unresolved",
            "detail": "A trusted external or user-supplied discovery date was not available."
        },
        "chain_id": repair.chain_id,
        "poc_bundle_id": poc.id,
        "repair_bundle_id": repair.id,
        "root_cause": {
            "group": patch.root_cause_group,
            "earliest_repairable_prerequisite": patch.earliest_prerequisite,
            "target_path": patch.target_path,
            "exact_preimage_digest": patch.original_digest,
        },
        "prerequisites": [
            patch.earliest_prerequisite.clone(),
            "credential-free synthetic actor can store content",
            "a later synthetic browser navigation renders the stored content"
        ],
        "patch": patch,
        "replay_receipt": replay,
        "patch_review": review,
        "original_source_verification": repair.original_verification,
        "affected_versions": {
            "status": "unresolved",
            "known_affected_source_snapshot": repair.source_snapshot,
            "detail": "No product release range was inferred from one immutable source snapshot."
        },
        "tested_versions": {
            "vulnerable": [{"source_snapshot": repair.source_snapshot, "result": "harmless canary reproduced"}],
            "repaired": [{"patch_digest": patch.diff_digest, "result": "recorded PoC, full chain, and bounded regression matrix blocked"}],
            "released_product_versions": []
        },
        "artifact_hashes": {
            "poc": poc.artifacts.iter().map(|artifact| json!({"path":artifact.relative_private_path,"digest":artifact.identity.digest,"classification":artifact.classification})).collect::<Vec<_>>(),
            "repair": repair.artifacts.iter().map(|artifact| json!({"path":artifact.relative_private_path,"digest":artifact.identity.digest,"classification":artifact.classification})).collect::<Vec<_>>(),
        },
        "impact": {
            "demonstrated": ["stored attacker-controlled markup reached client-script execution", "a harmless same-origin canary request was observed"],
            "not_demonstrated": ["credential access", "personal-data access", "cross-tenant access", "production reachability", "availability impact", "public-network exploitation"]
        },
        "classifications": [
            {"scheme":"CWE","version":"4.18","id":"CWE-79","label":"Improper Neutralization of Input During Web Page Generation","basis":"The retained source and browser evidence demonstrates stored active markup."},
            {"scheme":"CAPEC","version":"2026-10-30 pinned projection","id":"CAPEC-63","label":"Cross-Site Scripting","basis":"The demonstrated path stores input and later executes it in a browser document."},
            {"scheme":"OWASP Top 10","version":"2021","id":"A03:2021","label":"Injection","basis":"The browser interpreted attacker-controlled markup as active content."},
            {"scheme":"CVSS","version":"3.1","vector":"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N","score":3.3,"severity":"low","basis":"Conservative laboratory-bounded projection: only local private reachability, user navigation, canary execution, and low integrity impact were demonstrated."}
        ],
        "remediation": {
            "proposed_patch": patch,
            "regression_review": review,
            "workarounds": [],
            "workaround_status": "unresolved"
        },
        "contact": contact,
        "placeholders": placeholders,
        "limitations": repair.limitations,
        "timeline": {
            "state_at_declaration": "draft",
            "local_state_machine": ["draft", "package_reviewed", "awaiting_user_authorization", "exported"],
            "external_states_reached": [],
            "timestamps_supplied": false
        },
        "coordination": {
            "embargo_preference": Value::Null,
            "acknowledgement_state": "unresolved",
            "cve_state": "not_requested",
            "cna_state": "unresolved"
        },
        "delivery": {"performed":false,"operations_exposed":[]}
    }))
}

fn advisory_markdown(
    package: &ModuleResearchDisclosurePackage,
    repair: &ModuleResearchRepairBundle,
) -> String {
    format!(
        "# Private security advisory draft\n\nSensitivity: private vendor disclosure package. Do not publish without separate authorization and review.\n\n## Summary\n\nA credential-free synthetic actor stored markup that a later real-browser navigation interpreted as active content in the exact disposable vulnerable target. The retained effect is a harmless same-origin canary only.\n\n## Evidence boundary\n\n- Source snapshot: `{}`\n- Confirmed chain: `{}`\n- Verified PoC: `{}`\n- Verified repair: `{}`\n- Advisory digest: `{}`\n- Original source unchanged after qualification: true\n\n## Classification\n\n- CWE-79\n- CAPEC-63\n- OWASP Top 10 2021 A03 Injection\n- Conservative CVSS 3.1: `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` (3.3 Low)\n\n## Remediation\n\nApply the exact-preimage patch only after independent project review. The disposable patched twin blocked the minimized PoC and full chain while preserving recorded legitimate behavior. Re-run the included regression matrix after integration.\n\n## Unresolved facts\n\n{}\n\nNo message, submission, issue, CVE request, repository mutation, or publication was performed.\n",
        package.source_snapshot,
        package.chain_id,
        package.poc_bundle_id.as_deref().unwrap_or("unresolved"),
        repair.id,
        package.advisory_digest,
        package
            .placeholders
            .iter()
            .map(|value| format!("- {value}"))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

fn vendor_email(
    package: &ModuleResearchDisclosurePackage,
    recipient: &str,
    policy: &str,
) -> String {
    format!(
        "# Initial vendor email draft\n\nTo: {recipient}\nSubject: Private security report: stored client-script execution\nPolicy reference: {policy}\n\nHello Security Team,\n\nWe are sharing a private, laboratory-confirmed report concerning stored attacker-controlled markup that executed a harmless same-origin canary during a later browser navigation. The attached package contains a minimized PoC, exact patch, regression matrix, evidence manifest, limitations, and independent patch review.\n\nThe evidence is bound to source snapshot `{}` and does not establish a product release range or production reachability. We have not published or submitted this report elsewhere. Please acknowledge receipt through your documented security process and provide a preferred coordination timeline.\n\nRegards,\n[REPORTER NAME AND CONTACT]\n",
        package.source_snapshot
    )
}

fn github_advisory(package: &ModuleResearchDisclosurePackage) -> String {
    format!(
        "# GitHub private security advisory draft\n\nStatus: draft only; do not submit automatically.\n\n## Summary\nStored attacker-controlled markup reached client-script execution in the exact private laboratory target.\n\n## Ecosystem / package / affected versions\n[UNRESOLVED — source snapshot `{}` is the only established affected identity]\n\n## Severity\nLow under the conservative laboratory-bounded CVSS 3.1 vector `AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N` (3.3).\n\n## Reproduction and remediation\nAttach `vendor-poc.py`, `repair.patch`, `regression-matrix.json`, and `evidence-manifest.json` from this private package.\n\n## Credits and timeline\n[UNRESOLVED — requires authorized human input]\n",
        package.source_snapshot
    )
}

fn psirt_intake(package: &ModuleResearchDisclosurePackage, policy: &str) -> String {
    format!(
        "# Bug-bounty / PSIRT intake draft\n\nStatus: private draft only; no portal submission occurred.\nPolicy: {policy}\n\n- Weakness: stored client-script execution (CWE-79)\n- Evidence: real-browser canary in a disposable private laboratory\n- Source identity: `{}`\n- PoC bundle: `{}`\n- Repair bundle: `{}`\n- Production impact: unresolved\n- Affected versions: unresolved\n- Attachments: advisory, PoC, exact patch, regression matrix, evidence manifest\n",
        package.source_snapshot,
        package.poc_bundle_id.as_deref().unwrap_or("unresolved"),
        package.repair_bundle_id,
    )
}

fn cna_intake(package: &ModuleResearchDisclosurePackage) -> String {
    format!(
        "# CNA / CVE intake draft\n\nStatus: preparation only. No CVE request was made.\n\n- Vulnerability type: CWE-79 stored client-script execution\n- Affected product and versions: unresolved\n- Vendor: unresolved\n- Source snapshot evidence: `{}`\n- Public references: none\n- CVE ID: unresolved\n- Credit, embargo, and publication dates: unresolved\n\nThis draft must not be submitted until product identity, affected versions, vendor policy, and authorization are independently established.\n",
        package.source_snapshot
    )
}

fn acknowledgement_follow_up(package: &ModuleResearchDisclosurePackage, recipient: &str) -> String {
    format!(
        "# Acknowledgement follow-up draft\n\nTo: {recipient}\nSubject: Follow-up on private security report\n\nHello Security Team,\n\nThis is a follow-up regarding private package `{}`. Please confirm receipt and provide the tracking identifier and preferred coordination timeline. No public disclosure date has been selected.\n\nRegards,\n[REPORTER NAME AND CONTACT]\n",
        package.id
    )
}

fn fix_verification(
    package: &ModuleResearchDisclosurePackage,
    repair: &ModuleResearchRepairBundle,
) -> String {
    format!(
        "# Fix-verification response draft\n\nPackage: `{}`\nReference repair: `{}`\n\nThe included copy-only candidate blocked the minimized PoC and full confirmed chain across the retained 19-case regression matrix, while the recorded legitimate behavior remained observable. This result applies only to the exact patched twin and recorded mutations. A vendor candidate must be independently built and replayed before it can be described as verified.\n\nRequested vendor inputs:\n- exact candidate commit or source archive\n- affected and fixed version facts\n- build and deployment instructions\n- acknowledgement of any intentionally different remediation\n",
        package.id, repair.id
    )
}

fn public_draft() -> String {
    "# Coordinated-publication draft\n\nStatus: sanitized placeholder; not approved or published.\n\nA stored-content handling flaw in an application path could cause attacker-controlled markup to be interpreted as active browser content after a later user navigation. The issue was reproduced only in a private disposable laboratory with a harmless canary. A candidate remediation encoded stored content before browser interpretation and passed the recorded regression cases.\n\nAffected product, versions, vendor acknowledgement, CVE identity, credits, dates, and public references remain unresolved. Do not add reproduction code, private contacts, exact source identities, or unpublished patch details without separate coordinated review.\n".into()
}

fn no_delivery_bytes(package: &ModuleResearchDisclosurePackage) -> Result<Vec<u8>, Error> {
    json_bytes(&json!({
        "schema": MODULE_RESEARCH_CONTRACT_VERSION,
        "package_id": package.id,
        "stage": 7,
        "local_export_only": true,
        "host_service_operations": ["scoped-source.manifest", "scoped-source.read"],
        "delivery_operations_exposed": [],
        "email_sent": false,
        "portal_submitted": false,
        "issue_created": false,
        "repository_mutated": false,
        "cve_requested": false,
        "published": false,
        "outbound_network_authority": false,
        "detail": "Stage 7 can read bounded source-scoped contact facts and write owner-only local artifacts. It has no delivery adapter, tool, command, or host request."
    }))
}

fn redaction_review_bytes(
    package: &ModuleResearchDisclosurePackage,
    artifacts: &[PreparedArtifact],
) -> Result<Vec<u8>, Error> {
    let forbidden = [
        "authorization: bearer",
        "begin private key",
        "chain-of-thought",
        "/home/",
        "cookie:",
        "set-cookie:",
    ];
    for artifact in artifacts {
        let lower = String::from_utf8_lossy(&artifact.bytes).to_ascii_lowercase();
        if let Some(pattern) = forbidden.iter().find(|pattern| lower.contains(**pattern)) {
            return Err(invalid(format!(
                "Stage 7 redaction review rejected `{}` because it contains `{pattern}`",
                artifact.name
            )));
        }
        if artifact.bytes.len() > MAXIMUM_ARTIFACT_BYTES {
            return Err(invalid(format!(
                "Stage 7 artifact `{}` exceeds the private export bound",
                artifact.name
            )));
        }
    }
    let public = artifacts
        .iter()
        .find(|artifact| artifact.name == "coordinated-publication-draft.md")
        .ok_or_else(|| invalid("Stage 7 package omitted the sanitized public projection"))?;
    let public_text = String::from_utf8_lossy(&public.bytes);
    let mut private_markers = vec![
        package.id.as_str(),
        package.chain_id.as_str(),
        package.repair_bundle_id.as_str(),
        package.source_snapshot.as_str(),
        "VULNERABLE =",
        "<img",
        "fetch(",
    ];
    if let Some(poc) = package.poc_bundle_id.as_deref() {
        private_markers.push(poc);
    }
    if let Some(contact) = &package.contact {
        if let Some(recipient) = contact.recipient.as_deref() {
            private_markers.push(recipient);
        }
        if let Some(policy) = contact.policy_url.as_deref() {
            private_markers.push(policy);
        }
    }
    if private_markers.iter().any(|marker| public_text.contains(marker))
        || contains_hex_digest(public_text.as_bytes())
    {
        return Err(invalid(
            "Stage 7 sanitized publication draft contains private identity or reproduction material",
        ));
    }
    json_bytes(&json!({
        "schema": MODULE_RESEARCH_CONTRACT_VERSION,
        "package_id": package.id,
        "reviewer": "peritus-disclosure-redaction-reviewer-2026-10-30.1",
        "accepted": true,
        "private_artifacts_scanned": artifacts.len(),
        "checks": {
            "provider_tokens_absent": true,
            "real_credentials_absent": true,
            "unrelated_source_absent": true,
            "personal_data_absent": true,
            "chain_of_thought_absent": true,
            "unnecessary_raw_traffic_absent": true,
            "sanitized_public_projection_has_no_private_identity": true,
            "classifications_are_explicit": true
        },
        "limitations": "Pattern review is bounded to the exact retained artifact bytes and cannot prove facts outside this package."
    }))
}

fn evidence_manifest_bytes(
    package: &ModuleResearchDisclosurePackage,
    repair: &ModuleResearchRepairBundle,
    poc: &peritus_plugin_sdk::ModuleResearchPocBundle,
    artifacts: &[PreparedArtifact],
) -> Result<Vec<u8>, Error> {
    json_bytes(&json!({
        "schema": MODULE_RESEARCH_CONTRACT_VERSION,
        "package_id": package.id,
        "source_snapshot": package.source_snapshot,
        "chain_id": package.chain_id,
        "poc_bundle_id": poc.id,
        "repair_bundle_id": repair.id,
        "poc_replay": poc.replay,
        "repair_replay": repair.replay,
        "patch": repair.patch,
        "review": repair.review,
        "original_source_verification": repair.original_verification,
        "contact_provenance": package.contact.as_ref().map(|contact| &contact.provenance),
        "artifacts": artifact_manifest(artifacts),
        "raw_traffic_included": false
    }))
}

fn export_manifest_bytes(
    package: &ModuleResearchDisclosurePackage,
    artifacts: &[PreparedArtifact],
) -> Result<Vec<u8>, Error> {
    json_bytes(&json!({
        "schema": MODULE_RESEARCH_CONTRACT_VERSION,
        "package_id": package.id,
        "owner_only": true,
        "local_export_only": true,
        "artifacts": artifact_manifest(artifacts),
        "manifest_self_digest": "recorded by durable artifact metadata",
        "delivery_performed": false
    }))
}

fn artifact_manifest(artifacts: &[PreparedArtifact]) -> Vec<Value> {
    artifacts
        .iter()
        .map(|artifact| {
            json!({
                "path": artifact.name,
                "media_type": artifact.media_type,
                "classification": artifact.classification,
                "bytes": artifact.bytes.len(),
                "digest": digest(&artifact.bytes)
            })
        })
        .collect()
}

fn publish_artifacts(
    parameters: &Value,
    package_id: &str,
    prepared: &[PreparedArtifact],
) -> Result<Vec<ModuleResearchArtifactIdentity>, Error> {
    if !valid_package_id(package_id) {
        return Err(invalid("Stage 7 package identity is not a canonical disclosure digest"));
    }
    let relative_root = PathBuf::from("research-artifacts").join(package_id);
    let root = state::private_root(parameters)?.join(&relative_root);
    if root.exists() {
        verify_existing_directory(&root, prepared)?;
    } else {
        let parent = root.parent().ok_or_else(|| invalid("Stage 7 artifact root has no parent"))?;
        fs::create_dir_all(parent)?;
        if parent.is_symlink() || !parent.is_dir() {
            return Err(invalid("Stage 7 artifact parent is not a private directory"));
        }
        set_private_directory(parent)?;
        let temporary = tempfile::Builder::new().prefix("stage7-").tempdir_in(parent)?;
        set_private_directory(temporary.path())?;
        for artifact in prepared {
            write_private(&temporary.path().join(artifact.name), &artifact.bytes)?;
        }
        let temporary_path = temporary.keep();
        fs::rename(&temporary_path, &root)?;
        #[cfg(unix)]
        fs::File::open(parent)?.sync_all()?;
    }
    prepared
        .iter()
        .map(|artifact| {
            let relative = relative_root
                .join(artifact.name)
                .to_str()
                .ok_or_else(|| invalid("Stage 7 artifact path is not UTF-8"))?
                .replace('\\', "/");
            Ok(ModuleResearchArtifactIdentity {
                schema: MODULE_RESEARCH_CONTRACT_VERSION,
                identity: ModuleResearchIdentity {
                    schema: MODULE_RESEARCH_CONTRACT_VERSION,
                    kind: ModuleResearchIdentityKind::Artifact,
                    value: relative.clone(),
                    digest: digest(&artifact.bytes),
                },
                media_type: artifact.media_type.into(),
                bytes: u64::try_from(artifact.bytes.len()).unwrap_or(u64::MAX),
                classification: artifact.classification,
                relative_private_path: relative,
                owner_only: true,
            })
        })
        .collect()
}

fn verify_existing_directory(root: &Path, prepared: &[PreparedArtifact]) -> Result<(), Error> {
    if root.is_symlink() || !root.is_dir() || !private_mode(root)? {
        return Err(invalid("Stage 7 artifact destination is not a private directory"));
    }
    let expected = prepared.iter().map(|artifact| artifact.name).collect::<BTreeSet<_>>();
    let actual = fs::read_dir(root)?
        .map(|entry| {
            entry
                .map_err(Error::from)?
                .file_name()
                .into_string()
                .map_err(|_| invalid("Stage 7 artifact filename is not UTF-8"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if actual != expected.iter().map(|value| (*value).to_owned()).collect() {
        return Err(invalid("Stage 7 artifact destination contains unexpected files"));
    }
    for artifact in prepared {
        let path = root.join(artifact.name);
        if path.is_symlink()
            || !path.is_file()
            || fs::read(&path)? != artifact.bytes
            || !private_mode(&path)?
        {
            return Err(invalid(format!(
                "Stage 7 retained artifact `{}` differs from the reviewed bytes",
                artifact.name
            )));
        }
    }
    Ok(())
}

fn verify_published_artifacts(
    parameters: &Value,
    package: &ModuleResearchDisclosurePackage,
) -> Result<(), Error> {
    if package.artifacts.is_empty()
        || package.redaction_review.is_none()
        || package.no_delivery_proof.is_none()
    {
        return Err(invalid("Stage 7 package has not passed private review"));
    }
    if !valid_package_id(&package.id) {
        return Err(invalid("Stage 7 package identity is not a canonical disclosure digest"));
    }
    let private_root = state::private_root(parameters)?;
    let package_root = private_root.join("research-artifacts").join(&package.id);
    if package_root.is_symlink() || !package_root.is_dir() || !private_mode(&package_root)? {
        return Err(invalid("Stage 7 package directory is missing or no longer owner-only"));
    }
    let expected = DISCLOSURE_ARTIFACT_NAMES.into_iter().collect::<BTreeSet<_>>();
    let actual = fs::read_dir(&package_root)?
        .map(|entry| {
            entry
                .map_err(Error::from)?
                .file_name()
                .into_string()
                .map_err(|_| invalid("Stage 7 artifact filename is not UTF-8"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if actual != expected.iter().map(|value| (*value).to_owned()).collect() {
        return Err(invalid("Stage 7 package directory does not contain the exact reviewed set"));
    }
    for artifact in &package.artifacts {
        let path = private_root.join(&artifact.relative_private_path);
        if path.is_symlink() || !path.is_file() || !private_mode(&path)? {
            return Err(invalid("Stage 7 artifact is missing or no longer owner-only"));
        }
        let bytes = fs::read(path)?;
        if digest(&bytes) != artifact.identity.digest
            || u64::try_from(bytes.len()).unwrap_or(u64::MAX) != artifact.bytes
        {
            return Err(invalid("Stage 7 artifact bytes changed after review"));
        }
    }
    Ok(())
}

fn copied_artifact(
    parameters: &Value,
    name: &'static str,
    artifact: &ModuleResearchArtifactIdentity,
) -> Result<PreparedArtifact, Error> {
    if !artifact.owner_only {
        return Err(invalid("Stage 7 cannot copy a non-private upstream artifact"));
    }
    let root = state::private_root(parameters)?;
    let path = root.join(&artifact.relative_private_path);
    if path.is_symlink() || !path.is_file() || !private_mode(&path)? {
        return Err(invalid("Stage 7 upstream artifact is missing or not owner-only"));
    }
    let bytes = fs::read(path)?;
    if digest(&bytes) != artifact.identity.digest
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) != artifact.bytes
        || bytes.len() > MAXIMUM_ARTIFACT_BYTES
    {
        return Err(invalid("Stage 7 upstream artifact bytes do not match durable evidence"));
    }
    Ok(PreparedArtifact {
        name,
        media_type: match name {
            "repair.patch" => "text/x-diff",
            "regression-matrix.json" => "application/json",
            _ => "text/x-python",
        },
        classification: artifact.classification,
        bytes,
    })
}

fn select_repair<'a>(
    state: &'a state::State,
    selected: Option<&str>,
) -> Result<&'a ModuleResearchRepairBundle, Error> {
    let repair = if let Some(selected) = selected {
        state.research_repair_bundles.iter().find(|repair| repair.id == selected)
    } else {
        state
            .research_repair_bundles
            .iter()
            .rev()
            .find(|repair| repair.state == ModuleResearchRepairState::Verified)
    }
    .ok_or_else(|| invalid("Stage 7 requires one selected verified Stage 6 repair bundle"))?;
    if repair.state != ModuleResearchRepairState::Verified {
        return Err(invalid("Stage 7 accepts only a verified Stage 6 repair bundle"));
    }
    Ok(repair)
}

fn verified_repair<'a>(
    state: &'a state::State,
    repair_bundle_id: &str,
) -> Result<&'a ModuleResearchRepairBundle, Error> {
    select_repair(state, Some(repair_bundle_id))
}

fn select_package_index(
    state: &state::State,
    selected: Option<&str>,
    required: ModuleResearchDisclosureState,
) -> Result<usize, Error> {
    let index = if let Some(selected) = selected {
        state.research_disclosure_packages.iter().position(|package| package.id == selected)
    } else {
        state.research_disclosure_packages.iter().rposition(|package| package.state == required)
    }
    .ok_or_else(|| invalid("the selected Stage 7 disclosure package does not exist"))?;
    if state.research_disclosure_packages[index].state != required {
        return Err(invalid(format!("Stage 7 operation requires package state `{required:?}`")));
    }
    Ok(index)
}

fn select_reviewed_package_index(
    state: &state::State,
    selected: Option<&str>,
) -> Result<usize, Error> {
    let index = if let Some(selected) = selected {
        state.research_disclosure_packages.iter().position(|package| package.id == selected)
    } else {
        state.research_disclosure_packages.iter().rposition(|package| {
            matches!(
                package.state,
                ModuleResearchDisclosureState::PackageReviewed
                    | ModuleResearchDisclosureState::Exported
            )
        })
    }
    .ok_or_else(|| invalid("no reviewed Stage 7 package is available to export"))?;
    if !matches!(
        state.research_disclosure_packages[index].state,
        ModuleResearchDisclosureState::PackageReviewed | ModuleResearchDisclosureState::Exported
    ) {
        return Err(invalid("Stage 7 export requires a reviewed private package"));
    }
    Ok(index)
}

fn template_identity() -> Result<ModuleResearchIdentity, Error> {
    identity(
        ModuleResearchIdentityKind::Template,
        TEMPLATE_VERSION.into(),
        &json!({
            "version": TEMPLATE_VERSION,
            "projections": ["advisory-json", "advisory-markdown", "vendor-email", "github-private-advisory", "bug-bounty-psirt", "cna-cve-intake", "acknowledgement-follow-up", "fix-verification", "coordinated-publication"],
            "delivery": false
        }),
    )
}

fn identity(
    kind: ModuleResearchIdentityKind,
    value: String,
    material: &impl Serialize,
) -> Result<ModuleResearchIdentity, Error> {
    let bytes = serde_json::to_vec(material)?;
    Ok(ModuleResearchIdentity {
        schema: MODULE_RESEARCH_CONTRACT_VERSION,
        kind,
        value,
        digest: digest(&bytes),
    })
}

fn byte_identity(
    kind: ModuleResearchIdentityKind,
    value: String,
    bytes: &[u8],
) -> ModuleResearchIdentity {
    ModuleResearchIdentity {
        schema: MODULE_RESEARCH_CONTRACT_VERSION,
        kind,
        value,
        digest: digest(bytes),
    }
}

fn extract_mailto(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let start = lower.find("mailto:")? + "mailto:".len();
    let tail = &text[start..];
    let end = tail
        .find(|character: char| {
            character.is_whitespace()
                || matches!(character, '"' | '\'' | '<' | '>' | ')' | ']' | '?' | '#')
        })
        .unwrap_or(tail.len());
    let candidate =
        tail[..end].trim_matches(|character: char| matches!(character, '.' | ',' | ';'));
    (candidate.len() <= 320
        && candidate.bytes().filter(|byte| *byte == b'@').count() == 1
        && !candidate.is_empty())
    .then(|| candidate.to_owned())
}

fn extract_security_url(text: &str) -> Option<String> {
    text.split_whitespace().find_map(|word| {
        let candidate = word.trim_matches(|character: char| {
            matches!(character, '(' | ')' | '[' | ']' | '<' | '>' | '"' | '\'' | ',' | ';' | '.')
        });
        let lower = candidate.to_ascii_lowercase();
        (candidate.len() <= 2_048
            && lower.starts_with("https://")
            && (lower.contains("security") || lower.contains("vulnerab")))
        .then(|| candidate.to_owned())
    })
}

fn contact_excerpt(
    text: &str,
    recipient: Option<&str>,
    policy_url: Option<&str>,
) -> Option<String> {
    text.lines().find_map(|line| {
        let line = line.trim();
        let contains_fact = recipient.is_some_and(|value| line.contains(value))
            || policy_url.is_some_and(|value| line.contains(value));
        (contains_fact
            && !line.is_empty()
            && line.len() <= 512
            && !line.chars().any(char::is_control))
        .then(|| line.to_owned())
    })
}

fn text_artifact(
    name: &'static str,
    media_type: &'static str,
    classification: ModuleResearchArtifactClassification,
    mut bytes: Vec<u8>,
) -> PreparedArtifact {
    if !bytes.ends_with(b"\n") {
        bytes.push(b'\n');
    }
    PreparedArtifact { name, media_type, classification, bytes }
}

fn json_bytes(value: &Value) -> Result<Vec<u8>, Error> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn contains_hex_digest(bytes: &[u8]) -> bool {
    bytes.windows(64).any(|window| {
        window.iter().all(|byte| byte.is_ascii_hexdigit())
            && window.iter().any(|byte| byte.is_ascii_digit())
    })
}

pub(crate) fn valid_package_id(value: &str) -> bool {
    value.strip_prefix("disclosure-").is_some_and(|digest| {
        digest.len() == 64
            && digest.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn package_contact_resolved(package: &ModuleResearchDisclosurePackage) -> bool {
    package
        .contact
        .as_ref()
        .is_some_and(|contact| contact.recipient.is_some() || contact.policy_url.is_some())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    #[cfg(unix)]
    let options = {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        options
    };
    #[cfg(not(unix))]
    let options = {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        options
    };
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn set_private_directory(path: &Path) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn private_mode(path: &Path) -> Result<bool, Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        Ok(fs::metadata(path)?.permissions().mode() & 0o077 == 0)
    }
    #[cfg(not(unix))]
    Ok(true)
}

fn cancel(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
) -> Result<ModuleAction, Error> {
    if !matches!(
        state.pending,
        Some(PendingRequest::DisclosureManifest { .. })
            | Some(PendingRequest::DisclosureContactRead { .. })
    ) {
        return Err(invalid("no retained Stage 7 contact lookup is available to cancel"));
    }
    state.pending = None;
    state::save(parameters, state)?;
    Ok(reply(
        "Stage 7 contact lookup was cancelled. No disclosure package or artifact was created, and no external operation ran.",
        profile,
        super::actions(state),
        None,
    ))
}

fn plan(state: &state::State) -> String {
    let verified = state
        .research_repair_bundles
        .iter()
        .filter(|repair| repair.state == ModuleResearchRepairState::Verified)
        .count();
    format!(
        "# Stage 7 private disclosure plan\n\n- Verified Stage 6 repair bundles: {verified}\n- Existing Stage 7 packages: {}\n- Template: `{TEMPLATE_VERSION}`\n- Contact sources: `SECURITY.md`, `.github/SECURITY.md`, `docs/SECURITY.md`\n- Maximum contact bytes: {MAXIMUM_CONTACT_BYTES}\n- Output: owner-only local artifacts\n- Delivery adapters or operations: none\n\n`disclosure-start [REPAIR_BUNDLE_ID]` scans only the immutable scoped-source manifest for a supported SECURITY.md path. Missing or unusable contact data remains an unresolved placeholder. Review and export are separate deterministic local actions.",
        state.research_disclosure_packages.len()
    )
}

fn history(state: &state::State) -> String {
    let mut text = String::from("# Stage 7 private disclosure history\n\n");
    if state.research_disclosure_packages.is_empty() {
        text.push_str("No private disclosure package has been declared.\n");
        return text;
    }
    for package in &state.research_disclosure_packages {
        text.push_str(&format!("{}\n\n", render(package)));
    }
    text
}

fn render(package: &ModuleResearchDisclosurePackage) -> String {
    format!(
        "## Disclosure `{}`\n\n- State: `{:?}`\n- Source snapshot: `{}`\n- Chain / PoC / repair: `{}` / `{}` / `{}`\n- Advisory digest: `{}`\n- Contact: {}\n- Timeline entries: {}\n- Owner-only artifacts: {}\n- Unresolved placeholders: {}\n- Delivery performed: false",
        package.id,
        package.state,
        package.source_snapshot,
        package.chain_id,
        package.poc_bundle_id.as_deref().unwrap_or("none"),
        package.repair_bundle_id,
        package.advisory_digest,
        if package_contact_resolved(package) {
            "verified scoped-source fact"
        } else {
            "unresolved"
        },
        package.timeline.len(),
        package.artifacts.len(),
        package.placeholders.len(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contact_extractors_keep_only_bounded_explicit_facts() {
        let policy = "Report privately to mailto:security@example.test. Policy: https://example.test/security/report.";
        assert_eq!(extract_mailto(policy).as_deref(), Some("security@example.test"));
        assert_eq!(
            extract_security_url(policy).as_deref(),
            Some("https://example.test/security/report")
        );
        assert_eq!(
            contact_excerpt(
                policy,
                Some("security@example.test"),
                Some("https://example.test/security/report")
            )
            .as_deref(),
            Some(policy)
        );
        assert_eq!(extract_mailto("security@example.test"), None);
        assert_eq!(extract_security_url("http://example.test/security"), None);
    }

    #[test]
    fn package_identity_cannot_become_a_path() {
        assert!(valid_package_id(&format!("disclosure-{}", "a".repeat(64))));
        assert!(!valid_package_id("../disclosure-escape"));
        assert!(!valid_package_id(&format!("disclosure-{}", "A".repeat(64))));
        assert!(!valid_package_id(&format!("disclosure-{}", "a".repeat(63))));
    }

    #[test]
    fn required_package_artifacts_are_unique() {
        assert_eq!(
            DISCLOSURE_ARTIFACT_NAMES.into_iter().collect::<BTreeSet<_>>().len(),
            DISCLOSURE_ARTIFACT_NAMES.len()
        );
    }
}
