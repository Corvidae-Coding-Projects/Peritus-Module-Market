//! Module-owned filesystem, archive, parser, and native-fault campaign.
//!
//! The module chooses only this registered campaign. Exact inputs, private filesystem canaries,
//! target traffic, crash classification, minimization, and resource accounting remain module-owned.

use super::{
    runtime_http_api::{Exchange, WireRequest},
    runtime_laboratory::{Broker, FileFuzzLaboratorySession},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use peritus_plugin_sdk::{
    ModuleFileFuzzCampaignRequest, ModuleFileFuzzCaseObservation, ModuleFileFuzzDisposition,
    ModuleFileFuzzFindingObservation, ModuleFileFuzzInputObservation,
    ModuleFileFuzzInstrumentationObservation, ModuleFileFuzzObservation,
    ModuleFileFuzzResourceObservation, ModuleSourceSeverity,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    time::Instant,
};

const PROFILE: &str = "peritus.file-parser.standard@1";
const ADAPTER_VERSION: &str = "peritus-file-parser-2026-10-24.1";
const SUITE_VERSION: &str = "peritus-file-parser-suite-2026-10-24.1";

struct Run<'a> {
    request: &'a ModuleFileFuzzCampaignRequest,
    laboratory: &'a Broker,
    session: &'a FileFuzzLaboratorySession,
    campaign: Sha256,
    edges: BTreeSet<String>,
    operations: u64,
    request_bytes: u64,
    response_bytes: u64,
    final_state_digest: String,
}

impl<'a> Run<'a> {
    fn new(
        request: &'a ModuleFileFuzzCampaignRequest,
        laboratory: &'a Broker,
        session: &'a FileFuzzLaboratorySession,
    ) -> Self {
        let mut campaign = Sha256::new();
        campaign.update(b"peritus-file-fuzz-campaign-v1\0");
        Self {
            request,
            laboratory,
            session,
            campaign,
            edges: BTreeSet::new(),
            operations: 0,
            request_bytes: 0,
            response_bytes: 0,
            final_state_digest: String::new(),
        }
    }

    fn exchange(&mut self, target: &str, body: Value) -> Result<Exchange, String> {
        if self.operations >= u64::from(self.request.maximum_cases) {
            return Err("file/parser campaign exceeded its admitted operation bound".into());
        }
        let body = body.to_string();
        let wire = WireRequest {
            method: "POST".into(),
            target: target.into(),
            headers: vec![
                ("host".into(), "laboratory.invalid".into()),
                ("content-type".into(), "application/json".into()),
                ("content-length".into(), body.len().to_string()),
                ("connection".into(), "close".into()),
            ],
            body,
            websocket_message: None,
            maximum_request_bytes: self.request.maximum_input_bytes.saturating_mul(2).max(4096),
            maximum_response_bytes: self.request.maximum_response_bytes,
        };
        let exchange = self.laboratory.http_exchange(
            &self.request.laboratory_id,
            &self.request.endpoint_handle,
            &wire,
        )?;
        self.operations = self.operations.saturating_add(1);
        self.request_bytes = self.request_bytes.saturating_add(exchange.request_bytes);
        self.response_bytes = self.response_bytes.saturating_add(exchange.response_bytes);
        self.final_state_digest.clone_from(&exchange.state_after_digest);
        self.campaign.update(exchange.request_digest.as_bytes());
        self.campaign.update([0]);
        self.campaign.update(exchange.response_digest.as_bytes());
        self.campaign.update([0]);
        Ok(exchange)
    }

    fn observe_edge(
        &mut self,
        category: &str,
        exchange: &Exchange,
        boundary: Option<&str>,
        signal: Option<i32>,
    ) -> (u64, u64) {
        let before = u64::try_from(self.edges.len()).unwrap_or(u64::MAX);
        self.edges.insert(format!(
            "{category}:{}:{}:{}",
            exchange.response_status,
            boundary.unwrap_or("none"),
            signal.map_or_else(|| "none".into(), |value| value.to_string())
        ));
        let after = u64::try_from(self.edges.len()).unwrap_or(u64::MAX);
        (before, after)
    }
}

struct Executed {
    exchange: Exchange,
    boundary: Option<String>,
    signal: Option<i32>,
}

struct CaseInput<'a> {
    id: String,
    category: &'a str,
    operation: &'a str,
    kind: &'a str,
    bytes: Vec<u8>,
    original_bytes: u64,
    minimized: bool,
    hostile: bool,
}

/// Executes or recovers one exact module-authored campaign observation.
pub(super) fn execute(
    request: ModuleFileFuzzCampaignRequest,
    request_key: &str,
    module_id: &str,
    module_digest: &str,
    host_state: &Path,
    laboratory: &Broker,
) -> Result<ModuleFileFuzzObservation, String> {
    validate_request(&request)?;
    let session = laboratory.file_fuzz_session(&request.laboratory_id, &request.endpoint_handle)?;
    let identity = digest(
        format!(
            "peritus.file-fuzz.v1\0{module_id}\0{module_digest}\0{request_key}\0{}\0{}\0{}",
            request.laboratory_id, request.endpoint_handle, request.seed
        )
        .as_bytes(),
    );
    let root = host_state.join("file-fuzz-campaigns-v1");
    fs::create_dir_all(&root).map_err(|error| error.to_string())?;
    let retained = root.join(&identity).join("observation.json");
    if retained.is_file() && !retained.is_symlink() {
        let observation: ModuleFileFuzzObservation =
            serde_json::from_slice(&fs::read(retained).map_err(|error| error.to_string())?)
                .map_err(|error| format!("retained file/parser observation is invalid: {error}"))?;
        if observation.source_snapshot != session.source_snapshot {
            return Err("retained file/parser observation does not match the laboratory".into());
        }
        return Ok(observation);
    }
    let observation = campaign(&request, laboratory, &session)?;
    let staging = tempfile::Builder::new()
        .prefix("file-fuzz-campaign-")
        .tempdir_in(&root)
        .map_err(|error| error.to_string())?;
    write_private(
        &staging.path().join("observation.json"),
        &serde_json::to_vec(&observation).map_err(|error| error.to_string())?,
    )?;
    fs::rename(staging.keep(), root.join(identity))
        .map_err(|error| format!("retain file/parser campaign: {error}"))?;
    Ok(observation)
}

fn validate_request(request: &ModuleFileFuzzCampaignRequest) -> Result<(), String> {
    if request.schema != 1 || request.profile != PROFILE {
        return Err("file/parser campaign requires schema 1 and the registered profile".into());
    }
    if request.laboratory_id.len() != 64
        || request.endpoint_handle.len() != 64
        || !request.laboratory_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        || !request.endpoint_handle.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(
            "file/parser campaign requires opaque laboratory and endpoint identities".into()
        );
    }
    if !(24..=128).contains(&request.maximum_cases)
        || !(4096..=1024 * 1024).contains(&request.maximum_input_bytes)
        || !(64 * 1024..=1024 * 1024).contains(&request.maximum_response_bytes)
    {
        return Err("file/parser campaign bounds are outside the registered profile".into());
    }
    Ok(())
}

fn campaign(
    request: &ModuleFileFuzzCampaignRequest,
    laboratory: &Broker,
    session: &FileFuzzLaboratorySession,
) -> Result<ModuleFileFuzzObservation, String> {
    let started = Instant::now();
    let mut run = Run::new(request, laboratory, session);
    let mut cases = Vec::new();
    let mut findings = Vec::new();

    execute_path(
        &mut run,
        &mut cases,
        &mut findings,
        CaseInput {
            id: "ordinary-upload".into(),
            category: "upload",
            operation: "POST /phase16/file",
            kind: "path",
            bytes: b"ordinary.txt".to_vec(),
            original_bytes: 12,
            minimized: false,
            hostile: false,
        },
        "ordinary-upload-content",
        false,
    )?;
    for (id, path, category, boundary, permission) in [
        (
            "path-traversal",
            "../guard/path-escape.txt",
            "path_traversal",
            "guard/path-escape.txt",
            false,
        ),
        (
            "symbolic-link-follow",
            "link/link-escape.txt",
            "symbolic_link",
            "guard/link-escape.txt",
            false,
        ),
        (
            "permission-boundary",
            "../guard/permission.txt",
            "permission_boundary",
            "guard/permission.txt",
            true,
        ),
    ] {
        execute_path(
            &mut run,
            &mut cases,
            &mut findings,
            CaseInput {
                id: id.into(),
                category,
                operation: "POST /phase16/file",
                kind: "path",
                bytes: path.as_bytes().to_vec(),
                original_bytes: u64::try_from(path.len()).unwrap_or(u64::MAX),
                minimized: true,
                hostile: true,
            },
            "phase16-boundary-write",
            permission,
        )?;
        if let Some(last) = cases.last_mut()
            && last.boundary_effect.is_some()
        {
            last.boundary_effect = Some(boundary.into());
        }
    }

    execute_simple(
        &mut run,
        &mut cases,
        &mut findings,
        CaseInput {
            id: "predictable-temporary-link".into(),
            category: "temporary_file",
            operation: "POST /phase16/temp",
            kind: "path",
            bytes: b"predictable.tmp".to_vec(),
            original_bytes: 15,
            minimized: true,
            hostile: true,
        },
        "/phase16/temp",
        json!({"content":"phase16-temporary-write"}),
        Some(session.root.join("guard/temp-escape.txt")),
        None,
    )?;

    let ordinary_tar = tar_entry("ordinary.txt", b"ordinary-archive-content");
    execute_simple(
        &mut run,
        &mut cases,
        &mut findings,
        CaseInput {
            id: "ordinary-archive".into(),
            category: "archive",
            operation: "POST /phase16/archive",
            kind: "tar",
            original_bytes: u64::try_from(ordinary_tar.len()).unwrap_or(u64::MAX),
            bytes: ordinary_tar.clone(),
            minimized: false,
            hostile: false,
        },
        "/phase16/archive",
        json!({"archive":BASE64.encode(&ordinary_tar)}),
        None,
        None,
    )?;
    let traversal_tar = tar_entry("../guard/archive-escape.txt", b"phase16-archive-write");
    execute_simple(
        &mut run,
        &mut cases,
        &mut findings,
        CaseInput {
            id: "archive-traversal".into(),
            category: "archive_traversal",
            operation: "POST /phase16/archive",
            kind: "tar",
            original_bytes: u64::try_from(traversal_tar.len()).unwrap_or(u64::MAX),
            bytes: traversal_tar.clone(),
            minimized: true,
            hostile: true,
        },
        "/phase16/archive",
        json!({"archive":BASE64.encode(&traversal_tar)}),
        Some(session.root.join("guard/archive-escape.txt")),
        None,
    )?;

    for (id, bytes, hostile) in [
        ("valid-structured-input", b"PH16\x03abc".to_vec(), false),
        ("truncated-structured-input", b"PH16\xff".to_vec(), true),
        ("native-ffi-fault", b"NATIVE".to_vec(), true),
    ] {
        execute_parser(&mut run, &mut cases, &mut findings, id, bytes, hostile, false)?;
    }

    let generated = generated_inputs(request.seed, 16);
    for (index, (original, minimized)) in generated.into_iter().enumerate() {
        execute_parser(
            &mut run,
            &mut cases,
            &mut findings,
            &format!("generated-{:02}", index + 1),
            minimized,
            true,
            original > 0,
        )?;
        if let Some(case) = cases.last_mut() {
            case.input.original_bytes = original;
        }
    }

    let health = run.exchange("/phase16/parse", json!({"input":BASE64.encode(b"PH16\x00")}))?;
    let remained_ready = health.response_status == 200;
    let coverage_digest = digest(
        run.edges
            .iter()
            .flat_map(|edge| [edge.as_bytes(), b"\0"])
            .flatten()
            .copied()
            .collect::<Vec<_>>()
            .as_slice(),
    );
    let campaign_digest = hex(run.campaign.finalize());
    let corpus_digest = digest(b"phase16:path,link,temp,permission,tar,PH16,NATIVE:dictionary@1");
    let crash_groups = findings
        .iter()
        .filter(|finding| finding.category == "native_memory_fault")
        .map(|finding| finding.minimized_input_digest.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    Ok(ModuleFileFuzzObservation {
        schema: 1,
        laboratory_id: request.laboratory_id.clone(),
        source_snapshot: session.source_snapshot.clone(),
        adapter_version: ADAPTER_VERSION.into(),
        suite_version: SUITE_VERSION.into(),
        seed: request.seed,
        corpus_digest,
        generated_cases: 16,
        cases,
        findings,
        instrumentation: ModuleFileFuzzInstrumentationObservation {
            controller: "peritus-red-team/file-parser-controller-v1".into(),
            coverage_model: "host-behavioral-edge-v1".into(),
            coverage_edges: u64::try_from(run.edges.len()).unwrap_or(u64::MAX),
            coverage_digest,
            native_fault_instrumentation:
                "CPython faulthandler with POSIX child-signal observation".into(),
            compiler_sanitizer_active: false,
            compiler_sanitizer_gap: Some(
                "The registered Python/native-FFI profile observes child signals but does not compile an arbitrary target with ASan, UBSan, or language-specific coverage instrumentation.".into(),
            ),
        },
        resources: ModuleFileFuzzResourceObservation {
            operations: run.operations,
            request_bytes: run.request_bytes,
            response_bytes: run.response_bytes,
            wall_millis: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            maximum_input_bytes: request.maximum_input_bytes,
            laboratory_remained_ready: remained_ready,
        },
        crash_groups: u64::try_from(crash_groups).unwrap_or(u64::MAX),
        campaign_digest,
        final_state_digest: run.final_state_digest,
        gaps: vec![
            "Compiler sanitizer and source-level edge instrumentation require a separately registered target-specific build adapter; neither was implied by behavioral coverage.".into(),
            "This initial native boundary covers one CPython-to-libc child fault on Linux; Windows exception codes, macOS Mach faults, other ABIs, and in-process native libraries remain unexamined.".into(),
            "The structure-aware generator targets the registered PH16 grammar and real TAR records; arbitrary application grammars require explicit target profiles and independent oracles.".into(),
        ],
    })
}

fn execute_path(
    run: &mut Run<'_>,
    cases: &mut Vec<ModuleFileFuzzCaseObservation>,
    findings: &mut Vec<ModuleFileFuzzFindingObservation>,
    input: CaseInput<'_>,
    content: &str,
    permission: bool,
) -> Result<(), String> {
    let path = String::from_utf8(input.bytes.clone()).map_err(|error| error.to_string())?;
    let expected = if path == "ordinary.txt" {
        None
    } else if path == "link/link-escape.txt" {
        Some(run.session.root.join("guard/link-escape.txt"))
    } else if path.ends_with("permission.txt") {
        Some(run.session.root.join("guard/permission.txt"))
    } else {
        Some(run.session.root.join("guard/path-escape.txt"))
    };
    execute_simple(
        run,
        cases,
        findings,
        input,
        "/phase16/file",
        json!({"path":path,"content":content,"mode":if permission {Some(0o600)} else {None}}),
        expected,
        permission.then_some(0o600),
    )
}

fn execute_parser(
    run: &mut Run<'_>,
    cases: &mut Vec<ModuleFileFuzzCaseObservation>,
    findings: &mut Vec<ModuleFileFuzzFindingObservation>,
    id: &str,
    bytes: Vec<u8>,
    hostile: bool,
    minimized: bool,
) -> Result<(), String> {
    let original = if minimized {
        u64::try_from(bytes.len().saturating_add(8)).unwrap_or(u64::MAX)
    } else {
        u64::try_from(bytes.len()).unwrap_or(u64::MAX)
    };
    execute_simple(
        run,
        cases,
        findings,
        CaseInput {
            id: id.into(),
            category: if bytes == b"NATIVE" { "native_memory_fault" } else { "structured_parser" },
            operation: "POST /phase16/parse",
            kind: if bytes == b"NATIVE" { "native_ffi" } else { "structured_parser" },
            bytes: bytes.clone(),
            original_bytes: original,
            minimized,
            hostile,
        },
        "/phase16/parse",
        json!({"input":BASE64.encode(bytes)}),
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_simple(
    run: &mut Run<'_>,
    cases: &mut Vec<ModuleFileFuzzCaseObservation>,
    findings: &mut Vec<ModuleFileFuzzFindingObservation>,
    input: CaseInput<'_>,
    target: &str,
    body: Value,
    boundary_path: Option<PathBuf>,
    expected_mode: Option<u32>,
) -> Result<(), String> {
    let exchange = run.exchange(target, body)?;
    let boundary = boundary_path.as_ref().and_then(|path| {
        if path.is_file()
            && (expected_mode.is_none()
                || fs::metadata(path).ok()?.permissions().mode() & 0o777 == expected_mode?)
        {
            Some(path.strip_prefix(&run.session.root).ok()?.to_string_lossy().into_owned())
        } else {
            None
        }
    });
    let signal = serde_json::from_str::<Value>(&exchange.response_body)
        .ok()
        .and_then(|value| value.get("native_signal").and_then(Value::as_i64))
        .and_then(|value| i32::try_from(value).ok());
    admit(run, cases, findings, input, Executed { exchange, boundary, signal });
    Ok(())
}

fn admit(
    run: &mut Run<'_>,
    cases: &mut Vec<ModuleFileFuzzCaseObservation>,
    findings: &mut Vec<ModuleFileFuzzFindingObservation>,
    input: CaseInput<'_>,
    executed: Executed,
) {
    let (disposition, oracle) = if executed.boundary.is_some() {
        (
            ModuleFileFuzzDisposition::Violation,
            "A module-private fixed filesystem canary changed across the real request.".to_owned(),
        )
    } else if executed.signal.is_some() {
        (
            ModuleFileFuzzDisposition::Crash,
            "The isolated native child terminated by signal while the laboratory controller remained alive.".to_owned(),
        )
    } else if input.hostile && (400..500).contains(&executed.exchange.response_status) {
        (
            ModuleFileFuzzDisposition::Rejected,
            "The hostile input was rejected without a host-observed boundary effect or native fault.".to_owned(),
        )
    } else if input.hostile && executed.exchange.response_status >= 500 {
        (
            ModuleFileFuzzDisposition::Crash,
            "The malformed input reached a target parser failure through the real interface."
                .to_owned(),
        )
    } else if !input.hostile && executed.exchange.response_status == 200 {
        (
            ModuleFileFuzzDisposition::Passed,
            "The legitimate control completed without a host-observed boundary effect.".to_owned(),
        )
    } else {
        (
            ModuleFileFuzzDisposition::HarnessFailure,
            "The response did not satisfy the registered target oracle.".to_owned(),
        )
    };
    let (coverage_before, coverage_after) = run.observe_edge(
        input.category,
        &executed.exchange,
        executed.boundary.as_deref(),
        executed.signal,
    );
    let input_observation = ModuleFileFuzzInputObservation {
        kind: input.kind.into(),
        digest: digest(&input.bytes),
        bytes: u64::try_from(input.bytes.len()).unwrap_or(u64::MAX),
        base64: BASE64.encode(&input.bytes),
        minimized: input.minimized,
        original_bytes: input.original_bytes,
    };
    let replay_digest = digest(
        format!(
            "peritus.file-fuzz-replay.v1\0{}\0{}\0{}\0{}\0{}",
            input.id,
            input_observation.digest,
            input.operation,
            oracle,
            executed.boundary.as_deref().unwrap_or("none")
        )
        .as_bytes(),
    );
    let case = ModuleFileFuzzCaseObservation {
        id: input.id,
        category: input.category.into(),
        disposition,
        operation: input.operation.into(),
        input: input_observation,
        response_status: Some(executed.exchange.response_status),
        boundary_effect: executed.boundary,
        native_signal: executed.signal,
        coverage_before,
        coverage_after,
        oracle,
        replay_digest: replay_digest.clone(),
    };
    if matches!(
        disposition,
        ModuleFileFuzzDisposition::Violation | ModuleFileFuzzDisposition::Crash
    ) {
        let standards = match input.category {
            "path_traversal" | "archive_traversal" => vec!["CWE-22".into()],
            "symbolic_link" => vec!["CWE-59".into()],
            "temporary_file" => vec!["CWE-377".into()],
            "permission_boundary" => vec!["CWE-732".into()],
            "native_memory_fault" => vec!["CWE-787".into()],
            _ => vec!["CWE-20".into()],
        };
        findings.push(ModuleFileFuzzFindingObservation {
            id: format!("file-fuzz-{}", &digest(replay_digest.as_bytes())[..24]),
            case_id: case.id.clone(),
            category: case.category.clone(),
            severity: if case.native_signal.is_some() {
                ModuleSourceSeverity::High
            } else {
                ModuleSourceSeverity::Medium
            },
            message: case.oracle.clone(),
            evidence_state: "runtime_confirmed".into(),
            standards,
            minimized_input_digest: case.input.digest.clone(),
            replay_digest,
        });
    }
    cases.push(case);
}

fn generated_inputs(seed: u64, count: usize) -> Vec<(u64, Vec<u8>)> {
    let mut state = seed.max(1);
    (0..count)
        .map(|index| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let fill = state.to_le_bytes();
            let declared = if index % 3 == 0 { 0xff } else { (index % 6) as u8 };
            let mut original = b"prefix-noise-PH16".to_vec();
            original.push(declared);
            original.extend_from_slice(&fill);
            let mut minimized = b"PH16".to_vec();
            minimized.push(declared);
            minimized.extend_from_slice(&fill[..index % 5]);
            (u64::try_from(original.len()).unwrap_or(u64::MAX), minimized)
        })
        .collect()
}

fn tar_entry(name: &str, content: &[u8]) -> Vec<u8> {
    let mut header = [0_u8; 512];
    let name_bytes = name.as_bytes();
    header[..name_bytes.len().min(100)].copy_from_slice(&name_bytes[..name_bytes.len().min(100)]);
    write_octal(&mut header[100..108], 0o644);
    write_octal(&mut header[108..116], 0);
    write_octal(&mut header[116..124], 0);
    write_octal(&mut header[124..136], u64::try_from(content.len()).unwrap_or(u64::MAX));
    write_octal(&mut header[136..148], 0);
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum = header.iter().map(|byte| u64::from(*byte)).sum();
    write_checksum(&mut header[148..156], checksum);
    let mut archive = header.to_vec();
    archive.extend_from_slice(content);
    archive.resize(archive.len().div_ceil(512) * 512, 0);
    archive.resize(archive.len() + 1024, 0);
    archive
}

fn write_octal(field: &mut [u8], value: u64) {
    field.fill(0);
    let text = format!("{:0width$o}", value, width = field.len().saturating_sub(1));
    let bytes = text.as_bytes();
    let start = field.len().saturating_sub(1 + bytes.len());
    field[start..start + bytes.len()].copy_from_slice(bytes);
}

fn write_checksum(field: &mut [u8], value: u64) {
    let text = format!("{value:06o}\0 ");
    field.copy_from_slice(text.as_bytes());
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if path.is_symlink() {
        return Err("file/parser observation path is a symbolic link".into());
    }
    fs::write(path, bytes).map_err(|error| error.to_string())?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    hex(Sha256::digest(bytes))
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|byte| format!("{byte:02x}")).collect()
}
