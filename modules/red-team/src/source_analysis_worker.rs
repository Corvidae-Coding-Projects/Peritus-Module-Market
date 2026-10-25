//! Red Team-owned deterministic analysis over a host-isolated disposable source copy.
//!
//! This implementation emits source leads only. It never upgrades a pattern, dependency advisory,
//! or configuration observation into runtime proof.

use peritus_plugin_sdk::{
    ModuleSourceAnalysisLimits, ModuleSourceAnalysisObservation, ModuleSourceAnalysisTool,
    ModuleSourceComponentObservation, ModuleSourceFindingObservation,
    ModuleSourceLanguageObservation, ModuleSourceManifestObservation,
    ModuleSourceRawFindingObservation, ModuleSourceReachability, ModuleSourceSeverity,
};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

struct AnalysisSourceFile {
    path: String,
    digest: String,
    bytes: Vec<u8>,
}

struct AnalysisSourceSnapshot {
    snapshot_digest: String,
    files: Vec<AnalysisSourceFile>,
    skipped_oversized_files: u64,
    truncated: bool,
}

const ANALYZER_SET: &str = "peritus-static-2026-10-24.1";
const RULE_SET: &str = "peritus-source-rules-2026-10-24.1";
const ADVISORY_SET: &str = "peritus-advisories-2026-10-24.1";

pub(super) fn scan_disposable_source(
    snapshot_digest: String,
    limits: &ModuleSourceAnalysisLimits,
) -> Result<ModuleSourceAnalysisObservation, String> {
    if limits.maximum_files == 0
        || limits.maximum_files > 100_000
        || limits.maximum_file_bytes == 0
        || limits.maximum_file_bytes > 64 * 1024 * 1024
        || limits.maximum_total_bytes == 0
        || limits.maximum_total_bytes > 2 * 1024 * 1024 * 1024
    {
        return Err("source-analysis limits are outside the module worker bounds".into());
    }
    let root = std::env::current_dir().map_err(|error| error.to_string())?;
    let mut paths = Vec::new();
    collect_paths(&root, &root, &mut paths)?;
    paths.sort();
    let mut files = Vec::new();
    let mut skipped_oversized_files = 0_u64;
    let mut total = 0_u64;
    let mut truncated = false;
    for path in paths {
        if u64::try_from(files.len()).unwrap_or(u64::MAX) >= u64::from(limits.maximum_files) {
            truncated = true;
            break;
        }
        let metadata = fs::metadata(&path).map_err(|error| error.to_string())?;
        if metadata.len() > limits.maximum_file_bytes {
            skipped_oversized_files = skipped_oversized_files.saturating_add(1);
            continue;
        }
        if total.saturating_add(metadata.len()) > limits.maximum_total_bytes {
            truncated = true;
            break;
        }
        let bytes = fs::read(&path).map_err(|error| error.to_string())?;
        total = total.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        let relative = path
            .strip_prefix(&root)
            .map_err(|_| "source path escaped the disposable worker root")?
            .to_string_lossy()
            .replace('\\', "/");
        files.push(AnalysisSourceFile { path: relative, digest: digest(&bytes), bytes });
    }
    Ok(analyze(AnalysisSourceSnapshot {
        snapshot_digest,
        files,
        skipped_oversized_files,
        truncated,
    }))
}

fn collect_paths(root: &Path, directory: &Path, paths: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(directory).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|error| error.to_string())?;
        if file_type.is_symlink() {
            return Err("disposable source contains a symbolic link".into());
        }
        if file_type.is_dir() {
            let relative = path.strip_prefix(root).map_err(|_| "source directory escaped root")?;
            if matches!(relative.to_str(), Some(".git" | ".peritus" | ".crosslink")) {
                continue;
            }
            collect_paths(root, &path, paths)?;
        } else if file_type.is_file() {
            paths.push(path);
        } else {
            return Err("disposable source contains an unsupported special file".into());
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Rule {
    id: &'static str,
    category: &'static str,
    languages: &'static [&'static str],
    needle: &'static str,
    message: &'static str,
    severity: ModuleSourceSeverity,
    standards: &'static [&'static str],
}

const RULES: &[Rule] = &[
    Rule {
        id: "rust.command-shell",
        category: "input_interpretation_and_injection",
        languages: &["rust"],
        needle: "Command::new(\"sh\")",
        message: "Rust launches a shell; trace whether untrusted data reaches the command string.",
        severity: ModuleSourceSeverity::High,
        standards: &["CWE-78"],
    },
    Rule {
        id: "rust.unsafe-block",
        category: "memory_integers_and_unsafe_interfaces",
        languages: &["rust"],
        needle: "unsafe {",
        message: "Rust unsafe block requires invariant and boundary review.",
        severity: ModuleSourceSeverity::Medium,
        standards: &["CWE-119"],
    },
    Rule {
        id: "c.strcpy",
        category: "memory_integers_and_unsafe_interfaces",
        languages: &["c_cpp"],
        needle: "strcpy(",
        message: "Unbounded C string copy requires destination-size review.",
        severity: ModuleSourceSeverity::High,
        standards: &["CWE-120"],
    },
    Rule {
        id: "c.sprintf",
        category: "memory_integers_and_unsafe_interfaces",
        languages: &["c_cpp"],
        needle: "sprintf(",
        message: "Unbounded formatted write requires destination-size review.",
        severity: ModuleSourceSeverity::High,
        standards: &["CWE-120"],
    },
    Rule {
        id: "c.system",
        category: "input_interpretation_and_injection",
        languages: &["c_cpp"],
        needle: "system(",
        message: "C system call invokes a command interpreter; trace attacker control.",
        severity: ModuleSourceSeverity::High,
        standards: &["CWE-78"],
    },
    Rule {
        id: "js.eval",
        category: "input_interpretation_and_injection",
        languages: &["javascript_typescript"],
        needle: "eval(",
        message: "Dynamic JavaScript evaluation requires an untrusted-input trace.",
        severity: ModuleSourceSeverity::High,
        standards: &["CWE-95"],
    },
    Rule {
        id: "js.inner-html",
        category: "browser_and_client_trust",
        languages: &["javascript_typescript"],
        needle: ".innerHTML",
        message: "HTML sink requires a provenance and encoding review.",
        severity: ModuleSourceSeverity::High,
        standards: &["CWE-79"],
    },
    Rule {
        id: "js.child-process-exec",
        category: "input_interpretation_and_injection",
        languages: &["javascript_typescript"],
        needle: ".exec(",
        message: "Child-process shell execution requires an untrusted-input trace.",
        severity: ModuleSourceSeverity::High,
        standards: &["CWE-78"],
    },
    Rule {
        id: "python.eval",
        category: "input_interpretation_and_injection",
        languages: &["python"],
        needle: "eval(",
        message: "Python evaluation requires an untrusted-input trace.",
        severity: ModuleSourceSeverity::High,
        standards: &["CWE-95"],
    },
    Rule {
        id: "python.exec",
        category: "input_interpretation_and_injection",
        languages: &["python"],
        needle: "exec(",
        message: "Python execution requires an untrusted-input trace.",
        severity: ModuleSourceSeverity::High,
        standards: &["CWE-95"],
    },
    Rule {
        id: "python.subprocess-shell",
        category: "input_interpretation_and_injection",
        languages: &["python"],
        needle: "shell=True",
        message: "Python subprocess enables shell interpretation; trace argument control.",
        severity: ModuleSourceSeverity::High,
        standards: &["CWE-78"],
    },
    Rule {
        id: "python.yaml-unsafe",
        category: "input_interpretation_and_injection",
        languages: &["python"],
        needle: "yaml.load(",
        message: "YAML object construction requires an explicit safe loader review.",
        severity: ModuleSourceSeverity::High,
        standards: &["CWE-502"],
    },
    Rule {
        id: "go.command-shell",
        category: "input_interpretation_and_injection",
        languages: &["go"],
        needle: "exec.Command(\"sh\", \"-c\"",
        message: "Go launches a shell; trace whether untrusted data reaches the command string.",
        severity: ModuleSourceSeverity::High,
        standards: &["CWE-78"],
    },
    Rule {
        id: "go.insecure-tls",
        category: "cryptography_and_key_lifecycle",
        languages: &["go"],
        needle: "InsecureSkipVerify: true",
        message: "TLS certificate verification is disabled.",
        severity: ModuleSourceSeverity::High,
        standards: &["CWE-295"],
    },
    Rule {
        id: "java.runtime-exec",
        category: "input_interpretation_and_injection",
        languages: &["java"],
        needle: "Runtime.getRuntime().exec(",
        message: "Java runtime command execution requires an untrusted-input trace.",
        severity: ModuleSourceSeverity::High,
        standards: &["CWE-78"],
    },
    Rule {
        id: "java.sql-statement",
        category: "input_interpretation_and_injection",
        languages: &["java"],
        needle: ".executeQuery(",
        message: "SQL statement execution requires a parameterization and data-flow review.",
        severity: ModuleSourceSeverity::Medium,
        standards: &["CWE-89"],
    },
];

#[derive(Clone)]
struct RawLead {
    category: String,
    rule_id: String,
    severity: ModuleSourceSeverity,
    path: String,
    line: Option<u64>,
    message: String,
    root_cause: String,
    evidence_digest: String,
    redacted: bool,
    reachability: ModuleSourceReachability,
    standards: Vec<String>,
}

fn analyze(snapshot: AnalysisSourceSnapshot) -> ModuleSourceAnalysisObservation {
    let mut language_counts = BTreeMap::<String, (u64, u64)>::new();
    let mut manifests = Vec::new();
    let mut components = Vec::new();
    let mut raw = Vec::new();
    let mut scanned_files = 0_u64;
    let mut scanned_bytes = 0_u64;
    let mut skipped_binary_files = 0_u64;
    let mut source_texts = Vec::<(String, String, bool)>::new();

    for file in &snapshot.files {
        let Some(text) = text(file) else {
            skipped_binary_files = skipped_binary_files.saturating_add(1);
            continue;
        };
        scanned_files = scanned_files.saturating_add(1);
        scanned_bytes = scanned_bytes.saturating_add(file.bytes.len() as u64);
        let language = language(&file.path, text);
        if let Some(language) = language {
            let count = language_counts.entry(language.into()).or_default();
            count.0 = count.0.saturating_add(1);
            count.1 = count.1.saturating_add(file.bytes.len() as u64);
            scan_rules(file, text, language, &mut raw);
            scan_flow(file, text, language, &mut raw);
        }
        scan_secrets(file, text, &mut raw);
        scan_configuration(file, text, &mut raw);
        if let Some(ecosystem) = manifest_ecosystem(&file.path) {
            manifests.push(ModuleSourceManifestObservation {
                path: file.path.clone(),
                ecosystem: ecosystem.into(),
                digest: file.digest.clone(),
                status: "parsed_bounded".into(),
            });
            components.extend(parse_components(file, text, ecosystem));
        }
        source_texts.push((file.path.clone(), text.to_ascii_lowercase(), test_path(&file.path)));
    }

    for component in &mut components {
        component.reachability = dependency_reachability(component, &source_texts);
        component.advisories = advisories(component);
        if !component.advisories.is_empty() {
            let message = format!(
                "Pinned advisory data matches {} {} (reachability: {:?}).",
                component.name,
                component.version.as_deref().unwrap_or("unresolved"),
                component.reachability
            );
            raw.push(RawLead {
                category: "dependencies_and_supply_chain".into(),
                rule_id: "dependency.pinned-advisory".into(),
                severity: ModuleSourceSeverity::High,
                path: component.source_path.clone(),
                line: None,
                root_cause: format!(
                    "dependency:{}:{}:{}",
                    component.ecosystem,
                    component.name.to_ascii_lowercase(),
                    component.version.as_deref().unwrap_or("unknown")
                ),
                evidence_digest: digest(message.as_bytes()),
                message,
                redacted: false,
                reachability: component.reachability,
                standards: vec!["CWE-1104".into()],
            });
        }
    }
    components.sort_by(|left, right| {
        (&left.ecosystem, &left.name, &left.version, &left.source_path).cmp(&(
            &right.ecosystem,
            &right.name,
            &right.version,
            &right.source_path,
        ))
    });
    components.dedup();
    manifests.sort_by(|left, right| left.path.cmp(&right.path));
    let raw_result_digest = raw_digest(&raw);
    let raw_findings = raw_observations(&raw);
    let findings = deduplicate(raw);
    let languages = language_counts
        .into_iter()
        .map(|(language, (files, bytes))| ModuleSourceLanguageObservation {
            support: match language.as_str() {
                "python" | "javascript_typescript" => "patterns_and_same_file_flow",
                _ => "patterns",
            }
            .into(),
            language,
            files,
            bytes,
        })
        .collect();
    ModuleSourceAnalysisObservation {
        schema: 1,
        source_snapshot: snapshot.snapshot_digest,
        analyzer_set_version: ANALYZER_SET.into(),
        rule_set_version: RULE_SET.into(),
        advisory_dataset_version: ADVISORY_SET.into(),
        tools: tools(),
        languages,
        manifests,
        components,
        raw_findings,
        findings,
        scanned_files,
        scanned_bytes,
        skipped_oversized_files: snapshot.skipped_oversized_files,
        skipped_binary_files,
        truncated: snapshot.truncated,
        raw_result_digest,
        gaps: vec![
            "Source leads are not runtime confirmation; later adapters must prove exploitability and effects.".into(),
            "Flow analysis is bounded to simple same-file assignments and sinks for Python and JavaScript/TypeScript.".into(),
            "The embedded advisory set is pinned and intentionally finite; absence is not dependency safety.".into(),
            "Macros, generated code, dynamic imports, build scripts and language-specific semantic graphs may require dedicated analyzers.".into(),
        ],
    }
}

fn raw_observations(raw: &[RawLead]) -> Vec<ModuleSourceRawFindingObservation> {
    raw.iter()
        .enumerate()
        .map(|(index, lead)| ModuleSourceRawFindingObservation {
            id: format!(
                "raw-{}",
                &digest(
                    format!(
                        "{}\0{}\0{}\0{}",
                        lead.rule_id,
                        lead.path,
                        lead.line.unwrap_or_default(),
                        index
                    )
                    .as_bytes()
                )[..24]
            ),
            tool_id: if lead.rule_id.starts_with("dependency.") {
                "peritus-manifest-sbom"
            } else if lead.rule_id.contains("secret") || lead.rule_id.contains("config") {
                "peritus-secret-config"
            } else if lead.rule_id.contains("same-file") {
                "peritus-flow-lite"
            } else {
                "peritus-patterns"
            }
            .into(),
            rule_id: lead.rule_id.clone(),
            path: lead.path.clone(),
            line: lead.line,
            message: lead.message.clone(),
            evidence_digest: lead.evidence_digest.clone(),
            redacted: lead.redacted,
            reachability: lead.reachability,
            evidence_state: "source_lead".into(),
        })
        .collect()
}

fn tools() -> Vec<ModuleSourceAnalysisTool> {
    vec![
        tool(
            "peritus-language-discovery",
            "language_manifest_discovery",
            &["rust", "c_cpp", "javascript_typescript", "python", "go", "java"],
        ),
        tool(
            "peritus-patterns",
            "syntax_pattern",
            &[
                "rust",
                "c_cpp",
                "javascript_typescript",
                "python",
                "go",
                "java",
                "container",
                "infrastructure",
            ],
        ),
        tool("peritus-flow-lite", "same_file_data_flow", &["javascript_typescript", "python"]),
        tool(
            "peritus-manifest-sbom",
            "dependency_sbom",
            &["cargo", "npm", "python", "go", "maven"],
        ),
        tool(
            "peritus-secret-config",
            "redacted_secret_configuration",
            &["text", "container", "kubernetes", "terraform"],
        ),
    ]
}

fn tool(id: &str, kind: &str, supports: &[&str]) -> ModuleSourceAnalysisTool {
    ModuleSourceAnalysisTool {
        id: id.into(),
        version: "1.0.0".into(),
        kind: kind.into(),
        supports: supports.iter().map(|value| (*value).into()).collect(),
    }
}

fn text(file: &AnalysisSourceFile) -> Option<&str> {
    if file.bytes.iter().take(8192).any(|byte| *byte == 0) {
        return None;
    }
    std::str::from_utf8(&file.bytes).ok()
}

fn language<'a>(path: &str, text: &'a str) -> Option<&'a str> {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".rs") {
        Some("rust")
    } else if [".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"].iter().any(|ext| lower.ends_with(ext)) {
        Some("c_cpp")
    } else if [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"].iter().any(|ext| lower.ends_with(ext))
    {
        Some("javascript_typescript")
    } else if lower.ends_with(".py") {
        Some("python")
    } else if lower.ends_with(".go") {
        Some("go")
    } else if lower.ends_with(".java") {
        Some("java")
    } else {
        let _ = text;
        None
    }
}

fn scan_rules(file: &AnalysisSourceFile, text: &str, language: &str, leads: &mut Vec<RawLead>) {
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if comment_only(trimmed, language) {
            continue;
        }
        for rule in RULES {
            if rule.languages.contains(&language) && line.contains(rule.needle) {
                leads.push(rule_lead(file, index, rule));
            }
        }
    }
}

fn rule_lead(file: &AnalysisSourceFile, index: usize, rule: &Rule) -> RawLead {
    let reachability = path_reachability(&file.path);
    RawLead {
        category: rule.category.into(),
        rule_id: rule.id.into(),
        severity: rule.severity,
        path: file.path.clone(),
        line: Some(index.saturating_add(1) as u64),
        message: rule.message.into(),
        root_cause: format!("{}:{}", rule.id, file.path),
        evidence_digest: digest(
            format!("{}\0{}\0{}\0{}", file.digest, index.saturating_add(1), rule.id, RULE_SET)
                .as_bytes(),
        ),
        redacted: false,
        reachability,
        standards: rule.standards.iter().map(|value| (*value).into()).collect(),
    }
}

fn scan_flow(file: &AnalysisSourceFile, text: &str, language: &str, leads: &mut Vec<RawLead>) {
    if !matches!(language, "python" | "javascript_typescript") {
        return;
    }
    let mut tainted = BTreeSet::new();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if comment_only(trimmed, language) {
            continue;
        }
        if let Some((left, right)) = line.split_once('=')
            && source_expression(right, language)
            && let Some(name) = identifier(left)
        {
            tainted.insert(name.to_owned());
        }
        let sink = if language == "python" {
            ["eval(", "exec(", "os.system(", "shell=True"].iter().any(|sink| line.contains(sink))
        } else {
            ["eval(", ".innerHTML", ".exec("].iter().any(|sink| line.contains(sink))
        };
        if sink {
            for name in &tainted {
                if line.contains(name) {
                    let rule_id = format!("{language}.same-file-source-to-sink");
                    leads.push(RawLead {
                        category: if language == "javascript_typescript" && line.contains("innerHTML") {
                            "browser_and_client_trust"
                        } else {
                            "input_interpretation_and_injection"
                        }
                        .into(),
                        rule_id: rule_id.clone(),
                        severity: ModuleSourceSeverity::High,
                        path: file.path.clone(),
                        line: Some(index.saturating_add(1) as u64),
                        message: "A simple same-file assignment connects an input source to an interpretation sink; runtime proof remains required.".into(),
                        root_cause: format!("{rule_id}:{}:{name}", file.path),
                        evidence_digest: digest(format!("{}\0{}\0{rule_id}\0{name}", file.digest, index.saturating_add(1)).as_bytes()),
                        redacted: false,
                        reachability: path_reachability(&file.path),
                        standards: vec!["CWE-20".into()],
                    });
                }
            }
        }
    }
}

fn source_expression(value: &str, language: &str) -> bool {
    if language == "python" {
        ["input(", "request.", "sys.argv", "os.environ"].iter().any(|source| value.contains(source))
    } else {
        ["location.", "document.", "req.", "request.", "process.argv"]
            .iter()
            .any(|source| value.contains(source))
    }
}

fn identifier(value: &str) -> Option<&str> {
    value
        .split_whitespace()
        .last()
        .map(|name| {
            name.trim_matches(|character: char| {
                !character.is_ascii_alphanumeric() && character != '_'
            })
        })
        .filter(|name| !name.is_empty())
}

fn scan_secrets(file: &AnalysisSourceFile, text: &str, leads: &mut Vec<RawLead>) {
    for (index, line) in text.lines().enumerate() {
        let lower = line.to_ascii_lowercase();
        let name = ["api_key", "apikey", "secret", "password", "access_token", "private_key"]
            .into_iter()
            .find(|name| lower.contains(name));
        let Some(name) = name else { continue };
        let Some((_, value)) = line.split_once('=').or_else(|| line.split_once(':')) else {
            continue;
        };
        let candidate =
            value.trim().trim_matches(|character| matches!(character, '\'' | '"' | ','));
        let lower_candidate = candidate.to_ascii_lowercase();
        if candidate.len() < 8
            || ["example", "placeholder", "changeme", "redacted", "test-only", "test_only"]
                .iter()
                .any(|marker| lower_candidate.contains(marker))
            || ["getenv", "env::", "std::env", "process.env", "${", "{{"]
                .iter()
                .any(|marker| lower_candidate.contains(marker))
        {
            continue;
        }
        let fingerprint = digest(candidate.as_bytes());
        leads.push(RawLead {
            category: "configuration_secrets_and_observability".into(),
            rule_id: "secret.literal-assignment".into(),
            severity: ModuleSourceSeverity::High,
            path: file.path.clone(),
            line: Some(index.saturating_add(1) as u64),
            message: format!(
                "Potential literal `{name}` was redacted ({} bytes; fingerprint `{:.16}`).",
                candidate.len(),
                fingerprint
            ),
            root_cause: format!("secret.literal-assignment:{}:{name}", file.path),
            evidence_digest: digest(
                format!("{}\0{}\0{}\0{}", file.digest, index.saturating_add(1), name, fingerprint)
                    .as_bytes(),
            ),
            redacted: true,
            reachability: path_reachability(&file.path),
            standards: vec!["CWE-798".into()],
        });
    }
}

fn scan_configuration(file: &AnalysisSourceFile, text: &str, leads: &mut Vec<RawLead>) {
    let lower_path = file.path.to_ascii_lowercase();
    let lower = text.to_ascii_lowercase();
    if lower_path.ends_with("dockerfile") || lower_path.rsplit('/').next() == Some("dockerfile") {
        if text.lines().any(|line| {
            let line = line.trim().to_ascii_lowercase();
            line.starts_with("from ") && line.contains(":latest")
        }) {
            config_lead(
                file,
                leads,
                "container.unpinned-latest",
                "Container base image uses the mutable `latest` tag.",
                ModuleSourceSeverity::Medium,
                "CWE-1104",
            );
        }
        if !text.lines().any(|line| line.trim().to_ascii_lowercase().starts_with("user ")) {
            config_lead(
                file,
                leads,
                "container.no-user",
                "Container definition has no explicit non-root USER instruction.",
                ModuleSourceSeverity::Medium,
                "CWE-250",
            );
        }
    }
    if lower_path.ends_with(".yaml") || lower_path.ends_with(".yml") {
        if lower.contains("privileged: true") {
            config_lead(
                file,
                leads,
                "container.privileged",
                "Container or workload enables privileged execution.",
                ModuleSourceSeverity::High,
                "CWE-250",
            );
        }
        if lower.contains("hostnetwork: true") {
            config_lead(
                file,
                leads,
                "kubernetes.host-network",
                "Kubernetes workload joins the host network namespace.",
                ModuleSourceSeverity::High,
                "CWE-668",
            );
        }
    }
    if lower_path.ends_with(".tf") && lower.contains("0.0.0.0/0") {
        config_lead(
            file,
            leads,
            "terraform.public-ingress",
            "Infrastructure definition contains unrestricted IPv4 ingress.",
            ModuleSourceSeverity::High,
            "CWE-284",
        );
    }
    if lower.contains("insecureskipverify: true") || lower.contains("verify_tls = false") {
        config_lead(
            file,
            leads,
            "config.tls-verification-disabled",
            "Configuration disables TLS certificate verification.",
            ModuleSourceSeverity::High,
            "CWE-295",
        );
    }
    if lower.contains("debug = true") || lower.contains("debug: true") {
        config_lead(
            file,
            leads,
            "config.debug-enabled",
            "Configuration enables debug behavior; confirm production reachability.",
            ModuleSourceSeverity::Medium,
            "CWE-489",
        );
    }
}

fn config_lead(
    file: &AnalysisSourceFile,
    leads: &mut Vec<RawLead>,
    rule_id: &str,
    message: &str,
    severity: ModuleSourceSeverity,
    standard: &str,
) {
    leads.push(RawLead {
        category: "configuration_secrets_and_observability".into(),
        rule_id: rule_id.into(),
        severity,
        path: file.path.clone(),
        line: None,
        message: message.into(),
        root_cause: format!("{rule_id}:{}", file.path),
        evidence_digest: digest(format!("{}\0{rule_id}", file.digest).as_bytes()),
        redacted: false,
        reachability: path_reachability(&file.path),
        standards: vec![standard.into()],
    });
}

fn manifest_ecosystem(path: &str) -> Option<&'static str> {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    if matches!(name.as_str(), "cargo.toml" | "cargo.lock") {
        Some("cargo")
    } else if matches!(name.as_str(), "package.json" | "package-lock.json") {
        Some("npm")
    } else if name.starts_with("requirements") && name.ends_with(".txt") {
        Some("python")
    } else if name == "go.mod" {
        Some("go")
    } else if name == "pom.xml" {
        Some("maven")
    } else {
        None
    }
}

fn parse_components(
    file: &AnalysisSourceFile,
    text: &str,
    ecosystem: &str,
) -> Vec<ModuleSourceComponentObservation> {
    match ecosystem {
        "cargo" if file.path.ends_with("Cargo.lock") => parse_cargo_lock(file, text),
        "npm" => parse_npm(file, text),
        "python" => parse_requirements(file, text),
        "go" => parse_go_mod(file, text),
        "maven" => parse_pom(file, text),
        _ => Vec::new(),
    }
}

fn component(
    ecosystem: &str,
    name: &str,
    version: Option<String>,
    path: &str,
    scope: &str,
) -> Option<ModuleSourceComponentObservation> {
    let name = name.trim().trim_matches('"');
    if name.is_empty() || name.len() > 256 {
        return None;
    }
    Some(ModuleSourceComponentObservation {
        ecosystem: ecosystem.into(),
        name: name.into(),
        version: version.filter(|value| !value.is_empty() && value.len() <= 128),
        source_path: path.into(),
        scope: scope.into(),
        reachability: ModuleSourceReachability::Unknown,
        advisories: Vec::new(),
    })
}

fn parse_cargo_lock(
    file: &AnalysisSourceFile,
    text: &str,
) -> Vec<ModuleSourceComponentObservation> {
    let mut result = Vec::new();
    let mut name = None::<String>;
    let mut version = None::<String>;
    for line in text.lines().chain(std::iter::once("[[package]]")) {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            if let Some(name) = name.take()
                && let Some(value) =
                    component("cargo", &name, version.take(), &file.path, "resolved")
            {
                result.push(value);
            }
        } else if let Some(value) = trimmed.strip_prefix("name = ") {
            name = Some(value.trim_matches('"').into());
        } else if let Some(value) = trimmed.strip_prefix("version = ") {
            version = Some(value.trim_matches('"').into());
        }
    }
    result
}

fn parse_npm(file: &AnalysisSourceFile, text: &str) -> Vec<ModuleSourceComponentObservation> {
    let Ok(value) = serde_json::from_str::<Value>(text) else { return Vec::new() };
    let mut result = Vec::new();
    for (field, scope) in [("dependencies", "runtime"), ("devDependencies", "development")] {
        if let Some(values) = value.get(field).and_then(Value::as_object) {
            for (name, version) in values {
                if let Some(value) = component(
                    "npm",
                    name,
                    version.as_str().map(ToOwned::to_owned),
                    &file.path,
                    scope,
                ) {
                    result.push(value);
                }
            }
        }
    }
    if file.path.ends_with("package-lock.json")
        && let Some(packages) = value.get("packages").and_then(Value::as_object)
    {
        for (path, metadata) in packages {
            let Some(name) = path.strip_prefix("node_modules/") else { continue };
            let version = metadata.get("version").and_then(Value::as_str).map(ToOwned::to_owned);
            if let Some(value) = component("npm", name, version, &file.path, "resolved") {
                result.push(value);
            }
        }
    }
    result
}

fn parse_requirements(
    file: &AnalysisSourceFile,
    text: &str,
) -> Vec<ModuleSourceComponentObservation> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
                return None;
            }
            let (name, version) = line
                .split_once("==")
                .map_or((line, None), |(name, version)| (name, Some(version.trim().to_owned())));
            component(
                "python",
                name,
                version,
                &file.path,
                if test_path(&file.path) { "test" } else { "runtime" },
            )
        })
        .collect()
}

fn parse_go_mod(file: &AnalysisSourceFile, text: &str) -> Vec<ModuleSourceComponentObservation> {
    let mut result = Vec::new();
    let mut require_block = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "require (" {
            require_block = true;
            continue;
        }
        if require_block && trimmed == ")" {
            require_block = false;
            continue;
        }
        let value = trimmed.strip_prefix("require ").or(require_block.then_some(trimmed));
        let Some(value) = value else { continue };
        let mut parts = value.split_whitespace();
        let Some(name) = parts.next() else { continue };
        let version = parts.next().map(ToOwned::to_owned);
        if let Some(value) = component("go", name, version, &file.path, "runtime") {
            result.push(value);
        }
    }
    result
}

fn parse_pom(file: &AnalysisSourceFile, text: &str) -> Vec<ModuleSourceComponentObservation> {
    let mut result = Vec::new();
    for block in text.split("<dependency>").skip(1) {
        let block = block.split("</dependency>").next().unwrap_or(block);
        let artifact = xml_value(block, "artifactId");
        let group = xml_value(block, "groupId");
        let version = xml_value(block, "version").map(ToOwned::to_owned);
        let scope = xml_value(block, "scope").unwrap_or("runtime");
        if let Some(artifact) = artifact {
            let name =
                group.map_or_else(|| artifact.to_owned(), |group| format!("{group}:{artifact}"));
            if let Some(value) = component("maven", &name, version, &file.path, scope) {
                result.push(value);
            }
        }
    }
    result
}

fn xml_value<'a>(text: &'a str, tag: &str) -> Option<&'a str> {
    let start = format!("<{tag}>");
    let end = format!("</{tag}>");
    let value = text.split_once(&start)?.1.split_once(&end)?.0.trim();
    (!value.is_empty()).then_some(value)
}

fn dependency_reachability(
    component: &ModuleSourceComponentObservation,
    source_texts: &[(String, String, bool)],
) -> ModuleSourceReachability {
    let names = dependency_names(&component.name);
    let mut test = false;
    for (path, text, is_test) in source_texts {
        if path == &component.source_path || manifest_ecosystem(path).is_some() {
            continue;
        }
        if names.iter().any(|name| text.contains(name)) {
            if *is_test {
                test = true;
            } else {
                return ModuleSourceReachability::RuntimeReferenced;
            }
        }
    }
    if test || matches!(component.scope.as_str(), "test" | "development") {
        ModuleSourceReachability::TestOnly
    } else {
        ModuleSourceReachability::Unreachable
    }
}

fn dependency_names(name: &str) -> Vec<String> {
    let leaf = name.rsplit(['/', ':']).next().unwrap_or(name).to_ascii_lowercase();
    let mut names = vec![leaf.clone()];
    let underscored = leaf.replace('-', "_");
    if underscored != leaf {
        names.push(underscored);
    }
    // Package coordinates and source-level import names are not always identical. Keep this
    // registry deliberately small and pinned with the advisory data rather than treating fuzzy
    // substrings as proof of reachability.
    match leaf.as_str() {
        "pyyaml" => names.push("yaml".into()),
        "log4j-core" => names.push("log4j".into()),
        _ => {}
    }
    names
}

fn advisories(component: &ModuleSourceComponentObservation) -> Vec<String> {
    let name = component.name.to_ascii_lowercase();
    let version =
        component.version.as_deref().unwrap_or_default().trim_start_matches(['^', '~', '=']);
    match (component.ecosystem.as_str(), name.as_str(), version) {
        ("npm", "lodash", "4.17.20") => vec!["CVE-2021-23337".into()],
        ("python", "pyyaml", "5.3.1") => vec!["CVE-2020-14343".into()],
        ("maven", "org.apache.logging.log4j:log4j-core", "2.14.1") => {
            vec!["CVE-2021-44228".into()]
        }
        ("cargo", "time", "0.1.44") => vec!["RUSTSEC-2020-0071".into()],
        ("go", "github.com/dgrijalva/jwt-go", "v3.2.0+incompatible") => {
            vec!["CVE-2020-26160".into()]
        }
        _ => Vec::new(),
    }
}

fn deduplicate(raw: Vec<RawLead>) -> Vec<ModuleSourceFindingObservation> {
    let mut grouped = BTreeMap::<String, (RawLead, u64)>::new();
    for lead in raw {
        grouped
            .entry(lead.root_cause.clone())
            .and_modify(|(retained, count)| {
                *count = count.saturating_add(1);
                if lead.severity > retained.severity {
                    retained.severity = lead.severity;
                }
            })
            .or_insert((lead, 1));
    }
    grouped
        .into_iter()
        .map(|(root_cause, (lead, count))| ModuleSourceFindingObservation {
            id: format!("lead-{}", &digest(root_cause.as_bytes())[..24]),
            category: lead.category,
            rule_id: lead.rule_id,
            severity: lead.severity,
            path: lead.path,
            line: lead.line,
            message: lead.message,
            root_cause,
            evidence_digest: lead.evidence_digest,
            redacted: lead.redacted,
            reachability: lead.reachability,
            evidence_state: "source_lead".into(),
            standards: lead.standards,
            deduplicated_from: count,
        })
        .collect()
}

fn raw_digest(raw: &[RawLead]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"peritus-source-analysis-raw-v1\0");
    for lead in raw {
        hasher.update(lead.rule_id.as_bytes());
        hasher.update(b"\0");
        hasher.update(lead.path.as_bytes());
        hasher.update(b"\0");
        hasher.update(lead.line.unwrap_or_default().to_be_bytes());
        hasher.update(lead.evidence_digest.as_bytes());
        hasher.update(b"\0");
    }
    hex(&hasher.finalize())
}

fn path_reachability(path: &str) -> ModuleSourceReachability {
    if test_path(path) {
        ModuleSourceReachability::TestOnly
    } else if path.split('/').any(|part| matches!(part, "dead" | "unused" | "archive")) {
        ModuleSourceReachability::Unreachable
    } else {
        ModuleSourceReachability::Unknown
    }
}

fn test_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower
        .split('/')
        .any(|part| matches!(part, "test" | "tests" | "testing" | "fixtures" | "examples"))
        || lower.ends_with("_test.go")
        || lower.ends_with("_test.py")
        || lower.ends_with(".test.js")
        || lower.ends_with(".spec.ts")
        || lower.ends_with("requirements-test.txt")
        || lower.ends_with("requirements_test.txt")
}

fn comment_only(line: &str, language: &str) -> bool {
    line.starts_with("//")
        || line.starts_with("/*")
        || (language == "python" && line.starts_with('#'))
}

fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
