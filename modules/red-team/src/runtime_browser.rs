//! Module-owned real-browser controller.
//!
//! The host supplies only the worker process and disposable source tree. This module owns the
//! pinned campaigns, dependency discovery, browser invocation, deadlines, and result decoding.

use serde_json::Value;
use std::{
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const MAXIMUM_RESULT_BYTES: u64 = 256 * 1024;
const BROWSER_CAMPAIGN: &str = include_str!("../resources/browser_campaign.py");
const ATTACK_GRAPH_BROWSER: &str = include_str!("../resources/attack_graph_browser.py");
pub(super) const RESEARCH_POC: &str = include_str!("../resources/research_poc.py");
pub(super) const REPAIR_REGRESSION: &str = include_str!("../resources/repair_regression.py");
const DIAMOND_BROWSER: &str = include_str!("../resources/diamond_browser_campaign.py");
const GENERIC_WEB_BROWSER: &str = include_str!("../resources/generic_web_browser.py");

pub(super) fn campaign(
    directory: &Path,
    target_socket: &Path,
    attacker_socket: &Path,
    maximum_actions: u32,
    maximum_requests: u32,
) -> Result<Value, String> {
    if !(24..=128).contains(&maximum_actions) || !(24..=256).contains(&maximum_requests) {
        return Err("browser campaign bounds are outside the module profile".into());
    }
    run(
        directory,
        "browser_campaign.py",
        BROWSER_CAMPAIGN,
        vec![
            ("--target-socket".into(), target_socket.as_os_str().to_owned()),
            ("--attacker-socket".into(), attacker_socket.as_os_str().to_owned()),
            ("--maximum-actions".into(), maximum_actions.to_string().into()),
            ("--maximum-requests".into(), maximum_requests.to_string().into()),
        ],
        Duration::from_secs(90),
    )
}

pub(super) fn attack_graph(
    directory: &Path,
    target_socket: &Path,
    maximum_actions: u32,
    maximum_requests: u32,
) -> Result<Value, String> {
    if !(3..=32).contains(&maximum_actions) || !(8..=64).contains(&maximum_requests) {
        return Err("attack-graph browser bounds are outside the module profile".into());
    }
    run(
        directory,
        "attack_graph_browser.py",
        ATTACK_GRAPH_BROWSER,
        vec![
            ("--target-socket".into(), target_socket.as_os_str().to_owned()),
            ("--maximum-actions".into(), maximum_actions.to_string().into()),
            ("--maximum-requests".into(), maximum_requests.to_string().into()),
        ],
        Duration::from_secs(45),
    )
}

pub(super) fn research_poc(
    directory: &Path,
    target: &peritus_plugin_sdk::ModuleResearchPocTargetIdentity,
    destination: &str,
    synthetic_identity: &str,
    expect_vulnerable: bool,
    maximum_actions: u32,
    maximum_requests: u32,
) -> Result<Value, String> {
    let root = std::env::current_dir().map_err(|error| error.to_string())?;
    run(
        directory,
        "research_poc.py",
        RESEARCH_POC,
        vec![
            ("--target-root".into(), root.into_os_string()),
            ("--application-path".into(), target.application_path.clone().into()),
            ("--application-digest".into(), target.application_digest.clone().into()),
            ("--service-path".into(), target.service_path.clone().into()),
            ("--service-digest".into(), target.service_digest.clone().into()),
            ("--target-identity".into(), target.target_identity.clone().into()),
            ("--destination".into(), destination.into()),
            ("--synthetic-identity".into(), synthetic_identity.into()),
            ("--expect".into(), if expect_vulnerable { "vulnerable" } else { "safe" }.into()),
            ("--maximum-actions".into(), maximum_actions.to_string().into()),
            ("--maximum-requests".into(), maximum_requests.to_string().into()),
        ],
        Duration::from_secs(60),
    )
}

pub(super) fn repair_regression(
    directory: &Path,
    target_socket: &Path,
    destination: &str,
    synthetic_identity: &str,
    maximum_actions: u32,
    maximum_requests: u32,
) -> Result<Value, String> {
    run(
        directory,
        "repair_regression.py",
        REPAIR_REGRESSION,
        vec![
            ("--target-socket".into(), target_socket.as_os_str().to_owned()),
            ("--destination".into(), destination.into()),
            ("--synthetic-identity".into(), synthetic_identity.into()),
            ("--maximum-actions".into(), maximum_actions.to_string().into()),
            ("--maximum-requests".into(), maximum_requests.to_string().into()),
        ],
        Duration::from_secs(90),
    )
}

pub(super) fn diamond_campaign(directory: &Path, target: &str) -> Result<Value, String> {
    run(
        directory,
        "diamond_browser_campaign.py",
        DIAMOND_BROWSER,
        vec![("--target".into(), target.into())],
        Duration::from_secs(90),
    )
}

pub(super) fn generic_web_campaign(
    directory: &Path,
    target: &str,
    profile: &str,
) -> Result<Value, String> {
    run(
        directory,
        "generic_web_browser.py",
        GENERIC_WEB_BROWSER,
        vec![("--target".into(), target.into()), ("--profile".into(), profile.into())],
        Duration::from_secs(90),
    )
}

fn run(
    directory: &Path,
    script_name: &str,
    script_source: &str,
    arguments: Vec<(String, OsString)>,
    timeout: Duration,
) -> Result<Value, String> {
    fs::create_dir_all(directory).map_err(|error| error.to_string())?;
    let script = directory.join(script_name);
    write_private(&script, script_source.as_bytes())?;
    let result = directory.join("result.json");
    let output = directory.join("artifacts");
    let python = python()?;
    let browser_cache = browser_cache()?;
    let browser = ensure_browser(&python, &browser_cache)?;
    let mut command = Command::new(&python);
    command
        .arg(&script)
        .arg("--output")
        .arg(&output)
        .arg("--result")
        .arg(&result)
        .arg("--browser-executable")
        .arg(&browser);
    for (name, value) in arguments {
        command.arg(name).arg(value);
    }
    command
        .env("PLAYWRIGHT_BROWSERS_PATH", &browser_cache)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("launch module-owned real-browser campaign: {error}"))?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            let output = child.wait_with_output().map_err(|error| error.to_string())?;
            if !status.success() {
                return Err(format!(
                    "module-owned real-browser campaign failed ({status}): {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
            }
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("module-owned real-browser campaign exceeded its deadline".into());
        }
        thread::sleep(Duration::from_millis(40));
    }
    if result.is_symlink() {
        return Err("module browser result is a symbolic link".into());
    }
    let bytes = fs::read(result).map_err(|error| error.to_string())?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAXIMUM_RESULT_BYTES {
        return Err("module browser result exceeds its observation bound".into());
    }
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

fn python() -> Result<PathBuf, String> {
    for name in ["PERITUS_RED_TEAM_PYTHON", "PERITUS_AUTOMATION_PYTHON"] {
        if let Some(path) = env::var_os(name).map(PathBuf::from) {
            if path.is_absolute() && path.is_file() {
                return Ok(path);
            }
            return Err(format!("{name} must name an absolute Python executable"));
        }
    }
    if let Some(home) = env::var_os("HOME") {
        let root = PathBuf::from(home).join(".local/share/peritus/automation/runtime");
        for relative in ["bin/python", "Scripts/python.exe"] {
            let candidate = root.join(relative);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    executable_on_path(if cfg!(windows) { "python.exe" } else { "python3" })
        .ok_or_else(|| "the Red Team browser adapter requires Python 3 with Playwright".into())
}

fn browser_cache() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("PERITUS_RED_TEAM_BROWSERS_PATH")
        .or_else(|| env::var_os("PLAYWRIGHT_BROWSERS_PATH"))
        .map(PathBuf::from)
    {
        if path == Path::new("0") || path.is_absolute() {
            return Ok(path);
        }
        return Err("the Red Team browser cache path must be absolute or 0".into());
    }
    let home = env::var_os("HOME").ok_or("the Red Team browser cache root is unavailable")?;
    Ok(PathBuf::from(home).join(".cache/ms-playwright"))
}

fn ensure_browser(python: &Path, cache: &Path) -> Result<PathBuf, String> {
    if let Some(executable) = discover_browser(cache) {
        return Ok(executable);
    }
    let status = Command::new(python)
        .args(["-m", "playwright", "install", "chromium"])
        .env("PLAYWRIGHT_BROWSERS_PATH", cache)
        .status()
        .map_err(|error| format!("install the Red Team Chromium runtime: {error}"))?;
    if !status.success() {
        return Err(format!("install the Red Team Chromium runtime: {status}"));
    }
    discover_browser(cache)
        .ok_or_else(|| "Playwright completed without a discoverable Chromium executable".into())
}

fn discover_browser(cache: &Path) -> Option<PathBuf> {
    let roots = fs::read_dir(cache).ok()?;
    for root in roots.flatten().map(|entry| entry.path()) {
        let name = root.file_name()?.to_string_lossy();
        if !name.starts_with("chromium-") && !name.starts_with("chromium_headless_shell-") {
            continue;
        }
        for relative in [
            "chrome-linux64/chrome",
            "chrome-headless-shell-linux64/chrome-headless-shell",
            "chrome-mac/Chromium.app/Contents/MacOS/Chromium",
            "chrome-win/chrome.exe",
        ] {
            let candidate = root.join(relative);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn executable_on_path(name: &str) -> Option<PathBuf> {
    env::split_paths(&env::var_os("PATH").unwrap_or_default())
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if path.is_symlink() {
        return Err("module browser driver path is a symbolic link".into());
    }
    fs::write(path, bytes).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}
