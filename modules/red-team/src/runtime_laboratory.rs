//! Module-owned disposable target runtime.
//!
//! Peritus has already copied the explicitly selected source and bounded this worker process tree.
//! This layer owns Red Team target selection, protocol construction, state oracles, and cleanup.

use crate::{
    digest,
    runtime_http_api::{Exchange, WireRequest},
};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read as _, Write as _},
    os::unix::net::UnixStream,
    path::{Component, Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

const MAXIMUM_WIRE_BYTES: usize = 2 * 1024 * 1024;

pub(super) struct HttpLaboratory {
    _private: tempfile::TempDir,
    child: Child,
    socket_path: PathBuf,
    state_path: PathBuf,
    secret: Vec<u8>,
    source_snapshot: String,
    application_path: String,
    application_bytes: Vec<u8>,
    service_path: String,
    service_bytes: Vec<u8>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TargetBinding {
    pub(super) laboratory_id: String,
    pub(super) target: TargetPaths,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TargetPaths {
    pub(super) application_path: String,
    pub(super) service_path: String,
}

pub(super) struct Broker {
    source_snapshot: String,
    targets: Vec<TargetBinding>,
    laboratories: Mutex<BTreeMap<String, HttpLaboratory>>,
}

#[derive(Clone)]
pub(super) struct IdentityLaboratorySession {
    pub(super) source_snapshot: String,
    pub(super) credential_seed: Vec<u8>,
}

#[derive(Clone)]
pub(super) struct FileFuzzLaboratorySession {
    pub(super) root: PathBuf,
    pub(super) source_snapshot: String,
}

#[derive(Clone)]
pub(super) struct WorkflowLaboratorySession {
    pub(super) state_path: PathBuf,
    pub(super) source_snapshot: String,
}

#[derive(Clone)]
pub(super) struct BoundaryLaboratorySession {
    pub(super) root: PathBuf,
    pub(super) state_path: PathBuf,
    pub(super) source_snapshot: String,
}

#[derive(Clone)]
pub(super) struct BrowserLaboratorySession {
    pub(super) target_socket: PathBuf,
    pub(super) attacker_socket: PathBuf,
    pub(super) state_path: PathBuf,
    pub(super) source_snapshot: String,
}

#[derive(Clone)]
pub(super) struct AttackGraphLaboratorySession {
    pub(super) source_snapshot: String,
    pub(super) application_path: String,
    pub(super) application_bytes: Vec<u8>,
    pub(super) application_digest: String,
    pub(super) service_path: String,
    pub(super) service_bytes: Vec<u8>,
    pub(super) service_digest: String,
}

impl Broker {
    pub(super) fn new(source_snapshot: String, targets: Vec<TargetBinding>) -> Self {
        Self { source_snapshot, targets, laboratories: Mutex::new(BTreeMap::new()) }
    }

    pub(super) fn http_exchange(
        &self,
        laboratory_id: &str,
        _endpoint_handle: &str,
        request: &WireRequest,
    ) -> Result<Exchange, String> {
        let mut laboratories =
            self.laboratories.lock().map_err(|_| "module laboratory lock is poisoned")?;
        self.ensure(laboratory_id, &mut laboratories)?.exchange(request)
    }

    pub(super) fn identity_session(
        &self,
        laboratory_id: &str,
        _endpoint_handle: &str,
    ) -> Result<IdentityLaboratorySession, String> {
        self.with_laboratory(laboratory_id, |laboratory| IdentityLaboratorySession {
            source_snapshot: laboratory.source_snapshot.clone(),
            credential_seed: laboratory.secret.clone(),
        })
    }

    pub(super) fn file_fuzz_session(
        &self,
        laboratory_id: &str,
        _endpoint_handle: &str,
    ) -> Result<FileFuzzLaboratorySession, String> {
        self.with_laboratory(laboratory_id, |laboratory| FileFuzzLaboratorySession {
            root: laboratory._private.path().to_path_buf(),
            source_snapshot: laboratory.source_snapshot.clone(),
        })
    }

    pub(super) fn workflow_session(
        &self,
        laboratory_id: &str,
        _endpoint_handle: &str,
    ) -> Result<WorkflowLaboratorySession, String> {
        self.with_laboratory(laboratory_id, |laboratory| WorkflowLaboratorySession {
            state_path: laboratory.state_path.clone(),
            source_snapshot: laboratory.source_snapshot.clone(),
        })
    }

    pub(super) fn boundary_session(
        &self,
        laboratory_id: &str,
        _endpoint_handle: &str,
    ) -> Result<BoundaryLaboratorySession, String> {
        self.with_laboratory(laboratory_id, |laboratory| BoundaryLaboratorySession {
            root: laboratory._private.path().to_path_buf(),
            state_path: laboratory.state_path.clone(),
            source_snapshot: laboratory.source_snapshot.clone(),
        })
    }

    pub(super) fn browser_session(
        &self,
        laboratory_id: &str,
        _endpoint_handle: &str,
        _maximum_requests: u32,
    ) -> Result<BrowserLaboratorySession, String> {
        self.with_laboratory(laboratory_id, |laboratory| BrowserLaboratorySession {
            target_socket: laboratory.socket_path.clone(),
            attacker_socket: laboratory.socket_path.clone(),
            state_path: laboratory.state_path.clone(),
            source_snapshot: laboratory.source_snapshot.clone(),
        })
    }

    pub(super) fn attack_graph_session(
        &self,
        laboratory_id: &str,
        _endpoint_handle: &str,
    ) -> Result<AttackGraphLaboratorySession, String> {
        self.with_laboratory(laboratory_id, |laboratory| AttackGraphLaboratorySession {
            source_snapshot: laboratory.source_snapshot.clone(),
            application_path: laboratory.application_path.clone(),
            application_bytes: laboratory.application_bytes.clone(),
            application_digest: digest(&laboratory.application_bytes),
            service_path: laboratory.service_path.clone(),
            service_bytes: laboratory.service_bytes.clone(),
            service_digest: digest(&laboratory.service_bytes),
        })
    }

    pub(super) fn record_browser_observation(
        &self,
        laboratory_id: &str,
        _endpoint_handle: &str,
        _requests_observed: u64,
        final_state_digest: &str,
    ) -> Result<(), String> {
        let observed = self.with_laboratory(laboratory_id, |laboratory| {
            state(&laboratory.state_path).map(|state| state.digest)
        })??;
        if observed != final_state_digest {
            return Err("module browser final-state receipt does not match copied state".into());
        }
        Ok(())
    }

    fn with_laboratory<T>(
        &self,
        laboratory_id: &str,
        inspect: impl FnOnce(&HttpLaboratory) -> T,
    ) -> Result<T, String> {
        let mut laboratories =
            self.laboratories.lock().map_err(|_| "module laboratory lock is poisoned")?;
        Ok(inspect(self.ensure(laboratory_id, &mut laboratories)?))
    }

    fn ensure<'a>(
        &self,
        laboratory_id: &str,
        laboratories: &'a mut BTreeMap<String, HttpLaboratory>,
    ) -> Result<&'a mut HttpLaboratory, String> {
        if !laboratories.contains_key(laboratory_id) {
            let target = self
                .targets
                .iter()
                .find(|target| target.laboratory_id == laboratory_id)
                .ok_or_else(|| {
                format!("no module-owned target metadata for laboratory `{laboratory_id}`")
            })?;
            let laboratory = HttpLaboratory::launch(
                &target.target.application_path,
                &target.target.service_path,
                &self.source_snapshot,
            )?;
            laboratories.insert(laboratory_id.into(), laboratory);
        }
        laboratories
            .get_mut(laboratory_id)
            .ok_or_else(|| "module laboratory disappeared during launch".into())
    }
}

impl HttpLaboratory {
    pub(super) fn launch(
        application_path: &str,
        service_path: &str,
        source_snapshot: &str,
    ) -> Result<Self, String> {
        validate_path(application_path)?;
        validate_path(service_path)?;
        let root = std::env::current_dir().map_err(|error| error.to_string())?;
        let application = source_file(&root, application_path)?;
        let service = source_file(&root, service_path)?;
        // The controller is part of the target contract and remains identity evidence even though
        // the module launches the service directly to retain protocol control in this worker.
        let application_bytes = fs::read(&application).map_err(|error| error.to_string())?;
        let service_bytes = fs::read(&service).map_err(|error| error.to_string())?;
        let private_root = root.join(".red-team-worker-private");
        fs::create_dir_all(&private_root).map_err(|error| error.to_string())?;
        let private = tempfile::Builder::new()
            .prefix("http-")
            .tempdir_in(private_root)
            .map_err(|error| error.to_string())?;
        // AF_UNIX names have a small kernel limit. The generic host may place an isolated worker
        // under a deeply nested durable state root, so pass source-root-relative names to the
        // module-owned child rather than leaking that host path into the protocol.
        let private_relative = private
            .path()
            .strip_prefix(&root)
            .map_err(|_| "module laboratory directory escaped the disposable source root")?;
        let socket_path = private_relative.join("target.sock");
        let state_path = private_relative.join("state.json");
        let secret_path = private_relative.join("secret");
        fs::write(&state_path, b"{}\n").map_err(|error| error.to_string())?;
        let secret = format!(
            "peritus-red-team-secret-{}",
            &digest(format!("{source_snapshot}\0{service_path}").as_bytes())[..24]
        )
        .into_bytes();
        fs::write(&secret_path, &secret).map_err(|error| error.to_string())?;
        let mut command = Command::new("/usr/bin/python3");
        command.arg(&service).arg(&socket_path).arg(&state_path).arg(&secret_path);
        if service_path.ends_with("shared-service.py") {
            command.arg(if application_path.contains("/vulnerable/") {
                "vulnerable"
            } else {
                "safe"
            });
        }
        let mut child = command
            .current_dir(&root)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("launch module-owned HTTP target: {error}"))?;
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if socket_path.is_socket() && health(&socket_path).is_ok() {
                break;
            }
            if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
                let mut detail = String::new();
                if let Some(stderr) = child.stderr.take() {
                    let _ = stderr.take(8 * 1024).read_to_string(&mut detail);
                }
                return Err(format!(
                    "module-owned HTTP target exited before readiness ({status}): {}",
                    detail.trim()
                ));
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(
                    "module-owned HTTP target did not become ready before its deadline".into()
                );
            }
            thread::sleep(Duration::from_millis(20));
        }
        Ok(Self {
            _private: private,
            child,
            socket_path,
            state_path,
            secret,
            source_snapshot: source_snapshot.into(),
            application_path: application_path.into(),
            application_bytes,
            service_path: service_path.into(),
            service_bytes,
        })
    }

    pub(super) fn exchange(&mut self, request: &WireRequest) -> Result<Exchange, String> {
        let before = state(&self.state_path)?;
        let mut stream = UnixStream::connect(&self.socket_path)
            .map_err(|error| format!("connect module-owned HTTP target: {error}"))?;
        stream.set_read_timeout(Some(Duration::from_secs(4))).map_err(|error| error.to_string())?;
        stream
            .set_write_timeout(Some(Duration::from_secs(4)))
            .map_err(|error| error.to_string())?;
        let wire = request_bytes(request)?;
        if u64::try_from(wire.len()).unwrap_or(u64::MAX) > request.maximum_request_bytes {
            return Err("module-owned HTTP request exceeded its admitted byte bound".into());
        }
        stream.write_all(&wire).map_err(|error| error.to_string())?;
        let (raw, websocket_echo) = if let Some(message) = &request.websocket_message {
            websocket_exchange(&mut stream, message, request.maximum_response_bytes)?
        } else {
            (read_bounded(&mut stream, request.maximum_response_bytes)?, None)
        };
        let parsed = parse_response(&raw)?;
        let after = state(&self.state_path)?;
        let changed_state_keys = changed_keys(&before.values, &after.values);
        let secret_disclosed = contains(&raw, &self.secret);
        let mut body = parsed.body;
        if secret_disclosed {
            body = replace_all(&body, &self.secret, b"[REDACTED]");
        }
        Ok(Exchange {
            request_digest: digest(&wire),
            request_bytes: u64::try_from(wire.len()).unwrap_or(u64::MAX),
            response_status: parsed.status,
            response_headers: parsed.headers,
            response_body: String::from_utf8_lossy(&body).into_owned(),
            response_digest: digest(&raw),
            response_body_digest: digest(&body),
            response_bytes: u64::try_from(raw.len()).unwrap_or(u64::MAX),
            response_redacted: secret_disclosed,
            secret_disclosed,
            websocket_echo,
            state_before_digest: before.digest,
            state_after_digest: after.digest,
            changed_state_keys,
        })
    }
}

impl Drop for HttpLaboratory {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct ParsedResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

struct State {
    digest: String,
    values: BTreeMap<String, Value>,
}

fn health(socket: &Path) -> Result<(), String> {
    let mut stream = UnixStream::connect(socket).map_err(|error| error.to_string())?;
    stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: laboratory.invalid\r\nConnection: close\r\n\r\n")
        .map_err(|error| error.to_string())?;
    let response = read_bounded(&mut stream, 64 * 1024)?;
    if response.starts_with(b"HTTP/1.1 200") {
        Ok(())
    } else {
        Err("health route did not return HTTP 200".into())
    }
}

fn request_bytes(request: &WireRequest) -> Result<Vec<u8>, String> {
    if request.method.is_empty()
        || request.target.is_empty()
        || request.method.bytes().any(|byte| !byte.is_ascii_uppercase())
        || !request.target.starts_with('/')
        || request.target.contains(['\r', '\n'])
    {
        return Err("module-owned HTTP request has an invalid method or target".into());
    }
    let mut headers = request.headers.clone();
    if !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("host")) {
        headers.push(("host".into(), "laboratory.invalid".into()));
    }
    headers.retain(|(name, _)| !name.eq_ignore_ascii_case("content-length"));
    headers.push(("content-length".into(), request.body.len().to_string()));
    if request.websocket_message.is_some() {
        headers.push(("upgrade".into(), "websocket".into()));
        headers.push(("connection".into(), "Upgrade".into()));
        headers.push(("sec-websocket-version".into(), "13".into()));
        headers.push(("sec-websocket-key".into(), "cGVyaXR1cy1yZWQtdGVhbQ==".into()));
    } else if !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("connection")) {
        headers.push(("connection".into(), "close".into()));
    }
    let mut bytes = format!("{} {} HTTP/1.1\r\n", request.method, request.target).into_bytes();
    for (name, value) in headers {
        if name.is_empty() || name.contains(['\r', '\n', ':']) || value.contains(['\r', '\n']) {
            return Err("module-owned HTTP header contains invalid bytes".into());
        }
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(b": ");
        bytes.extend_from_slice(value.as_bytes());
        bytes.extend_from_slice(b"\r\n");
    }
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(request.body.as_bytes());
    Ok(bytes)
}

fn websocket_exchange(
    stream: &mut UnixStream,
    message: &str,
    maximum: u64,
) -> Result<(Vec<u8>, Option<String>), String> {
    let mut head = Vec::new();
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        if head.len() >= MAXIMUM_WIRE_BYTES
            || u64::try_from(head.len()).unwrap_or(u64::MAX) > maximum
        {
            return Err("WebSocket response head exceeded its admitted bound".into());
        }
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).map_err(|error| error.to_string())?;
        head.push(byte[0]);
    }
    if !head.starts_with(b"HTTP/1.1 101") {
        return Ok((head, None));
    }
    let payload = message.as_bytes();
    if payload.len() > 125 {
        return Err("pinned WebSocket message exceeds the short-frame bound".into());
    }
    let mask = [0x12, 0x34, 0x56, 0x78];
    let mut frame = vec![0x81, 0x80 | u8::try_from(payload.len()).map_err(|_| "frame length")?];
    frame.extend_from_slice(&mask);
    frame.extend(payload.iter().enumerate().map(|(index, byte)| byte ^ mask[index % 4]));
    stream.write_all(&frame).map_err(|error| error.to_string())?;
    let mut response_head = [0_u8; 2];
    stream.read_exact(&mut response_head).map_err(|error| error.to_string())?;
    let length = usize::from(response_head[1] & 0x7f);
    if length > 125 {
        return Err("WebSocket response used an unsupported frame length".into());
    }
    let mut echo = vec![0_u8; length];
    stream.read_exact(&mut echo).map_err(|error| error.to_string())?;
    let text = String::from_utf8(echo.clone()).map_err(|_| "WebSocket echo is not UTF-8")?;
    head.extend_from_slice(&response_head);
    head.extend_from_slice(&echo);
    Ok((head, Some(text)))
}

fn read_bounded(stream: &mut UnixStream, maximum: u64) -> Result<Vec<u8>, String> {
    let maximum = usize::try_from(maximum).unwrap_or(MAXIMUM_WIRE_BYTES).min(MAXIMUM_WIRE_BYTES);
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = stream.read(&mut buffer).map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        if bytes.len().saturating_add(read) > maximum {
            return Err("module-owned HTTP response exceeded its admitted byte bound".into());
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    Ok(bytes)
}

fn parse_response(bytes: &[u8]) -> Result<ParsedResponse, String> {
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "module-owned HTTP response has no complete head".to_string())?;
    let head = std::str::from_utf8(&bytes[..split])
        .map_err(|_| "module-owned HTTP response head is not UTF-8")?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| "module-owned HTTP response has no valid status".to_string())?;
    let mut headers = Vec::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "module-owned HTTP response has an invalid header".to_string())?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    Ok(ParsedResponse { status, headers, body: bytes[split + 4..].to_vec() })
}

fn state(path: &Path) -> Result<State, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let values = serde_json::from_slice::<BTreeMap<String, Value>>(&bytes)
        .map_err(|error| format!("decode copied target state: {error}"))?;
    Ok(State { digest: digest(&bytes), values })
}

fn changed_keys(before: &BTreeMap<String, Value>, after: &BTreeMap<String, Value>) -> Vec<String> {
    before
        .keys()
        .chain(after.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|key| before.get(*key) != after.get(*key))
        .cloned()
        .collect()
}

fn validate_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.len() > 4_096
        || path.contains(['\0', '\\'])
        || Path::new(path).is_absolute()
        || !Path::new(path).components().all(|component| matches!(component, Component::Normal(_)))
    {
        return Err("module target paths must be canonical source-relative paths".into());
    }
    Ok(())
}

fn source_file(root: &Path, path: &str) -> Result<PathBuf, String> {
    let root = fs::canonicalize(root).map_err(|error| error.to_string())?;
    let target = fs::canonicalize(root.join(path)).map_err(|error| error.to_string())?;
    if target.starts_with(&root) && target.is_file() {
        Ok(target)
    } else {
        Err(format!("module target `{path}` is not a regular file in the disposable source"))
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
}

fn replace_all(bytes: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(bytes.len());
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes[offset..].starts_with(needle) {
            result.extend_from_slice(replacement);
            offset += needle.len();
        } else {
            result.push(bytes[offset]);
            offset += 1;
        }
    }
    result
}

#[cfg(unix)]
trait SocketPath {
    fn is_socket(&self) -> bool;
}

#[cfg(unix)]
impl SocketPath for PathBuf {
    fn is_socket(&self) -> bool {
        use std::os::unix::fs::FileTypeExt as _;
        fs::metadata(self).is_ok_and(|metadata| metadata.file_type().is_socket())
    }
}
