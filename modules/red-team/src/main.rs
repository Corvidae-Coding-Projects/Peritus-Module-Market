//! Native Red Team module executable using Peritus's framed IPC contract.

use peritus_plugin_sdk::{
    FailureClass, HostRequest, JsonBounds, JsonPayload, PluginFailure, PluginRequestEnvelope,
    PluginResponse, PluginResponseEnvelope, PluginStatus, decode_frame, encode_frame,
};
use serde_json::json;
use std::io::{Read, Write};

const FRAME_BYTES: u32 = 32 * 1024 * 1024;

fn main() {
    let result =
        if std::env::args().nth(1).as_deref() == Some("worker") { worker() } else { serve() };
    if let Err(error) = result {
        eprintln!("red-team: {error}");
        std::process::exit(1);
    }
}

fn worker() -> Result<(), Box<dyn std::error::Error>> {
    let name = std::env::args().nth(2).ok_or("worker name is required")?;
    let mut bytes = Vec::new();
    std::io::stdin().read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err("worker input exceeds 1 MiB".into());
    }
    let input = serde_json::from_slice(&bytes)?;
    let output = peritus_red_team::run_worker(&name, input)?;
    serde_json::to_writer(std::io::stdout().lock(), &output)?;
    Ok(())
}

fn serve() -> Result<(), Box<dyn std::error::Error>> {
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    let mut initialized = false;

    loop {
        let mut header = [0_u8; 4];
        match stdin.read_exact(&mut header) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        let length = u32::from_be_bytes(header);
        if length == 0 || length > FRAME_BYTES {
            return Err("invalid request frame length".into());
        }
        let mut frame = header.to_vec();
        frame.resize(length as usize + 4, 0);
        stdin.read_exact(&mut frame[4..])?;
        let request: PluginRequestEnvelope = decode_frame(&frame, FRAME_BYTES)?;
        let shutdown = matches!(request.request, HostRequest::Shutdown);
        let response = match request.request {
            HostRequest::Initialize { plugin_id, plugin_version, .. }
                if plugin_id.as_str() == "peritus.red-team"
                    && plugin_version.to_string() == env!("CARGO_PKG_VERSION") =>
            {
                initialized = true;
                PluginResponse::Status { status: PluginStatus::Ready }
            }
            HostRequest::Invoke { capability, input, .. }
                if initialized && capability == "module.workflow" =>
            {
                let result = (|| -> Result<serde_json::Value, Box<dyn std::error::Error>> {
                    let method = input.value()["method"].as_str().ok_or("missing method")?;
                    let parameters: serde_json::Value = serde_json::from_str(
                        input.value()["params_json"].as_str().ok_or("missing params_json")?,
                    )?;
                    Ok(peritus_red_team::dispatch(method, &parameters)?)
                })();
                let value = match result {
                    Ok(value) => json!({"json":value.to_string()}),
                    Err(error) => json!({"json":json!({"error":error.to_string()}).to_string()}),
                };
                PluginResponse::Success {
                    output: JsonPayload::new(value, JsonBounds::PRODUCTION)?,
                    rendering: None,
                }
            }
            HostRequest::Health => PluginResponse::Status { status: PluginStatus::Healthy },
            HostRequest::Cancel { .. } => {
                PluginResponse::Status { status: PluginStatus::Cancelled }
            }
            HostRequest::Shutdown => PluginResponse::Status { status: PluginStatus::Stopped },
            _ => PluginResponse::Failure(PluginFailure {
                class: FailureClass::InvalidInput,
                code: "red-team-native-request".into(),
                detail:
                    "unsupported request or identity; initialize this exact native plugin first"
                        .into(),
                retryable_with_new_action: true,
            }),
        };
        stdout.write_all(&encode_frame(
            &PluginResponseEnvelope {
                protocol_version: 1,
                request_id: request.request_id,
                response,
            },
            FRAME_BYTES,
        )?)?;
        stdout.flush()?;
        if shutdown {
            return Ok(());
        }
    }
}
