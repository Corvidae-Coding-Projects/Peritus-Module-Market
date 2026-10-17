//! Native plugin executable using Peritus's stable framed IPC SDK.
use peritus_plugin_sdk::*;
use serde_json::json;
use std::io::{Read, Write};
const FRAME: u32 = 32 * 1024 * 1024;
fn main() {
    if let Err(error) = serve() {
        eprintln!("deep-research: {error}");
        std::process::exit(1);
    }
}
fn serve() -> Result<(), Box<dyn std::error::Error>> {
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    let mut initialized = false;
    loop {
        let mut header = [0u8; 4];
        match stdin.read_exact(&mut header) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        let length = u32::from_be_bytes(header);
        if length == 0 || length > FRAME {
            return Err("invalid request frame length".into());
        }
        let mut frame = header.to_vec();
        frame.resize(length as usize + 4, 0);
        stdin.read_exact(&mut frame[4..])?;
        let request: PluginRequestEnvelope = decode_frame(&frame, FRAME)?;
        let shutdown = matches!(request.request, HostRequest::Shutdown);
        let response = match request.request {
            HostRequest::Initialize { plugin_id, plugin_version, .. }
                if plugin_id.as_str() == "peritus.deep-research"
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
                    let params: serde_json::Value = serde_json::from_str(
                        input.value()["params_json"].as_str().ok_or("missing params_json")?,
                    )?;
                    Ok(peritus_deep_research::dispatch(method, &params)?)
                })();
                let value = match result {
                    Ok(v) => json!({"json":v.to_string()}),
                    Err(e) => json!({"json":json!({"error":e.to_string()}).to_string()}),
                };
                PluginResponse::Success {
                    output: JsonPayload::new(value, JsonBounds::PRODUCTION)?,
                    rendering: None,
                }
            }
            HostRequest::Shutdown => PluginResponse::Status { status: PluginStatus::Stopped },
            HostRequest::Health => PluginResponse::Status { status: PluginStatus::Healthy },
            HostRequest::Cancel { .. } => {
                PluginResponse::Status { status: PluginStatus::Cancelled }
            }
            _ => PluginResponse::Failure(PluginFailure {
                class: FailureClass::InvalidInput,
                code: "native-plugin-request".into(),
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
            FRAME,
        )?)?;
        stdout.flush()?;
        if shutdown {
            return Ok(());
        }
    }
}
