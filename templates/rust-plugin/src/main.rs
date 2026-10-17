//! Native plugin executable using Peritus's stable framed IPC SDK.
use peritus_plugin_sdk::*;
use serde_json::json;
use std::io::{Read, Write};
const FRAME: u32 = 32 * 1024 * 1024;
fn main() {
    if let Err(error) = serve() {
        eprintln!("counter: {error}");
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
                if plugin_id.as_str() == "example.counter"
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
                    Ok(dispatch(method, &params)?)
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

// Native feature code. Replace this coordinator and functions with your extension.
fn dispatch(
    method: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let result = match method {
        "command" => {
            let command = params["text"].as_str().unwrap_or_default();
            if let Some(text) = command.strip_prefix("count ") {
                ModuleAction::Reply {
                    text: count(text).to_string(),
                    actions: vec![],
                    attachment: None,
                }
            } else if let Some(text) = command.strip_prefix("ask ") {
                ModuleAction::Model{request:ModuleAgentRequest{key:"counter-agent".into(),role:"writer".into(),status:"Counter plugin · explaining text statistics".into(),system:"Call text_count with the exact requested text, then explain its observed Unicode scalar and whitespace-delimited word counts briefly. No edits or commands.".into(),prompt:text.into(),tools:vec![],functions:vec![ModuleFunction{name:"text_count".into(),description:"Compute text statistics in this native Rust plugin.".into(),schema:json!({"type":"object","properties":{"text":{"type":"string"}},"required":["text"],"additionalProperties":false})}]}}
            } else {
                ModuleAction::Reply{text:"Native Rust counter: count TEXT executes plugin code; ask TEXT lets an agent call the plugin's text_count function.".into(),actions:vec![ModuleMenuAction{label:"Count text".into(),arguments:"count ".into(),submit:false},ModuleMenuAction{label:"Ask an agent".into(),arguments:"ask ".into(),submit:false}],attachment:None}
            }
        }
        "tool" => {
            if params["name"] != "text_count" {
                return Err("unknown plugin function".into());
            }
            let args: serde_json::Value = serde_json::from_str(
                params["arguments_json"].as_str().ok_or("missing arguments")?,
            )?;
            return Ok(count(args["text"].as_str().ok_or("missing text")?));
        }
        "model_result" => ModuleAction::Reply {
            text: params["text"].as_str().unwrap_or_default().into(),
            actions: vec![],
            attachment: None,
        },
        "observe" => return Ok(json!({"recorded":true})),
        _ => return Err("unsupported service".into()),
    };
    Ok(serde_json::to_value(result)?)
}
fn count(text: &str) -> serde_json::Value {
    json!({"unicode_scalars":text.chars().count(),"words":text.split_whitespace().count(),"utf8_bytes":text.len()})
}
