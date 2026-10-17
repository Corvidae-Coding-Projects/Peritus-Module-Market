//! Native Rust Deep Research implementation. Peritus supplies generic host services only.
mod coordinator;
mod definitions;
pub mod ledger;
pub use coordinator::dispatch;
pub use ledger::Research;
use sha2::{Digest, Sha256};
use std::{fs, io::Write, path::Path};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(String),
    #[error("research storage: {0}")]
    Io(#[from] std::io::Error),
    #[error("research JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("research configuration: {0}")]
    Toml(#[from] toml::de::Error),
}
fn invalid(s: impl Into<String>) -> Error {
    Error::Invalid(s.into())
}
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}
fn publish(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let parent = path.parent().ok_or_else(|| invalid("state path needs a parent"))?;
    fs::create_dir_all(parent)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|e| e.error)?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
