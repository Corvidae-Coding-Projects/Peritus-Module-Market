use std::process::Command;

fn main() {
    let _ = Command::new("printf").arg("safe").status();
}
