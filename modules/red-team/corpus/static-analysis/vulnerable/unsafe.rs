use std::process::Command;
use time::Timespec;

fn main() {
    let _ = Command::new("sh").arg("-c").arg("echo unsafe").status();
    unsafe { std::ptr::read_volatile(&0_u8); }
    let _ = Timespec::new(0, 0);
}
