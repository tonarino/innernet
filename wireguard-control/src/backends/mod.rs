#[cfg(target_os = "linux")]
pub mod kernel;

#[cfg(target_os = "openbsd")]
pub mod kernelopenbsd;

pub mod userspace;
