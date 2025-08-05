use wireguard_control::{Backend, Device};

#[cfg(target_os = "linux")]
const BACKEND: Backend = Backend::Kernel;
#[cfg(target_os = "openbsd")]
const BACKEND: Backend = Backend::OpenBSD;
#[cfg(not(any(target_os = "linux", target_os = "openbsd")))]
const BACKEND: Backend = Backend::Userspace;

fn main() {
    let devices = Device::list(BACKEND).unwrap();
    println!("{devices:?}");
}
