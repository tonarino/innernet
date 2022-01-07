use wireguard_control::{Backend, Device};


#[cfg(target_os = "linux")]
const BACKEND: Backend = Backend::Kernel;
#[cfg(not(target_os = "linux"))]
const BACKEND: Backend = Backend::Userspace;

fn main() {
    let devices = Device::list(BACKEND).unwrap();
    println!("{:?}", devices);
}
