pub mod backends;
mod config;
mod device;
mod key;

pub use crate::{config::*, device::*, key::*};

#[derive(Debug, Copy, Clone)]
pub enum Backend {
    Auto,
    #[cfg(target_os = "linux")]
    Kernel,
    Userspace,
}
pub struct Wireguard {
    backend: Backend,
}

impl Default for Wireguard {
    fn default() -> Self {
        Self {
            backend: Backend::Auto,
        }
    }
}

impl Wireguard {
    fn with_backend(backend: Backend) -> Self {
        Self { backend }
    }

    // /// Enumerates all WireGuard interfaces currently present in the system
    // /// and returns their names.
    // ///
    // /// You can use [`get_by_name`](DeviceInfo::get_by_name) to retrieve more
    // /// detailed information on each interface.
    // #[cfg(target_os = "linux")]
    // pub fn device_names() -> Result<Vec<InterfaceName>, std::io::Error> {
    //     match self.backend {
    //         Backend::Auto => backends::kernel::enumerate().or_else(|_| backends::userspace::enu)

    //     } else {
    //         backends::userspace::enumerate()
    //     }
    // }
}
