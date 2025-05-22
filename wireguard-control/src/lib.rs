pub mod backends;
mod config;
mod device;
mod key;

use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

pub use crate::{config::*, device::*, key::*};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    #[cfg(target_os = "linux")]
    Kernel,
    #[cfg(target_os = "openbsd")]
    KernelOpenBSD,
    Userspace,
}

impl Default for Backend {
    fn default() -> Self {
        #[cfg(target_os = "linux")]
        {
            Self::Kernel
        }
        #[cfg(target_os = "openbsd")]
        {
            Self::KernelOpenBSD;
        }

        #[cfg(not(target_os = "linux"))]
        {
            Self::Userspace
        }
    }
}

impl Display for Backend {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(target_os = "linux")]
            Self::Kernel => write!(f, "kernel"),
            #[cfg(target_os = "openbsd")]
            Self::KernelOpenBSD => write!(f, "kernel"),
            Self::Userspace => write!(f, "userspace"),
        }
    }
}

impl FromStr for Backend {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            #[cfg(target_os = "linux")]
            "kernel" => Ok(Self::Kernel),
            #[cfg(target_os = "openbsd")]
            "kernel" => Ok(Self::KernelOpenBSD),
            "userspace" => Ok(Self::Userspace),
            _ => Err(format!("valid values: {}.", Self::variants().join(", "))),
        }
    }
}

impl Backend {
    pub fn variants() -> &'static [&'static str] {
        #[cfg(any(target_os = "linux", target_os = "openbsd"))]
        {
            &["kernel", "userspace"]
        }
        #[cfg(not(any(target_os = "linux", target_os = "openbsd")))]
        {
            &["userspace"]
        }
    }
}
