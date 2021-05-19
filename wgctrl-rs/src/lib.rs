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
    Userspace,
}

impl Default for Backend {
    fn default() -> Self {
        #[cfg(target_os = "linux")]
        {
            Self::Kernel
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
            Self::Userspace => write!(f, "userspace"),
        }
    }
}

impl FromStr for Backend {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            #[cfg(target_os = "linux")]
            "kernel" => Ok(Self::Kernel),
            "userspace" => Ok(Self::Userspace),
            _ => Err("Not a valid backend. Must be either 'kernel' or 'wireguard'."),
        }
    }
}
