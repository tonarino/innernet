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
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            #[cfg(target_os = "linux")]
            "kernel" => Ok(Self::Kernel),
            "userspace" => Ok(Self::Userspace),
            _ => Err(std::io::ErrorKind::NotFound.into()),
        }
    }
}

impl Backend {
    pub fn variants() -> &'static [&'static str] {
        #[cfg(target_os = "linux")]
        {
            &["kernel", "userspace"]
        }

        #[cfg(not(target_os = "linux"))]
        {
            &["userspace"]
        }
    }
}
