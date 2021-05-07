use colored::*;
use lazy_static::lazy_static;
use std::{
    fmt::Display,
    fs::{self, File},
    io,
    os::unix::fs::PermissionsExt,
    path::Path,
    str::FromStr,
    time::Duration,
};

pub mod interface_config;
pub mod prompts;
pub mod types;
pub mod wg;

pub use types::*;

lazy_static! {
    pub static ref CLIENT_CONFIG_PATH: &'static Path = Path::new("/etc/innernet");
    pub static ref CLIENT_DATA_PATH: &'static Path = Path::new("/var/lib/innernet");
    pub static ref SERVER_CONFIG_DIR: &'static Path = Path::new("/etc/innernet-server");
    pub static ref SERVER_DATABASE_DIR: &'static Path = Path::new("/var/lib/innernet-server");
    pub static ref REDEEM_TRANSITION_WAIT: Duration = Duration::from_secs(5);
}

pub const PERSISTENT_KEEPALIVE_INTERVAL_SECS: u16 = 25;
pub const INNERNET_PUBKEY_HEADER: &str = "X-Innernet-Server-Key";

pub type Error = Box<dyn std::error::Error>;

pub static WG_MANAGE_DIR: &str = "/etc/innernet";
pub static WG_DIR: &str = "/etc/wireguard";

pub fn ensure_dirs_exist(dirs: &[&Path]) -> Result<(), Error> {
    for dir in dirs {
        match fs::create_dir(dir) {
            Err(e) if e.kind() != io::ErrorKind::AlreadyExists => {
                return Err(e.into());
            },
            _ => {
                let target_file = File::open(dir).with_path(dir)?;
                if chmod(&target_file, 0o700)? {
                    println!(
                        "{} updated permissions for {} to 0700.",
                        "[!]".yellow(),
                        dir.display()
                    );
                }
            },
        }
    }
    Ok(())
}

/// Updates the permissions of a file or directory. Returns `Ok(true)` if
/// permissions had to be changed, `Ok(false)` if permissions were already
/// correct.
pub fn chmod(file: &File, new_mode: u32) -> Result<bool, Error> {
    let metadata = file.metadata()?;
    let mut permissions = metadata.permissions();
    let mode = permissions.mode() & 0o777;
    let updated = if mode != new_mode {
        permissions.set_mode(new_mode);
        file.set_permissions(permissions)?;
        true
    } else {
        false
    };

    Ok(updated)
}

#[derive(Clone, Debug, PartialEq)]
pub struct Timestring {
    timestring: String,
    seconds: u64,
}

impl Display for Timestring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.timestring)
    }
}

impl FromStr for Timestring {
    type Err = &'static str;

    fn from_str(timestring: &str) -> Result<Self, Self::Err> {
        if timestring.len() < 2 {
            Err("timestring isn't long enough!".into())
        } else {
            let (n, suffix) = timestring.split_at(timestring.len() - 1);
            let n: u64 = n.parse().map_err(|_| "invalid timestring (a number followed by a time unit character, eg. '15m')")?;
            let multiplier = match suffix {
                "s" => Ok(1),
                "m" => Ok(60),
                "h" => Ok(60 * 60),
                "d" => Ok(60 * 60 * 24),
                "w" => Ok(60 * 60 * 24 * 7),
                _ => Err("invalid timestring suffix (must be one of 's', 'm', 'h', 'd', or 'w')"),
            }?;

            Ok(Self {
                timestring: timestring.to_string(),
                seconds: n * multiplier,
            })
        }
    }
}

impl From<Timestring> for Duration {
    fn from(timestring: Timestring) -> Self {
        Duration::from_secs(timestring.seconds)
    }
}
