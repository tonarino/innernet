pub use anyhow::Error;
use std::{
    fs::{self, File, Permissions},
    io,
    net::{IpAddr, Ipv6Addr},
    os::unix::fs::PermissionsExt,
    path::Path,
    time::Duration,
};

pub mod interface_config;
#[cfg(target_os = "linux")]
mod netlink;
pub mod prompts;
pub mod types;
pub mod wg;

pub use types::*;

pub const REDEEM_TRANSITION_WAIT: Duration = Duration::from_secs(5);
pub const PERSISTENT_KEEPALIVE_INTERVAL_SECS: u16 = 25;
pub const INNERNET_PUBKEY_HEADER: &str = "X-Innernet-Server-Key";

pub fn ensure_dirs_exist(dirs: &[&Path]) -> Result<(), WrappedIoError> {
    for dir in dirs {
        match fs::create_dir(dir).with_path(dir) {
            Ok(()) => {
                log::debug!("created dir {}", dir.to_string_lossy());
                std::fs::set_permissions(dir, Permissions::from_mode(0o700)).with_path(dir)?;
            },
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                warn_on_dangerous_mode(dir).with_path(dir)?;
            },
            Err(e) => {
                return Err(e);
            },
        }
    }
    Ok(())
}

pub fn warn_on_dangerous_mode(path: &Path) -> Result<(), io::Error> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    let permissions = metadata.permissions();
    let mode = permissions.mode() & 0o777;

    if mode & 0o007 != 0 {
        log::warn!(
            "{} is world-accessible (mode is {:#05o}). This is probably not what you want.",
            path.to_string_lossy(),
            mode
        );
    }
    Ok(())
}

/// Updates the permissions of a file or directory. Returns `Ok(true)` if
/// permissions had to be changed, `Ok(false)` if permissions were already
/// correct.
pub fn chmod(file: &File, new_mode: u32) -> Result<bool, io::Error> {
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

#[cfg(target_os = "macos")]
pub fn _get_local_addrs() -> Result<impl Iterator<Item = std::net::IpAddr>, io::Error> {
    use nix::{net::if_::InterfaceFlags, sys::socket::SockAddr};

    let addrs = nix::ifaddrs::getifaddrs()?
        .filter(|addr| {
            addr.flags.contains(InterfaceFlags::IFF_UP)
                && !addr.flags.intersects(
                    InterfaceFlags::IFF_LOOPBACK
                        | InterfaceFlags::IFF_POINTOPOINT
                        | InterfaceFlags::IFF_PROMISC,
                )
        })
        .filter_map(|addr| match addr.address {
            Some(SockAddr::Inet(addr)) => Some(addr.to_std().ip()),
            _ => None,
        });

    Ok(addrs)
}

#[cfg(target_os = "linux")]
pub use netlink::get_local_addrs as _get_local_addrs;

pub fn get_local_addrs() -> Result<impl Iterator<Item = std::net::IpAddr>, io::Error> {
    // TODO(jake): this is temporary pending the stabilization of rust-lang/rust#27709
    fn is_unicast_global(ip: &Ipv6Addr) -> bool {
        !((ip.segments()[0] & 0xff00) == 0xff00 // multicast
            || ip.is_loopback()
            || ip.is_unspecified()
            || ((ip.segments()[0] == 0x2001) && (ip.segments()[1] == 0xdb8)) // documentation
            || (ip.segments()[0] & 0xffc0) == 0xfe80 // unicast link local
            || (ip.segments()[0] & 0xfe00) == 0xfc00) // unicast local
    }

    Ok(_get_local_addrs()?
        .filter(|ip| {
            ip.is_ipv4()
                || matches!(ip,
            IpAddr::V6(v6) if is_unicast_global(v6))
        })
        .take(10))
}
