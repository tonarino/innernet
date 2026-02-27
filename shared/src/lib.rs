use colored::Colorize;
use hostsfile::HostsBuilder;
use ipnet::IpNet;
use std::{
    fs::{self, File, Permissions},
    io,
    net::{IpAddr, Ipv6Addr},
    os::unix::fs::PermissionsExt,
    path::Path,
    time::Duration,
};
use wireguard_control::InterfaceName;

pub mod interface_config;
#[cfg(target_os = "linux")]
mod netlink;
pub mod peer;
pub mod prompts;
pub mod types;
pub mod wg;

pub use anyhow::Error;
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

#[cfg(any(target_os = "macos", target_os = "openbsd"))]
pub fn _get_local_addrs() -> Result<impl Iterator<Item = std::net::IpAddr>, io::Error> {
    use std::net::Ipv4Addr;

    use nix::net::if_::InterfaceFlags;

    let addrs = nix::ifaddrs::getifaddrs()?
        .filter(|addr| {
            addr.flags.contains(InterfaceFlags::IFF_UP)
                && !addr.flags.intersects(
                    InterfaceFlags::IFF_LOOPBACK
                        | InterfaceFlags::IFF_POINTOPOINT
                        | InterfaceFlags::IFF_PROMISC,
                )
        })
        .filter_map(|interface_addr| {
            interface_addr.address.and_then(|addr| {
                if let Some(sockaddr_in) = addr.as_sockaddr_in() {
                    Some(IpAddr::V4(Ipv4Addr::from(sockaddr_in.ip())))
                } else {
                    addr.as_sockaddr_in6()
                        .map(|sockaddr_in6| IpAddr::V6(sockaddr_in6.ip()))
                }
            })
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

pub trait IpNetExt {
    fn is_assignable(&self, ip: &IpAddr) -> bool;
}

impl IpNetExt for IpNet {
    fn is_assignable(&self, ip: &IpAddr) -> bool {
        self.contains(ip)
            && match self {
                IpNet::V4(_) => {
                    self.prefix_len() >= 31 || (ip != &self.network() && ip != &self.broadcast())
                },
                IpNet::V6(_) => self.prefix_len() >= 127 || ip != &self.network(),
            }
    }
}

pub fn update_hosts_file(
    interface: &InterfaceName,
    opts: &HostsOpts,
    peers: impl IntoIterator<Item = impl AsRef<Peer>>,
) -> Result<(), WrappedIoError> {
    if opts.no_write_hosts {
        return Ok(());
    }

    let mut hosts_builder = HostsBuilder::new(format!("innernet {interface}"));
    for peer in peers {
        let peer = peer.as_ref();
        let peer_hostname = if let Some(suffix) = &opts.host_suffix {
            if suffix.is_empty() {
                peer.contents.name.to_string()
            } else {
                format!("{}.{}", peer.contents.name, suffix)
            }
        } else {
            format!("{}.{}.wg", peer.contents.name, interface)
        };
        hosts_builder.add_hostname(peer.contents.ip, peer_hostname);
    }
    match hosts_builder
        .write_to(opts.hosts_path.as_path())
        .with_path(opts.hosts_path.as_path())
    {
        Ok(has_written) if has_written => {
            log::info!(
                "updated {} with the latest peers.",
                opts.hosts_path.to_string_lossy().yellow()
            )
        },
        Ok(_) => {},
        Err(e) => log::warn!("failed to update hosts ({})", e),
    };

    Ok(())
}
