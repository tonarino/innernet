use crate::{Error, IoErrorContext, NetworkOpts, Peer, PeerDiff};
use ipnet::IpNet;
use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use wireguard_control::{
    Backend, Device, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder, PeerInfo,
};

#[cfg(target_os = "macos")]
fn cmd(bin: &str, args: &[&str]) -> Result<std::process::Output, io::Error> {
    let output = std::process::Command::new(bin).args(args).output()?;
    log::debug!("cmd: {} {}", bin, args.join(" "));
    log::debug!("status: {:?}", output.status.code());
    log::trace!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    log::trace!("stderr: {}", String::from_utf8_lossy(&output.stderr));
    if output.status.success() {
        Ok(output)
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "failed to run {} {} command: {}",
                bin,
                args.join(" "),
                String::from_utf8_lossy(&output.stderr)
            ),
        ))
    }
}

#[cfg(target_os = "macos")]
pub fn set_addr(interface: &InterfaceName, addr: IpNet) -> Result<(), io::Error> {
    let real_interface = wireguard_control::backends::userspace::resolve_tun(interface)?;

    if matches!(addr, IpNet::V4(_)) {
        cmd(
            "ifconfig",
            &[
                &real_interface,
                "inet",
                &addr.to_string(),
                &addr.addr().to_string(),
                "alias",
            ],
        )
        .map(|_output| ())
    } else {
        cmd(
            "ifconfig",
            &[&real_interface, "inet6", &addr.to_string(), "alias"],
        )
        .map(|_output| ())
    }
}

#[cfg(target_os = "macos")]
pub fn set_up(interface: &InterfaceName, mtu: u32) -> Result<(), io::Error> {
    let real_interface = wireguard_control::backends::userspace::resolve_tun(interface)?;
    cmd("ifconfig", &[&real_interface, "mtu", &mtu.to_string()])?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub use super::netlink::set_addr;

#[cfg(target_os = "linux")]
pub use super::netlink::set_up;

pub fn up(
    interface: &InterfaceName,
    private_key: &str,
    address: IpNet,
    listen_port: Option<u16>,
    peer: Option<(&str, IpAddr, SocketAddr)>,
    network: NetworkOpts,
) -> Result<(), io::Error> {
    let mut device = DeviceUpdate::new();
    if let Some((public_key, address, endpoint)) = peer {
        let prefix = if address.is_ipv4() { 32 } else { 128 };
        let peer_config = PeerConfigBuilder::new(
            &wireguard_control::Key::from_base64(public_key).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "failed to parse base64 public key",
                )
            })?,
        )
        .add_allowed_ip(address, prefix)
        .set_persistent_keepalive_interval(25)
        .set_endpoint(endpoint);
        device = device.add_peer(peer_config);
    }
    if let Some(listen_port) = listen_port {
        device = device.set_listen_port(listen_port);
    }
    device
        .set_private_key(wireguard_control::Key::from_base64(private_key).unwrap())
        .apply(interface, network.backend)?;
    set_addr(interface, address)?;
    set_up(
        interface,
        network.mtu.unwrap_or(if matches!(address, IpNet::V4(_)) {
            1420
        } else {
            1400
        }),
    )?;
    if !network.no_routing {
        add_route(interface, address)?;
    }
    Ok(())
}

pub fn set_listen_port(
    interface: &InterfaceName,
    listen_port: Option<u16>,
    backend: Backend,
) -> Result<(), Error> {
    let mut device = DeviceUpdate::new();
    if let Some(listen_port) = listen_port {
        device = device.set_listen_port(listen_port);
    } else {
        device = device.randomize_listen_port();
    }
    device.apply(interface, backend)?;

    Ok(())
}

pub fn down(interface: &InterfaceName, backend: Backend) -> Result<(), Error> {
    Ok(Device::get(interface, backend)
        .with_str(interface.as_str_lossy())?
        .delete()
        .with_str(interface.as_str_lossy())?)
}

/// Add a route in the OS's routing table to get traffic flowing through this interface.
/// Returns an error if the process doesn't exit successfully, otherwise returns
/// true if the route was changed, false if the route already exists.
#[cfg(target_os = "macos")]
pub fn add_route(interface: &InterfaceName, cidr: IpNet) -> Result<bool, io::Error> {
    let real_interface = wireguard_control::backends::userspace::resolve_tun(interface)?;
    let output = cmd(
        "route",
        &[
            "-n",
            "add",
            if matches!(cidr, IpNet::V4(_)) {
                "-inet"
            } else {
                "-inet6"
            },
            &cidr.to_string(),
            "-interface",
            &real_interface,
        ],
    )?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "failed to add route for device {} ({}): {}",
                &interface, real_interface, stderr
            ),
        ))
    } else {
        Ok(!stderr.contains("File exists"))
    }
}

#[cfg(target_os = "linux")]
pub use super::netlink::add_route;

pub trait DeviceExt {
    /// Diff the output of a wgctrl device with a list of server-reported peers.
    fn diff<'a>(&'a self, peers: &'a [Peer]) -> Vec<PeerDiff<'a>>;

    // /// Get a peer by their public key, a helper function.
    fn get_peer(&self, public_key: &str) -> Option<&PeerInfo>;
}

impl DeviceExt for Device {
    fn diff<'a>(&'a self, peers: &'a [Peer]) -> Vec<PeerDiff<'a>> {
        let interface_public_key = self
            .public_key
            .as_ref()
            .map(|k| k.to_base64())
            .unwrap_or_default();
        let existing_peers = &self.peers;

        // Match existing peers (by pubkey) to new peer information from the server.
        let modifications = peers.iter().filter_map(|peer| {
            if peer.is_disabled || peer.public_key == interface_public_key {
                None
            } else {
                let existing_peer = existing_peers
                    .iter()
                    .find(|p| p.config.public_key.to_base64() == peer.public_key);
                PeerDiff::new(existing_peer, Some(peer)).unwrap()
            }
        });

        // Remove any peers on the interface that aren't in the server's peer list any more.
        let removals = existing_peers.iter().filter_map(|existing| {
            let public_key = existing.config.public_key.to_base64();
            if peers.iter().any(|p| p.public_key == public_key) {
                None
            } else {
                PeerDiff::new(Some(existing), None).unwrap()
            }
        });

        modifications.chain(removals).collect::<Vec<_>>()
    }

    fn get_peer(&self, public_key: &str) -> Option<&PeerInfo> {
        Key::from_base64(public_key)
            .ok()
            .and_then(|key| self.peers.iter().find(|peer| peer.config.public_key == key))
    }
}

pub trait PeerInfoExt {
    /// WireGuard rejects any communication after REJECT_AFTER_TIME, so we can use this
    /// as a heuristic for "currentness" without relying on heavier things like ICMP.
    fn is_recently_connected(&self) -> bool;
}
impl PeerInfoExt for PeerInfo {
    fn is_recently_connected(&self) -> bool {
        const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);

        let last_handshake = self
            .stats
            .last_handshake_time
            .and_then(|t| t.elapsed().ok())
            .unwrap_or(Duration::MAX);

        last_handshake <= REJECT_AFTER_TIME
    }
}
