use crate::{backends, key::Key};

use std::{
    net::{IpAddr, SocketAddr},
    time::SystemTime,
};

/// Represents an IP address a peer is allowed to have, in CIDR notation.
///
/// This may have unexpected semantics - refer to the
/// [WireGuard documentation](https://www.wireguard.com/#cryptokey-routing)
/// for more information on how routing is implemented.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AllowedIp {
    /// The IP address.
    pub address: IpAddr,
    /// The CIDR subnet mask.
    pub cidr: u8,
}

impl std::str::FromStr for AllowedIp {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = s.split('/').collect();
        if parts.len() != 2 {
            return Err(());
        }

        Ok(AllowedIp {
            address: parts[0].parse().map_err(|_| ())?,
            cidr: parts[1].parse().map_err(|_| ())?,
        })
    }
}

/// Represents a single peer's configuration (i.e. persistent attributes).
///
/// These are the attributes that don't change over time and are part of the configuration.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PeerConfig {
    /// The public key of the peer.
    pub public_key: Key,
    /// The preshared key available to both peers (`None` means no PSK is used).
    pub preshared_key: Option<Key>,
    /// The endpoint this peer listens for connections on (`None` means any).
    pub endpoint: Option<SocketAddr>,
    /// The interval for sending keepalive packets (`None` means disabled).
    pub persistent_keepalive_interval: Option<u16>,
    /// The IP addresses this peer is allowed to have.
    pub allowed_ips: Vec<AllowedIp>,
    pub(crate) __cant_construct_me: (),
}

/// Represents a single peer's current statistics (i.e. the data from the current session).
///
/// These are the attributes that will change over time; to update them,
/// re-read the information from the interface.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PeerStats {
    /// Time of the last handshake/rekey with this peer.
    pub last_handshake_time: Option<SystemTime>,
    /// Number of bytes received from this peer.
    pub rx_bytes: u64,
    /// Number of bytes transmitted to this peer.
    pub tx_bytes: u64,
    pub(crate) __cant_construct_me: (),
}

/// Represents the complete status of a peer.
///
/// This struct simply combines [`PeerInfo`](PeerInfo) and [`PeerStats`](PeerStats)
/// to represent all available information about a peer.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PeerInfo {
    pub config: PeerConfig,
    pub stats: PeerStats,
}

/// Represents all available information about a WireGuard device (interface).
///
/// This struct contains the current configuration of the device
/// and the current configuration _and_ state of all of its peers.
/// The peer statistics are retrieved once at construction time,
/// and need to be updated manually by calling [`get_by_name`](DeviceInfo::get_by_name).
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DeviceInfo {
    /// The interface name of this device
    pub name: String,
    /// The public encryption key of this interface (if present)
    pub public_key: Option<Key>,
    /// The private encryption key of this interface (if present)
    pub private_key: Option<Key>,
    /// The [fwmark](https://www.linux.org/docs/man8/tc-fw.html) of this interface
    pub fwmark: Option<u32>,
    /// The port to listen for incoming connections on
    pub listen_port: Option<u16>,
    /// The list of all registered peers and their information
    pub peers: Vec<PeerInfo>,
    /// The associated "real name" of the interface (ex. "utun8" on macOS).
    pub linked_name: Option<String>,

    pub(crate) __cant_construct_me: (),
}

impl DeviceInfo {
    /// Enumerates all WireGuard interfaces currently present in the system
    /// and returns their names.
    ///
    /// You can use [`get_by_name`](DeviceInfo::get_by_name) to retrieve more
    /// detailed information on each interface.
    #[cfg(target_os = "linux")]
    pub fn enumerate() -> Result<Vec<String>, std::io::Error> {
        if backends::kernel::exists() {
            backends::kernel::enumerate()
        } else {
            backends::userspace::enumerate()
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn enumerate() -> Result<Vec<String>, std::io::Error> {
        crate::backends::userspace::enumerate()
    }

    #[cfg(target_os = "linux")]
    pub fn get_by_name(name: &str) -> Result<Self, std::io::Error> {
        if backends::kernel::exists() {
            backends::kernel::get_by_name(name)
        } else {
            backends::userspace::get_by_name(name)
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn get_by_name(name: &str) -> Result<Self, std::io::Error> {
        backends::userspace::get_by_name(name)
    }

    #[cfg(target_os = "linux")]
    pub fn delete(self) -> Result<(), std::io::Error> {
        backends::kernel::delete_interface(&self.name)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn delete(self) -> Result<(), std::io::Error> {
        backends::userspace::delete_interface(&self.name)
    }
}

#[cfg(test)]
mod tests {
    use crate::{DeviceConfigBuilder, KeyPair, PeerConfigBuilder};

    const TEST_INTERFACE: &str = "wgctrl-test";
    use super::*;

    #[test]
    fn test_add_peers() {
        if unsafe { libc::getuid() } != 0 {
            return;
        }

        let keypairs: Vec<_> = (0..10).map(|_| KeyPair::generate()).collect();
        let mut builder = DeviceConfigBuilder::new();
        for keypair in &keypairs {
            builder = builder.add_peer(PeerConfigBuilder::new(&keypair.public))
        }
        builder.apply(TEST_INTERFACE).unwrap();

        let device = DeviceInfo::get_by_name(TEST_INTERFACE).unwrap();

        for keypair in &keypairs {
            assert!(device
                .peers
                .iter()
                .any(|p| p.config.public_key == keypair.public));
        }

        device.delete().unwrap();
    }
}
