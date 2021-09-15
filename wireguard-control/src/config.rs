use crate::{
    device::{AllowedIp, PeerConfig},
    key::Key,
};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Builds and represents a single peer in a WireGuard interface configuration.
///
/// Note that if a peer with that public key already exists on the interface,
/// the settings specified here will be applied _on top_ of the existing settings,
/// similarly to interface-wide settings.
///
/// If this is not what you want, use [`DeviceConfigBuilder::replace_peers`](DeviceConfigBuilder::replace_peers)
/// to replace all peer settings on the interface, or use
/// [`DeviceConfigBuilder::remove_peer_by_key`](DeviceConfigBuilder::remove_peer_by_key) first
/// to remove the peer from the interface, and then apply a second configuration to re-add it.
///
/// # Example
/// ```rust
/// # use wireguard_control::*;
/// # use std::net::AddrParseError;
/// # fn try_main() -> Result<(), AddrParseError> {
/// let peer_keypair = KeyPair::generate();
///
/// // create a new peer and allow it to connect from 192.168.1.2
/// let peer = PeerConfigBuilder::new(&peer_keypair.public)
///     .replace_allowed_ips()
///     .add_allowed_ip("192.168.1.2".parse()?, 32);
///
/// // update our existing configuration with the new peer
/// DeviceUpdate::new().add_peer(peer).apply(&"wg-example".parse().unwrap(), Backend::Userspace);
///
/// println!("Send these keys to your peer: {:#?}", peer_keypair);
///
/// # Ok(())
/// # }
/// # fn main() { try_main(); }
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PeerConfigBuilder {
    pub(crate) public_key: Key,
    pub(crate) preshared_key: Option<Key>,
    pub(crate) endpoint: Option<SocketAddr>,
    pub(crate) persistent_keepalive_interval: Option<u16>,
    pub(crate) allowed_ips: Vec<AllowedIp>,
    pub(crate) replace_allowed_ips: bool,
    pub(crate) remove_me: bool,
}

impl PeerConfigBuilder {
    /// Creates a new `PeerConfigBuilder` that does nothing when applied.
    pub fn new(public_key: &Key) -> Self {
        PeerConfigBuilder {
            public_key: public_key.clone(),
            preshared_key: None,
            endpoint: None,
            persistent_keepalive_interval: None,
            allowed_ips: vec![],
            replace_allowed_ips: false,
            remove_me: false,
        }
    }

    pub fn into_peer_config(self) -> PeerConfig {
        PeerConfig {
            public_key: self.public_key,
            preshared_key: self.preshared_key,
            endpoint: self.endpoint,
            persistent_keepalive_interval: self.persistent_keepalive_interval,
            allowed_ips: self.allowed_ips,
            __cant_construct_me: (),
        }
    }

    /// The public key used in this builder.
    pub fn public_key(&self) -> &Key {
        &self.public_key
    }

    /// Creates a `PeerConfigBuilder` from a [`PeerConfig`](PeerConfig).
    ///
    /// This is mostly a convenience method for cases when you want to copy
    /// some or most of the existing peer configuration to a new configuration.
    ///
    /// This returns a `PeerConfigBuilder`, so you can still call any methods
    /// you need to override the imported settings.
    pub fn from_peer_config(config: PeerConfig) -> Self {
        let mut builder = Self::new(&config.public_key);
        if let Some(k) = config.preshared_key {
            builder = builder.set_preshared_key(k);
        }
        if let Some(e) = config.endpoint {
            builder = builder.set_endpoint(e);
        }
        if let Some(k) = config.persistent_keepalive_interval {
            builder = builder.set_persistent_keepalive_interval(k);
        }
        builder
            .replace_allowed_ips()
            .add_allowed_ips(&config.allowed_ips)
    }

    /// Specifies a preshared key to be set for this peer.
    pub fn set_preshared_key(mut self, key: Key) -> Self {
        self.preshared_key = Some(key);
        self
    }

    /// Specifies that this peer's preshared key should be unset.
    pub fn unset_preshared_key(self) -> Self {
        self.set_preshared_key(Key::zero())
    }

    /// Specifies an exact endpoint that this peer should be allowed to connect from.
    pub fn set_endpoint(mut self, address: SocketAddr) -> Self {
        self.endpoint = Some(address);
        self
    }

    /// Specifies the interval between keepalive packets to be sent to this peer.
    pub fn set_persistent_keepalive_interval(mut self, interval: u16) -> Self {
        self.persistent_keepalive_interval = Some(interval);
        self
    }

    /// Specifies that this peer does not require keepalive packets.
    pub fn unset_persistent_keepalive(self) -> Self {
        self.set_persistent_keepalive_interval(0)
    }

    /// Specifies an IP address this peer will be allowed to connect from/to.
    ///
    /// See [`AllowedIp`](AllowedIp) for details. This method can be called
    /// more than once, and all IP addresses will be added to the configuration.
    pub fn add_allowed_ip(mut self, address: IpAddr, cidr: u8) -> Self {
        self.allowed_ips.push(AllowedIp { address, cidr });
        self
    }

    /// Specifies multiple IP addresses this peer will be allowed to connect from/to.
    ///
    /// See [`AllowedIp`](AllowedIp) for details. This method can be called
    /// more than once, and all IP addresses will be added to the configuration.
    pub fn add_allowed_ips(mut self, ips: &[AllowedIp]) -> Self {
        self.allowed_ips.extend_from_slice(ips);
        self
    }

    /// Specifies this peer should be allowed to connect to all IP addresses.
    ///
    /// This is a convenience method for cases when you want to connect to a server
    /// that all traffic should be routed through.
    pub fn allow_all_ips(self) -> Self {
        self.add_allowed_ip(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)
            .add_allowed_ip(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), 0)
    }

    /// Specifies that the allowed IP addresses in this configuration should replace
    /// the existing configuration of the interface, not be appended to it.
    pub fn replace_allowed_ips(mut self) -> Self {
        self.replace_allowed_ips = true;
        self
    }

    /// Mark peer for removal from interface.
    pub fn remove(mut self) -> Self {
        self.remove_me = true;
        self
    }
}
