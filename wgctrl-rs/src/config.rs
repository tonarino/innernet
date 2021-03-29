use crate::{
    backends,
    device::{AllowedIp, PeerConfig},
    key::{Key, KeyPair},
};

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

/// Builds and represents a configuration that can be applied to a WireGuard interface.
///
/// This is the primary way of changing the settings of an interface.
///
/// Note that if an interface exists, the configuration is applied _on top_ of the existing
/// settings, and missing parts are not overwritten or set to defaults.
///
/// If this is not what you want, use [`delete_interface`](delete_interface)
/// to remove the interface entirely before applying the new configuration.
///
/// # Example
/// ```rust
/// # use wgctrl::*;
/// # use std::net::AddrParseError;
/// # fn try_main() -> Result<(), AddrParseError> {
/// let our_keypair = KeyPair::generate();
/// let peer_keypair = KeyPair::generate();
/// let server_addr = "192.168.1.1:51820".parse()?;
///
/// DeviceConfigBuilder::new()
///     .set_keypair(our_keypair)
///     .replace_peers()
///     .add_peer_with(&peer_keypair.public, |peer| {
///         peer.set_endpoint(server_addr)
///             .replace_allowed_ips()
///             .allow_all_ips()
///     }).apply("wg-example");
///
/// println!("Send these keys to your peer: {:#?}", peer_keypair);
///
/// # Ok(())
/// # }
/// # fn main() { try_main(); }
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DeviceConfigBuilder {
    pub(crate) public_key: Option<Key>,
    pub(crate) private_key: Option<Key>,
    pub(crate) fwmark: Option<u32>,
    pub(crate) listen_port: Option<u16>,
    pub(crate) peers: Vec<PeerConfigBuilder>,
    pub(crate) replace_peers: bool,
}

impl DeviceConfigBuilder {
    /// Creates a new `DeviceConfigBuilder` that does nothing when applied.
    pub fn new() -> Self {
        DeviceConfigBuilder {
            public_key: None,
            private_key: None,
            fwmark: None,
            listen_port: None,
            peers: vec![],
            replace_peers: false,
        }
    }

    /// Sets a new keypair to be applied to the interface.
    ///
    /// This is a convenience method that simply wraps
    /// [`set_public_key`](DeviceConfigBuilder::set_public_key)
    /// and [`set_private_key`](DeviceConfigBuilder::set_private_key).
    pub fn set_keypair(self, keypair: KeyPair) -> Self {
        self.set_public_key(keypair.public)
            .set_private_key(keypair.private)
    }

    /// Specifies a new public key to be applied to the interface.
    pub fn set_public_key(mut self, key: Key) -> Self {
        self.public_key = Some(key);
        self
    }

    /// Specifies that the public key for this interface should be unset.
    pub fn unset_public_key(self) -> Self {
        self.set_public_key(Key::zero())
    }

    /// Sets a new private key to be applied to the interface.
    pub fn set_private_key(mut self, key: Key) -> Self {
        self.private_key = Some(key);
        self
    }

    /// Specifies that the private key for this interface should be unset.
    pub fn unset_private_key(self) -> Self {
        self.set_private_key(Key::zero())
    }

    /// Specifies the fwmark value that should be applied to packets coming from the interface.
    pub fn set_fwmark(mut self, fwmark: u32) -> Self {
        self.fwmark = Some(fwmark);
        self
    }

    /// Specifies that fwmark should not be set on packets from the interface.
    pub fn unset_fwmark(self) -> Self {
        self.set_fwmark(0)
    }

    /// Specifies the port to listen for incoming packets on.
    ///
    /// This is useful for a server configuration that listens on a fixed endpoint.
    pub fn set_listen_port(mut self, port: u16) -> Self {
        self.listen_port = Some(port);
        self
    }

    /// Specifies that a random port should be used for incoming packets.
    ///
    /// This is probably what you want in client configurations.
    pub fn randomize_listen_port(self) -> Self {
        self.set_listen_port(0)
    }

    /// Specifies a new peer configuration to be added to the interface.
    ///
    /// See [`PeerConfigBuilder`](PeerConfigBuilder) for details on building
    /// peer configurations. This method can be called more than once, and all
    /// peers will be added to the configuration.
    pub fn add_peer(mut self, peer: PeerConfigBuilder) -> Self {
        self.peers.push(peer);
        self
    }

    /// Specifies a new peer configuration using a builder function.
    ///
    /// This is simply a convenience method to make adding peers more fluent.
    /// This method can be called more than once, and all peers will be added
    /// to the configuration.
    pub fn add_peer_with(
        self,
        pubkey: &Key,
        builder: impl Fn(PeerConfigBuilder) -> PeerConfigBuilder,
    ) -> Self {
        self.add_peer(builder(PeerConfigBuilder::new(pubkey)))
    }

    /// Specifies multiple peer configurations to be added to the interface.
    pub fn add_peers(mut self, peers: &[PeerConfigBuilder]) -> Self {
        self.peers.extend_from_slice(peers);
        self
    }

    /// Specifies that the peer configurations in this `DeviceConfigBuilder` should
    /// replace the existing configurations on the interface, not modify or append to them.
    pub fn replace_peers(mut self) -> Self {
        self.replace_peers = true;
        self
    }

    /// Specifies that the peer with this public key should be removed from the interface.
    pub fn remove_peer_by_key(self, public_key: &Key) -> Self {
        let mut peer = PeerConfigBuilder::new(public_key);
        peer.remove_me = true;
        self.add_peer(peer)
    }

    /// Build and apply the configuration to a WireGuard interface by name.
    ///
    /// An interface with the provided name will be created if one does not exist already.
    #[cfg(target_os = "linux")]
    pub fn apply(self, iface: &str) -> io::Result<()> {
        if backends::kernel::exists() {
            backends::kernel::apply(self, iface)
        } else {
            backends::userspace::apply(self, iface)
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn apply(self, iface: &str) -> io::Result<()> {
        backends::userspace::apply(self, iface)
    }
}

impl Default for DeviceConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

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
/// # use wgctrl::*;
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
/// DeviceConfigBuilder::new().add_peer(peer).apply("wg-example");
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
    pub fn disable_persistent_keepalive(self) -> Self {
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

/// Deletes an existing WireGuard interface by name.
#[cfg(target_os = "linux")]
pub fn delete_interface(iface: &str) -> io::Result<()> {
    backends::kernel::delete_interface(iface)
}
