use libc::c_char;

use crate::{backends, key::Key, Backend, KeyPair, PeerConfigBuilder};

use std::{
    borrow::Cow,
    ffi::CStr,
    fmt, io,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    time::SystemTime,
};

/// Represents an IP address a peer is allowed to have, in CIDR notation.
#[derive(PartialEq, Eq, Clone)]
pub struct AllowedIp {
    /// The IP address.
    pub address: IpAddr,
    /// The CIDR subnet mask.
    pub cidr: u8,
}

impl fmt::Debug for AllowedIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.cidr)
    }
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
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct PeerStats {
    /// Time of the last handshake/rekey with this peer.
    pub last_handshake_time: Option<SystemTime>,
    /// Number of bytes received from this peer.
    pub rx_bytes: u64,
    /// Number of bytes transmitted to this peer.
    pub tx_bytes: u64,
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
pub struct Device {
    /// The interface name of this device
    pub name: InterfaceName,
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
    /// The backend the device exists on (userspace or kernel).
    pub backend: Backend,

    pub(crate) __cant_construct_me: (),
}

type RawInterfaceName = [c_char; libc::IFNAMSIZ];

/// The name of a Wireguard interface device.
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct InterfaceName(RawInterfaceName);

impl FromStr for InterfaceName {
    type Err = InvalidInterfaceName;

    /// Attempts to parse a Rust string as a valid Linux interface name.
    ///
    /// Extra validation logic ported from [iproute2](https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/tree/lib/utils.c#n827)
    fn from_str(name: &str) -> Result<Self, InvalidInterfaceName> {
        let len = name.len();
        if len == 0 {
            return Err(InvalidInterfaceName::Empty);
        }

        // Ensure its short enough to include a trailing NUL
        if len > (libc::IFNAMSIZ - 1) {
            return Err(InvalidInterfaceName::TooLong);
        }

        let mut buf = [c_char::default(); libc::IFNAMSIZ];
        // Check for interior NULs and other invalid characters.
        for (out, b) in buf.iter_mut().zip(name.as_bytes().iter()) {
            if *b == 0 || *b == b'/' || b.is_ascii_whitespace() {
                return Err(InvalidInterfaceName::InvalidChars);
            }

            *out = *b as c_char;
        }

        Ok(Self(buf))
    }
}

impl InterfaceName {
    /// Returns a human-readable form of the device name.
    ///
    /// Only use this when the interface name was constructed from a Rust string.
    pub fn as_str_lossy(&self) -> Cow<'_, str> {
        // SAFETY: These are C strings coming from wgctrl, so they are correctly NUL terminated.
        unsafe { CStr::from_ptr(self.0.as_ptr()) }.to_string_lossy()
    }

    #[cfg(target_os = "linux")]
    /// Returns a pointer to the inner byte buffer for FFI calls.
    pub fn as_ptr(&self) -> *const c_char {
        self.0.as_ptr()
    }
}

impl fmt::Debug for InterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str_lossy())
    }
}

impl fmt::Display for InterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str_lossy())
    }
}

/// An interface name was bad.
#[derive(Debug, PartialEq)]
pub enum InvalidInterfaceName {
    /// Provided name was longer then the interface name length limit
    /// of the system.
    TooLong,

    // These checks are done in the kernel as well, but no reason to let bad names
    // get that far: https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/tree/lib/utils.c?id=1f420318bda3cc62156e89e1b56d60cc744b48ad#n827.
    /// Interface name was an empty string.
    Empty,
    /// Interface name contained a nul, `/` or whitespace character.
    InvalidChars,
}

impl fmt::Display for InvalidInterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => write!(
                f,
                "interface name longer than system max of {} chars",
                libc::IFNAMSIZ
            ),
            Self::Empty => f.write_str("an empty interface name was provided"),
            Self::InvalidChars => f.write_str("interface name contained slash or space characters"),
        }
    }
}

impl From<InvalidInterfaceName> for std::io::Error {
    fn from(e: InvalidInterfaceName) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
    }
}

impl std::error::Error for InvalidInterfaceName {}

impl Device {
    /// Enumerates all WireGuard interfaces currently present in the system,
    /// both with kernel and userspace backends.
    ///
    /// You can use [`get_by_name`](DeviceInfo::get_by_name) to retrieve more
    /// detailed information on each interface.
    pub fn list(backend: Backend) -> Result<Vec<InterfaceName>, std::io::Error> {
        match backend {
            #[cfg(target_os = "linux")]
            Backend::Kernel => backends::kernel::enumerate(),
            Backend::Userspace => backends::userspace::enumerate(),
        }
    }

    pub fn get(name: &InterfaceName, backend: Backend) -> Result<Self, std::io::Error> {
        match backend {
            #[cfg(target_os = "linux")]
            Backend::Kernel => backends::kernel::get_by_name(name),
            Backend::Userspace => backends::userspace::get_by_name(name),
        }
    }

    pub fn delete(self) -> Result<(), std::io::Error> {
        match self.backend {
            #[cfg(target_os = "linux")]
            Backend::Kernel => backends::kernel::delete_interface(&self.name),
            Backend::Userspace => backends::userspace::delete_interface(&self.name),
        }
    }
}

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
/// # use wireguard_control::*;
/// # use std::net::AddrParseError;
/// # fn try_main() -> Result<(), AddrParseError> {
/// let our_keypair = KeyPair::generate();
/// let peer_keypair = KeyPair::generate();
/// let server_addr = "192.168.1.1:51820".parse()?;
///
/// DeviceUpdate::new()
///     .set_keypair(our_keypair)
///     .replace_peers()
///     .add_peer_with(&peer_keypair.public, |peer| {
///         peer.set_endpoint(server_addr)
///             .replace_allowed_ips()
///             .allow_all_ips()
///     }).apply(&"wg-example".parse().unwrap(), Backend::Userspace);
///
/// println!("Send these keys to your peer: {:#?}", peer_keypair);
///
/// # Ok(())
/// # }
/// # fn main() { try_main(); }
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DeviceUpdate {
    pub(crate) public_key: Option<Key>,
    pub(crate) private_key: Option<Key>,
    pub(crate) fwmark: Option<u32>,
    pub(crate) listen_port: Option<u16>,
    pub(crate) peers: Vec<PeerConfigBuilder>,
    pub(crate) replace_peers: bool,
}

impl DeviceUpdate {
    /// Creates a new `DeviceConfigBuilder` that does nothing when applied.
    #[must_use]
    pub fn new() -> Self {
        DeviceUpdate {
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
    #[must_use]
    pub fn set_keypair(self, keypair: KeyPair) -> Self {
        self.set_public_key(keypair.public)
            .set_private_key(keypair.private)
    }

    /// Specifies a new public key to be applied to the interface.
    #[must_use]
    pub fn set_public_key(mut self, key: Key) -> Self {
        self.public_key = Some(key);
        self
    }

    /// Specifies that the public key for this interface should be unset.
    #[must_use]
    pub fn unset_public_key(self) -> Self {
        self.set_public_key(Key::zero())
    }

    /// Sets a new private key to be applied to the interface.
    #[must_use]
    pub fn set_private_key(mut self, key: Key) -> Self {
        self.private_key = Some(key);
        self
    }

    /// Specifies that the private key for this interface should be unset.
    #[must_use]
    pub fn unset_private_key(self) -> Self {
        self.set_private_key(Key::zero())
    }

    /// Specifies the fwmark value that should be applied to packets coming from the interface.
    #[must_use]
    pub fn set_fwmark(mut self, fwmark: u32) -> Self {
        self.fwmark = Some(fwmark);
        self
    }

    /// Specifies that fwmark should not be set on packets from the interface.
    #[must_use]
    pub fn unset_fwmark(self) -> Self {
        self.set_fwmark(0)
    }

    /// Specifies the port to listen for incoming packets on.
    ///
    /// This is useful for a server configuration that listens on a fixed endpoint.
    #[must_use]
    pub fn set_listen_port(mut self, port: u16) -> Self {
        self.listen_port = Some(port);
        self
    }

    /// Specifies that a random port should be used for incoming packets.
    ///
    /// This is probably what you want in client configurations.
    #[must_use]
    pub fn randomize_listen_port(self) -> Self {
        self.set_listen_port(0)
    }

    /// Specifies a new peer configuration to be added to the interface.
    ///
    /// See [`PeerConfigBuilder`](PeerConfigBuilder) for details on building
    /// peer configurations. This method can be called more than once, and all
    /// peers will be added to the configuration.
    #[must_use]
    pub fn add_peer(mut self, peer: PeerConfigBuilder) -> Self {
        self.peers.push(peer);
        self
    }

    /// Specifies a new peer configuration using a builder function.
    ///
    /// This is simply a convenience method to make adding peers more fluent.
    /// This method can be called more than once, and all peers will be added
    /// to the configuration.
    #[must_use]
    pub fn add_peer_with(
        self,
        pubkey: &Key,
        builder: impl Fn(PeerConfigBuilder) -> PeerConfigBuilder,
    ) -> Self {
        self.add_peer(builder(PeerConfigBuilder::new(pubkey)))
    }

    /// Specifies multiple peer configurations to be added to the interface.
    #[must_use]
    pub fn add_peers(mut self, peers: &[PeerConfigBuilder]) -> Self {
        self.peers.extend_from_slice(peers);
        self
    }

    /// Specifies that the peer configurations in this `DeviceConfigBuilder` should
    /// replace the existing configurations on the interface, not modify or append to them.
    #[must_use]
    pub fn replace_peers(mut self) -> Self {
        self.replace_peers = true;
        self
    }

    /// Specifies that the peer with this public key should be removed from the interface.
    #[must_use]
    pub fn remove_peer_by_key(self, public_key: &Key) -> Self {
        let mut peer = PeerConfigBuilder::new(public_key);
        peer.remove_me = true;
        self.add_peer(peer)
    }

    /// Build and apply the configuration to a WireGuard interface by name.
    ///
    /// An interface with the provided name will be created if one does not exist already.
    pub fn apply(self, iface: &InterfaceName, backend: Backend) -> io::Result<()> {
        match backend {
            #[cfg(target_os = "linux")]
            Backend::Kernel => backends::kernel::apply(&self, iface),
            Backend::Userspace => backends::userspace::apply(&self, iface),
        }
    }
}

impl Default for DeviceUpdate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::{DeviceUpdate, InterfaceName, InvalidInterfaceName, KeyPair, PeerConfigBuilder};

    const TEST_INTERFACE: &str = "wgctrl-test";
    use super::*;

    #[test]
    fn test_add_peers() {
        if unsafe { libc::getuid() } != 0 {
            return;
        }

        let keypairs: Vec<_> = (0..10).map(|_| KeyPair::generate()).collect();
        let mut builder = DeviceUpdate::new();
        for keypair in &keypairs {
            builder = builder.add_peer(PeerConfigBuilder::new(&keypair.public))
        }
        let interface = TEST_INTERFACE.parse().unwrap();
        builder.apply(&interface, Backend::Userspace).unwrap();

        let device = Device::get(&interface, Backend::Userspace).unwrap();

        for keypair in &keypairs {
            assert!(device
                .peers
                .iter()
                .any(|p| p.config.public_key == keypair.public));
        }

        device.delete().unwrap();
    }

    #[test]
    fn test_interface_names() {
        assert_eq!(
            "wg-01".parse::<InterfaceName>().unwrap().as_str_lossy(),
            "wg-01"
        );
        assert!("longer-nul\0".parse::<InterfaceName>().is_err());

        let invalid_names = &[
            ("", InvalidInterfaceName::Empty),          // Empty Rust string
            ("\0", InvalidInterfaceName::InvalidChars), // Empty C string
            ("ifname\0nul", InvalidInterfaceName::InvalidChars), // Contains interior NUL
            ("if name", InvalidInterfaceName::InvalidChars), // Contains a space
            ("ifna/me", InvalidInterfaceName::InvalidChars), // Contains a slash
            ("if na/me", InvalidInterfaceName::InvalidChars), // Contains a space and slash
            ("interfacelongname", InvalidInterfaceName::TooLong), // Too long
        ];

        for (name, expected) in invalid_names {
            assert!(name.parse::<InterfaceName>().as_ref() == Err(expected))
        }
    }
}
