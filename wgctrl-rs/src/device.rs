use libc::c_char;

use crate::{backends, key::Key};

use std::{
    borrow::Cow,
    ffi::CStr,
    fmt,
    net::{IpAddr, SocketAddr},
    str::FromStr,
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
        // Ensure its short enough to include a trailing NUL
        if len > (libc::IFNAMSIZ - 1) {
            return Err(InvalidInterfaceName::TooLong(len));
        }

        if len == 0 || name.trim_start_matches('\0').is_empty() {
            return Err(InvalidInterfaceName::Empty);
        }

        let mut buf = [c_char::default(); libc::IFNAMSIZ];
        // Check for interior NULs and other invalid characters.
        for (out, b) in buf.iter_mut().zip(name.as_bytes()[..(len - 1)].iter()) {
            if *b == 0 {
                return Err(InvalidInterfaceName::InteriorNul);
            }

            if *b == b'/' || b.is_ascii_whitespace() {
                return Err(InvalidInterfaceName::InvalidChars);
            }

            *out = *b as i8;
        }

        Ok(Self(buf))
    }
}

impl InterfaceName {
    #[cfg(target_os = "linux")]
    /// Creates a new [InterfaceName](Self).
    ///
    /// ## Safety
    ///
    /// The caller must ensure that `name` is a valid C string terminated by a NUL.
    pub(crate) unsafe fn from_wg(name: RawInterfaceName) -> Self {
        Self(name)
    }

    /// Returns a human-readable form of the device name.
    ///
    /// Only use this when the interface name was constructed from a Rust string.
    pub fn as_str_lossy(&self) -> Cow<'_, str> {
        // SAFETY: These are C strings coming from wgctrl, so they are correctly NUL terminated.
        unsafe { CStr::from_ptr(self.0.as_ptr()) }.to_string_lossy()
    }

    #[cfg(target_os = "linux")]
    /// Returns a pointer to the inner byte buffer for FFI calls.
    pub(crate) fn as_ptr(&self) -> *const c_char {
        self.0.as_ptr()
    }

    #[cfg(target_os = "linux")]
    /// Consumes this interface name, returning its raw byte buffer.
    pub(crate) fn into_inner(self) -> RawInterfaceName {
        self.0
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
    /// Provided name had an interior NUL byte.
    InteriorNul,
    /// Provided name was longer then the interface name length limit
    /// of the system.
    TooLong(usize),

    // These checks are done in the kernel as well, but no reason to let bad names
    // get that far: https://git.kernel.org/pub/scm/network/iproute2/iproute2.git/tree/lib/utils.c?id=1f420318bda3cc62156e89e1b56d60cc744b48ad#n827.
    /// Interface name was an empty string.
    Empty,
    /// Interface name contained a `/` or space character.
    InvalidChars,
}

impl fmt::Display for InvalidInterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InteriorNul => f.write_str("interface name contained an interior NUL byte"),
            Self::TooLong(size) => write!(
                f,
                "interface name was {} bytes long but the system's max is {}",
                size,
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

impl DeviceInfo {
    /// Enumerates all WireGuard interfaces currently present in the system
    /// and returns their names.
    ///
    /// You can use [`get_by_name`](DeviceInfo::get_by_name) to retrieve more
    /// detailed information on each interface.
    #[cfg(target_os = "linux")]
    pub fn enumerate() -> Result<Vec<InterfaceName>, std::io::Error> {
        if backends::kernel::exists() {
            backends::kernel::enumerate()
        } else {
            backends::userspace::enumerate()
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn enumerate() -> Result<Vec<InterfaceName>, std::io::Error> {
        crate::backends::userspace::enumerate()
    }

    #[cfg(target_os = "linux")]
    pub fn get_by_name(name: &InterfaceName) -> Result<Self, std::io::Error> {
        if backends::kernel::exists() {
            backends::kernel::get_by_name(name)
        } else {
            backends::userspace::get_by_name(name)
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn get_by_name(name: &InterfaceName) -> Result<Self, std::io::Error> {
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
    use crate::{
        DeviceConfigBuilder, InterfaceName, InvalidInterfaceName, KeyPair, PeerConfigBuilder,
    };

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
        let interface = TEST_INTERFACE.parse().unwrap();
        builder.apply(&interface).unwrap();

        let device = DeviceInfo::get_by_name(&interface).unwrap();

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
        assert!("wg-01".parse::<InterfaceName>().is_ok());
        assert!("longer-nul\0".parse::<InterfaceName>().is_ok());

        let invalid_names = &[
            ("", InvalidInterfaceName::Empty),   // Empty Rust string
            ("\0", InvalidInterfaceName::Empty), // Empty C string
            ("ifname\0nul", InvalidInterfaceName::InteriorNul), // Contains interior NUL
            ("if name", InvalidInterfaceName::InvalidChars), // Contains a space
            ("ifna/me", InvalidInterfaceName::InvalidChars), // Contains a slash
            ("if na/me", InvalidInterfaceName::InvalidChars), // Contains a space and slash
            ("interfacelongname", InvalidInterfaceName::TooLong(17)), // Too long
        ];

        for (name, expected) in invalid_names {
            assert!(name.parse::<InterfaceName>().as_ref() == Err(expected))
        }
    }
}
