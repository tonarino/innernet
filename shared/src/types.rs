use ipnetwork::IpNetwork;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Display, Formatter},
    io,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    ops::Deref,
    path::Path,
    str::FromStr,
    time::{Duration, SystemTime},
    vec,
};
use structopt::StructOpt;
use url::Host;
use wgctrl::{Backend, InterfaceName, InvalidInterfaceName, Key, PeerConfig, PeerConfigBuilder};

#[derive(Debug, Clone)]
pub struct Interface {
    name: InterfaceName,
}

impl FromStr for Interface {
    type Err = String;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        if !Hostname::is_valid(name) {
            return Err("interface name is not a valid hostname".into());
        }
        let name = name
            .parse()
            .map_err(|e: InvalidInterfaceName| e.to_string())?;
        Ok(Self { name })
    }
}

impl Deref for Interface {
    type Target = InterfaceName;

    fn deref(&self) -> &Self::Target {
        &self.name
    }
}

#[derive(Clone, Debug, PartialEq)]
/// An external endpoint that supports both IP and domain name hosts.
pub struct Endpoint {
    host: Host,
    port: u16,
}

impl From<SocketAddr> for Endpoint {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4addr) => Self {
                host: Host::Ipv4(*v4addr.ip()),
                port: v4addr.port(),
            },
            SocketAddr::V6(v6addr) => Self {
                host: Host::Ipv6(*v6addr.ip()),
                port: v6addr.port(),
            },
        }
    }
}

impl FromStr for Endpoint {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.rsplitn(2, ':').collect::<Vec<&str>>().as_slice() {
            [port, host] => {
                let port = port.parse().map_err(|_| "couldn't parse port")?;
                let host = Host::parse(host).map_err(|_| "couldn't parse host")?;
                Ok(Endpoint { host, port })
            },
            _ => Err("couldn't parse in form of 'host:port'"),
        }
    }
}

impl Serialize for Endpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Endpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct EndpointVisitor;
        impl<'de> serde::de::Visitor<'de> for EndpointVisitor {
            type Value = Endpoint;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid host:port endpoint")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                s.parse().map_err(serde::de::Error::custom)
            }
        }
        deserializer.deserialize_str(EndpointVisitor)
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.host.fmt(f)?;
        f.write_str(":")?;
        self.port.fmt(f)
    }
}

impl Endpoint {
    pub fn resolve(&self) -> Result<SocketAddr, io::Error> {
        let mut addrs = self.to_string().to_socket_addrs()?;
        addrs.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "failed to resolve address".to_string(),
            )
        })
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(tag = "option", content = "content")]
pub enum EndpointContents {
    Set(Endpoint),
    Unset,
}

impl From<EndpointContents> for Option<Endpoint> {
    fn from(endpoint: EndpointContents) -> Self {
        match endpoint {
            EndpointContents::Set(addr) => Some(addr),
            EndpointContents::Unset => None,
        }
    }
}

impl From<Option<Endpoint>> for EndpointContents {
    fn from(option: Option<Endpoint>) -> Self {
        match option {
            Some(addr) => Self::Set(addr),
            None => Self::Unset,
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct AssociationContents {
    pub cidr_id_1: i64,
    pub cidr_id_2: i64,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Association {
    pub id: i64,

    #[serde(flatten)]
    pub contents: AssociationContents,
}

impl Deref for Association {
    type Target = AssociationContents;

    fn deref(&self) -> &Self::Target {
        &self.contents
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, PartialOrd, Eq, Ord)]
pub struct CidrContents {
    pub name: String,
    pub cidr: IpNetwork,
    pub parent: Option<i64>,
}

impl Deref for CidrContents {
    type Target = IpNetwork;

    fn deref(&self) -> &Self::Target {
        &self.cidr
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, PartialOrd, Eq, Ord)]
pub struct Cidr {
    pub id: i64,

    #[serde(flatten)]
    pub contents: CidrContents,
}

impl Display for Cidr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.cidr)
    }
}

impl Deref for Cidr {
    type Target = CidrContents;

    fn deref(&self) -> &Self::Target {
        &self.contents
    }
}

#[derive(Clone, PartialEq, PartialOrd, Eq, Ord)]
pub struct CidrTree<'a> {
    cidrs: &'a [Cidr],
    contents: &'a Cidr,
}

impl<'a> std::ops::Deref for CidrTree<'a> {
    type Target = Cidr;

    fn deref(&self) -> &Self::Target {
        self.contents
    }
}

impl<'a> CidrTree<'a> {
    pub fn new(cidrs: &'a [Cidr]) -> Self {
        let root = cidrs
            .iter()
            .min_by_key(|c| c.cidr.prefix())
            .expect("failed to find root CIDR");
        Self::with_root(cidrs, root)
    }

    pub fn with_root(cidrs: &'a [Cidr], root: &'a Cidr) -> Self {
        Self {
            cidrs,
            contents: root,
        }
    }

    pub fn children(&self) -> impl Iterator<Item = CidrTree> {
        self.cidrs
            .iter()
            .filter(move |c| c.parent == Some(self.contents.id))
            .map(move |c| Self {
                cidrs: self.cidrs,
                contents: c,
            })
    }

    pub fn leaves(&self) -> Vec<Cidr> {
        if !self.cidrs.iter().any(|cidr| cidr.parent == Some(self.id)) {
            vec![self.contents.clone()]
        } else {
            self.children().flat_map(|child| child.leaves()).collect()
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct RedeemContents {
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, StructOpt)]
pub struct InstallOpts {
    /// Set a specific interface name
    #[structopt(long, conflicts_with = "default-name")]
    pub name: Option<String>,

    /// Use the network name inside the invitation as the interface name
    #[structopt(long = "default-name")]
    pub default_name: bool,

    /// Delete the invitation after a successful install
    #[structopt(short, long)]
    pub delete_invite: bool,
}

#[derive(Debug, Clone, PartialEq, StructOpt)]
pub struct AddPeerOpts {
    /// Name of new peer
    #[structopt(long)]
    pub name: Option<Hostname>,

    /// Specify desired IP of new peer (within parent CIDR)
    #[structopt(long, conflicts_with = "auto-ip")]
    pub ip: Option<IpAddr>,

    /// Auto-assign the peer the first available IP within the CIDR
    #[structopt(long = "auto-ip")]
    pub auto_ip: bool,

    /// Name of CIDR to add new peer under
    #[structopt(long)]
    pub cidr: Option<String>,

    /// Make new peer an admin?
    #[structopt(long)]
    pub admin: Option<bool>,

    /// Bypass confirmation
    #[structopt(long)]
    pub yes: bool,

    /// Save the config to the given location
    #[structopt(long)]
    pub save_config: Option<String>,

    /// Invite expiration period (eg. "30d", "7w", "2h", "60m", "1000s")
    #[structopt(long)]
    pub invite_expires: Option<Timestring>,
}

#[derive(Debug, Clone, PartialEq, StructOpt)]
pub struct RenamePeerOpts {
    /// Name of peer to rename
    #[structopt(long)]
    pub name: Option<Hostname>,

    /// The new name of the peer
    #[structopt(long)]
    pub new_name: Option<Hostname>,

    /// Bypass confirmation
    #[structopt(long)]
    pub yes: bool,
}

#[derive(Debug, Clone, PartialEq, StructOpt)]
pub struct AddCidrOpts {
    /// The CIDR name (eg. "engineers")
    #[structopt(long)]
    pub name: Option<Hostname>,

    /// The CIDR network (eg. "10.42.5.0/24")
    #[structopt(long)]
    pub cidr: Option<IpNetwork>,

    /// The CIDR parent name
    #[structopt(long)]
    pub parent: Option<String>,

    /// Bypass confirmation
    #[structopt(long)]
    pub yes: bool,
}

#[derive(Debug, Clone, PartialEq, StructOpt)]
pub struct DeleteCidrOpts {
    /// The CIDR name (eg. "engineers")
    #[structopt(long)]
    pub name: Option<String>,

    /// Bypass confirmation
    #[structopt(long)]
    pub yes: bool,
}

#[derive(Debug, Clone, PartialEq, StructOpt)]
pub struct AddAssociationOpts {
    /// The first cidr to associate
    pub cidr1: Option<String>,

    /// The second cidr to associate
    pub cidr2: Option<String>,
}

#[derive(Debug, Clone, Copy, StructOpt)]
pub struct NetworkOpt {
    #[structopt(long)]
    /// Whether the routing should be done by innernet or is done by an
    /// external tool like e.g. babeld.
    pub no_routing: bool,

    #[structopt(long, default_value, possible_values = Backend::variants())]
    /// Specify a WireGuard backend to use.
    /// If not set, innernet will auto-select based on availability.
    pub backend: Backend,

    #[structopt(long)]
    /// Specify the desired MTU for your interface (default: 1420 for IPv4 and 1400 for IPv6).
    pub mtu: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct PeerContents {
    pub name: Hostname,
    pub ip: IpAddr,
    pub cidr_id: i64,
    pub public_key: String,
    pub endpoint: Option<Endpoint>,
    pub persistent_keepalive_interval: Option<u16>,
    pub is_admin: bool,
    pub is_disabled: bool,
    pub is_redeemed: bool,
    pub invite_expires: Option<SystemTime>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Peer {
    pub id: i64,

    #[serde(flatten)]
    pub contents: PeerContents,
}

impl Deref for Peer {
    type Target = PeerContents;

    fn deref(&self) -> &Self::Target {
        &self.contents
    }
}

impl Display for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", &self.name, &self.public_key)
    }
}

#[derive(Debug, PartialEq)]
pub struct PeerDiff {
    pub public_key: String,
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive_interval: Option<u16>,
    pub is_disabled: bool,
}

impl Peer {
    pub fn diff(&self, peer: &PeerConfig) -> Option<PeerDiff> {
        assert_eq!(self.public_key, peer.public_key.to_base64());

        let endpoint_diff = if let Some(ref endpoint) = self.endpoint {
            match endpoint.resolve() {
                Ok(resolved) if Some(resolved) != peer.endpoint => Some(resolved),
                _ => None,
            }
        } else {
            None
        };

        let keepalive_diff =
            if peer.persistent_keepalive_interval != self.persistent_keepalive_interval {
                self.persistent_keepalive_interval
            } else {
                None
            };

        if endpoint_diff.is_none() && keepalive_diff.is_none() {
            None
        } else {
            Some(PeerDiff {
                public_key: self.public_key.clone(),
                endpoint: endpoint_diff,
                persistent_keepalive_interval: keepalive_diff,
                is_disabled: self.is_disabled,
            })
        }
    }
}

impl<'a> From<&'a Peer> for PeerConfigBuilder {
    fn from(peer: &Peer) -> Self {
        let builder = PeerConfigBuilder::new(&Key::from_base64(&peer.public_key).unwrap())
            .replace_allowed_ips()
            .add_allowed_ip(peer.ip, if peer.ip.is_ipv4() { 32 } else { 128 });

        let builder = if peer.is_disabled {
            builder.remove()
        } else {
            builder
        };

        let builder = if let Some(interval) = peer.persistent_keepalive_interval {
            builder.set_persistent_keepalive_interval(interval)
        } else {
            builder
        };

        let resolved = peer.endpoint.as_ref().map(|e| e.resolve().ok()).flatten();

        if let Some(endpoint) = resolved {
            builder.set_endpoint(endpoint)
        } else {
            builder
        }
    }
}

impl<'a> From<&'a PeerDiff> for PeerConfigBuilder {
    fn from(peer: &PeerDiff) -> Self {
        let builder = PeerConfigBuilder::new(&Key::from_base64(&peer.public_key).unwrap());

        let builder = if peer.is_disabled {
            builder.remove()
        } else {
            builder
        };

        let builder = if let Some(interval) = peer.persistent_keepalive_interval {
            builder.set_persistent_keepalive_interval(interval)
        } else {
            builder
        };

        if let Some(endpoint) = peer.endpoint {
            builder.set_endpoint(endpoint)
        } else {
            builder
        }
    }
}

/// This model is sent as a response to the /state endpoint, and is meant
/// to include all the data a client needs to update its WireGuard interface.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct State {
    /// This list will be only the peers visible to the user requesting this
    /// information, not including disabled peers or peers from other CIDRs
    /// that the user's CIDR is not authorized to communicate with.
    pub peers: Vec<Peer>,

    /// At the moment, this is all CIDRs, regardless of whether the peer is
    /// eligible to communicate with them or not.
    pub cidrs: Vec<Cidr>,
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
            Err("timestring isn't long enough!")
        } else {
            let (n, suffix) = timestring.split_at(timestring.len() - 1);
            let n: u64 = n.parse().map_err(|_| {
                "invalid timestring (a number followed by a time unit character, eg. '15m')"
            })?;
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Hostname(String);

lazy_static! {
    /// Regex to match the requirements of hostname(7), needed to have peers also be reachable hostnames.
    /// Note that the full length also must be maximum 63 characters, which this regex does not check.
    static ref HOSTNAME_REGEX: Regex = Regex::new(r"^([a-z0-9]-?)*[a-z0-9]$").unwrap();
}

impl Hostname {
    pub fn is_valid(name: &str) -> bool {
        name.len() < 64 && HOSTNAME_REGEX.is_match(name)
    }
}

impl FromStr for Hostname {
    type Err = &'static str;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        if Self::is_valid(name) {
            Ok(Self(name.to_string()))
        } else {
            Err("invalid hostname string (only alphanumeric with dashes)")
        }
    }
}

impl Deref for Hostname {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for Hostname {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub trait IoErrorContext<T> {
    fn with_path<P: AsRef<Path>>(self, path: P) -> Result<T, WrappedIoError>;
    fn with_str<S: Into<String>>(self, context: S) -> Result<T, WrappedIoError>;
}

impl<T> IoErrorContext<T> for Result<T, std::io::Error> {
    fn with_path<P: AsRef<Path>>(self, path: P) -> Result<T, WrappedIoError> {
        self.with_str(path.as_ref().to_string_lossy())
    }

    fn with_str<S: Into<String>>(self, context: S) -> Result<T, WrappedIoError> {
        self.map_err(|e| WrappedIoError {
            io_error: e,
            context: context.into(),
        })
    }
}

#[derive(Debug)]
pub struct WrappedIoError {
    io_error: std::io::Error,
    context: String,
}

impl std::fmt::Display for WrappedIoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "{} - {}", self.context, self.io_error)
    }
}

impl Deref for WrappedIoError {
    type Target = std::io::Error;

    fn deref(&self) -> &Self::Target {
        &self.io_error
    }
}

impl std::error::Error for WrappedIoError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use wgctrl::{Key, PeerConfigBuilder};

    #[test]
    fn test_peer_no_diff() {
        const PUBKEY: &str = "4CNZorWVtohO64n6AAaH/JyFjIIgBFrfJK2SGtKjzEE=";
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let peer = Peer {
            id: 1,
            contents: PeerContents {
                name: "peer1".parse().unwrap(),
                ip,
                cidr_id: 1,
                public_key: PUBKEY.to_owned(),
                endpoint: None,
                persistent_keepalive_interval: None,
                is_admin: false,
                is_disabled: false,
                is_redeemed: true,
                invite_expires: None,
            },
        };
        let builder =
            PeerConfigBuilder::new(&Key::from_base64(PUBKEY).unwrap()).add_allowed_ip(ip, 32);

        let config = builder.into_peer_config();

        assert_eq!(peer.diff(&config), None);
    }

    #[test]
    fn test_peer_diff() {
        const PUBKEY: &str = "4CNZorWVtohO64n6AAaH/JyFjIIgBFrfJK2SGtKjzEE=";
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let peer = Peer {
            id: 1,
            contents: PeerContents {
                name: "peer1".parse().unwrap(),
                ip,
                cidr_id: 1,
                public_key: PUBKEY.to_owned(),
                endpoint: None,
                persistent_keepalive_interval: Some(15),
                is_admin: false,
                is_disabled: false,
                is_redeemed: true,
                invite_expires: None,
            },
        };
        let builder =
            PeerConfigBuilder::new(&Key::from_base64(PUBKEY).unwrap()).add_allowed_ip(ip, 32);

        let config = builder.into_peer_config();

        println!("{:?}", peer);
        println!("{:?}", config);
        assert!(matches!(peer.diff(&config), Some(_)));
    }
}
