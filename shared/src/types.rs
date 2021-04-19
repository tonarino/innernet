use crate::prompts::hostname_validator;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Display, Formatter},
    net::{IpAddr, SocketAddr},
    ops::Deref,
    path::Path,
    str::FromStr,
};
use structopt::StructOpt;
use wgctrl::{InterfaceName, InvalidInterfaceName, Key, PeerConfig, PeerConfigBuilder};

#[derive(Debug, Clone)]
pub struct Interface {
    name: InterfaceName,
}

impl FromStr for Interface {
    type Err = String;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        let name = name.to_string();
        hostname_validator(&name)?;
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

#[derive(Deserialize, Serialize, Debug)]
#[serde(tag = "option", content = "content")]
pub enum EndpointContents {
    Set(SocketAddr),
    Unset,
}

impl Into<Option<SocketAddr>> for EndpointContents {
    fn into(self) -> Option<SocketAddr> {
        match self {
            Self::Set(addr) => Some(addr),
            Self::Unset => None,
        }
    }
}

impl From<Option<SocketAddr>> for EndpointContents {
    fn from(option: Option<SocketAddr>) -> Self {
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Cidr {
    pub id: i64,

    #[serde(flatten)]
    pub contents: CidrContents,
}

impl Deref for Cidr {
    type Target = CidrContents;

    fn deref(&self) -> &Self::Target {
        &self.contents
    }
}

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
        let mut leaves = vec![];
        for cidr in self.cidrs {
            if !self.cidrs.iter().any(|c| c.parent == Some(cidr.id)) {
                leaves.push(cidr.clone());
            }
        }
        leaves
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
    pub name: Option<String>,

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
}

#[derive(Debug, Clone, PartialEq, StructOpt)]
pub struct AddCidrOpts {
    /// The CIDR name (eg. "engineers")
    #[structopt(long)]
    pub name: Option<String>,

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
pub struct AddAssociationOpts {
    /// The first cidr to associate
    pub cidr1: Option<String>,

    /// The second cidr to associate
    pub cidr2: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct PeerContents {
    pub name: String,
    pub ip: IpAddr,
    pub cidr_id: i64,
    pub public_key: String,
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive_interval: Option<u16>,
    pub is_admin: bool,
    pub is_disabled: bool,
    pub is_redeemed: bool,
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

        let endpoint_diff = if peer.endpoint != self.endpoint {
            self.endpoint
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

        if let Some(endpoint) = peer.endpoint {
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
                name: "peer1".to_owned(),
                ip,
                cidr_id: 1,
                public_key: PUBKEY.to_owned(),
                endpoint: None,
                persistent_keepalive_interval: None,
                is_admin: false,
                is_disabled: false,
                is_redeemed: true,
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
                name: "peer1".to_owned(),
                ip,
                cidr_id: 1,
                public_key: PUBKEY.to_owned(),
                endpoint: None,
                persistent_keepalive_interval: Some(15),
                is_admin: false,
                is_disabled: false,
                is_redeemed: true,
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
