use crate::{chmod, ensure_dirs_exist, Endpoint, Error, IoErrorContext, Peer, WrappedIoError};
use indoc::writedoc;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{self, Write},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};
use wireguard_control::{InterfaceName, KeyPair};

/// This struct contains everything necessary to establish an innernet connection: information about
/// a local innernet interface and a remote innernet server.
#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct InterfaceConfig {
    /// The information to bring up the interface.
    pub interface: InterfaceInfo,

    /// The necessary contact information for the server.
    pub server: ServerInfo,

    /// A configurable map of peer IP addresses to Endpoints which should
    /// be used as the WireGuard endpoint for that peer.
    #[serde(default)]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    peer_endpoint_overrides: BTreeMap<IpAddr, Endpoint>,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct InterfaceInfo {
    /// The interface name (i.e. "tonari")
    pub network_name: String,

    /// The invited peer's internal IP address that's been allocated to it, inside
    /// the entire network's CIDR prefix.
    pub address: IpNet,

    /// WireGuard private key (base64)
    pub private_key: String,

    /// The local listen port. A random port will be used if `None`.
    pub listen_port: Option<u16>,
}

impl InterfaceInfo {
    pub fn new(network_name: &InterfaceName, keypair: &KeyPair, address: IpNet) -> Self {
        Self {
            network_name: network_name.to_string(),
            private_key: keypair.private.to_base64(),
            address,
            listen_port: None,
        }
    }
}

#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct ServerInfo {
    /// The server's WireGuard public key
    pub public_key: String,

    /// The external internet endpoint to reach the server.
    pub external_endpoint: Endpoint,

    /// An IPv6 external endpoint, used when the server is unreachable over `external_endpoint`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_endpoint_v6: Option<Endpoint>,

    /// An internal endpoint in the WireGuard network that hosts the coordination API.
    pub internal_endpoint: SocketAddr,
}

impl ServerInfo {
    pub fn new(server_peer: &Peer, internal_endpoint: SocketAddr) -> Self {
        Self {
            external_endpoint: server_peer
                .endpoint
                .clone()
                .expect("The innernet server should have a WireGuard endpoint"),
            external_endpoint_v6: server_peer.ipv6_external_endpoint().cloned(),
            internal_endpoint,
            public_key: server_peer.public_key.clone(),
        }
    }
}

impl InterfaceConfig {
    fn new(interface: InterfaceInfo, server: ServerInfo) -> Self {
        InterfaceConfig {
            interface,
            server,
            peer_endpoint_overrides: BTreeMap::new(),
        }
    }

    /// Save a new config file, failing if it already exists.
    pub fn save_new(&self, path: impl AsRef<Path>, mode: u32) -> Result<(), WrappedIoError> {
        let path = path.as_ref();
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .with_path(path)?;

        chmod(&file, mode).with_path(path)?;

        file.write_all(self.as_toml().as_bytes()).with_path(path)?;

        Ok(())
    }

    /// Overwrites the config file if it already exists.
    pub fn save(&self, config_dir: &Path, interface: &InterfaceName) -> Result<PathBuf, Error> {
        let path = Self::build_config_file_path(config_dir, interface)?;
        File::create(&path)
            .with_path(&path)?
            .write_all(self.as_toml().as_bytes())?;

        Ok(path)
    }

    fn as_toml(&self) -> String {
        toml::to_string(self).unwrap()
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        Ok(toml::from_str(
            &std::fs::read_to_string(&path).with_path(path)?,
        )?)
    }

    pub fn from_interface(config_dir: &Path, interface: &InterfaceName) -> Result<Self, Error> {
        let path = Self::build_config_file_path(config_dir, interface)?;
        crate::warn_on_dangerous_mode(&path).with_path(&path)?;
        Self::from_file(path)
    }

    pub fn get_path(config_dir: &Path, interface: &InterfaceName) -> PathBuf {
        config_dir
            .join(interface.to_string())
            .with_extension("conf")
    }

    pub fn build_config_file_path(
        config_dir: &Path,
        interface: &InterfaceName,
    ) -> Result<PathBuf, WrappedIoError> {
        ensure_dirs_exist(&[config_dir])?;
        Ok(Self::get_path(config_dir, interface))
    }

    pub fn peer_endpoint_overrides(&self) -> &BTreeMap<IpAddr, Endpoint> {
        &self.peer_endpoint_overrides
    }

    pub fn set_endpoint_override_for_peer(&mut self, peer_ip: IpAddr, endpoint: Endpoint) {
        self.peer_endpoint_overrides.insert(peer_ip, endpoint);
    }

    pub fn unset_endpoint_override_for_peer(&mut self, peer_ip: IpAddr) {
        self.peer_endpoint_overrides.remove(&peer_ip);
    }
}

impl InterfaceInfo {
    pub fn public_key(&self) -> Result<String, Error> {
        Ok(wireguard_control::Key::from_base64(&self.private_key)?
            .get_public()
            .to_base64())
    }
}

#[must_use]
pub struct PeerInvitation {
    interface_config: InterfaceConfig,
}

impl PeerInvitation {
    pub fn new(interface: InterfaceInfo, server: ServerInfo) -> Self {
        Self {
            interface_config: InterfaceConfig::new(interface, server),
        }
    }

    /// Save a new invitation file, failing if it already exists.
    pub fn save_new(&self, path: impl AsRef<Path>) -> Result<(), io::Error> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;

        writedoc!(
            file,
            r"
                    # This is an invitation file to an innernet network.
                    #
                    # To join, you must install innernet.
                    # See https://github.com/tonarino/innernet for instructions.
                    #
                    # If you have innernet, just run:
                    #
                    #   innernet install <this file>
                    #
                    # Don't edit the contents below unless you love chaos and dysfunction.
                "
        )?;

        file.write_all(self.interface_config.as_toml().as_bytes())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PeerContents;

    fn server_peer(candidates: Vec<Endpoint>) -> Peer {
        Peer {
            id: 1,
            contents: PeerContents {
                name: "innernet-server".parse().unwrap(),
                ip: "10.42.0.1".parse().unwrap(),
                cidr_id: 2,
                public_key: "4CNZorWVtohO64n6AAaH/JyFjIIgBFrfJK2SGtKjzEE=".to_owned(),
                endpoint: Some("203.0.113.1:51820".parse().unwrap()),
                persistent_keepalive_interval: None,
                is_admin: true,
                is_disabled: false,
                is_redeemed: true,
                invite_expires: None,
                candidates,
            },
        }
    }

    fn round_trip(server: ServerInfo) -> (String, InterfaceConfig) {
        let keypair = KeyPair::generate();
        let interface = InterfaceInfo::new(
            &"test".parse().unwrap(),
            &keypair,
            "10.42.1.1/16".parse().unwrap(),
        );
        let toml = InterfaceConfig::new(interface, server).as_toml();
        let parsed = toml::from_str(&toml).unwrap();
        (toml, parsed)
    }

    #[test]
    fn test_server_info_with_ipv6_endpoint() {
        let v6: Endpoint = "[2001:db8::1]:51820".parse().unwrap();
        let peer = server_peer(vec![v6.clone()]);
        let server = ServerInfo::new(&peer, "10.42.0.1:51820".parse().unwrap());
        assert_eq!(server.external_endpoint_v6, Some(v6.clone()));

        let (toml, parsed) = round_trip(server);
        assert!(toml.contains("external-endpoint-v6 = \"[2001:db8::1]:51820\""));
        assert_eq!(parsed.server.external_endpoint_v6, Some(v6));
    }

    #[test]
    fn test_server_info_without_ipv6_endpoint() {
        let peer = server_peer(vec![]);
        let server = ServerInfo::new(&peer, "10.42.0.1:51820".parse().unwrap());
        assert_eq!(server.external_endpoint_v6, None);

        let (toml, parsed) = round_trip(server);
        assert!(!toml.contains("external-endpoint-v6"));
        assert_eq!(parsed.server.external_endpoint_v6, None);
    }
}
