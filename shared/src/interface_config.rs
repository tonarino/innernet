use crate::{
    chmod, ensure_dirs_exist, Cidr, Endpoint, Error, IoErrorContext, Peer, WrappedIoError,
};
use indoc::writedoc;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    net::SocketAddr,
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

#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct ServerInfo {
    /// The server's WireGuard public key
    pub public_key: String,

    /// The external internet endpoint to reach the server.
    pub external_endpoint: Endpoint,

    /// An internal endpoint in the WireGuard network that hosts the coordination API.
    pub internal_endpoint: SocketAddr,
}

impl InterfaceConfig {
    /// Save a new config file, failing if it already exists.
    pub fn save_new(&self, path: impl AsRef<Path>, mode: u32) -> Result<(), WrappedIoError> {
        let path = path.as_ref();
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .with_path(path)?;

        chmod(&file, mode).with_path(path)?;

        file.write_all(self.contents().as_bytes()).with_path(path)?;

        Ok(())
    }

    /// Overwrites the config file if it already exists.
    pub fn save(&self, config_dir: &Path, interface: &InterfaceName) -> Result<PathBuf, Error> {
        let path = Self::build_config_file_path(config_dir, interface)?;
        File::create(&path)
            .with_path(&path)?
            .write_all(self.contents().as_bytes())?;

        Ok(path)
    }

    fn contents(&self) -> String {
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

    fn build_config_file_path(
        config_dir: &Path,
        interface: &InterfaceName,
    ) -> Result<PathBuf, WrappedIoError> {
        ensure_dirs_exist(&[config_dir])?;
        Ok(Self::get_path(config_dir, interface))
    }

    fn new(
        network_name: &InterfaceName,
        peer: &Peer,
        server_peer: &Peer,
        root_cidr: &Cidr,
        keypair: KeyPair,
        server_api_addr: &SocketAddr,
    ) -> Result<InterfaceConfig, Error> {
        let invitation = InterfaceConfig {
            interface: InterfaceInfo {
                network_name: network_name.to_string(),
                private_key: keypair.private.to_base64(),
                address: IpNet::new(peer.ip, root_cidr.prefix_len())?,
                listen_port: None,
            },
            server: ServerInfo {
                external_endpoint: server_peer
                    .endpoint
                    .clone()
                    .expect("The innernet server should have a WireGuard endpoint"),
                internal_endpoint: *server_api_addr,
                public_key: server_peer.public_key.clone(),
            },
        };

        Ok(invitation)
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
    pub fn new(
        network_name: &InterfaceName,
        peer: &Peer,
        server_peer: &Peer,
        root_cidr: &Cidr,
        keypair: KeyPair,
        server_api_addr: &SocketAddr,
    ) -> Result<Self, Error> {
        let interface_config = InterfaceConfig::new(
            network_name,
            peer,
            server_peer,
            root_cidr,
            keypair,
            server_api_addr,
        )?;

        Ok(Self { interface_config })
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

        file.write_all(self.interface_config.contents().as_bytes())?;

        Ok(())
    }
}
