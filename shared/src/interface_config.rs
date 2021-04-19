use crate::{ensure_dirs_exist, Endpoint, Error, IoErrorContext, CLIENT_CONFIG_PATH};
use colored::*;
use indoc::writedoc;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use wgctrl::InterfaceName;

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
    pub address: IpNetwork,

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
    pub fn write_to_path<P: AsRef<Path>>(
        &self,
        path: P,
        comments: bool,
        mode: Option<u32>,
    ) -> Result<(), Error> {
        let path = path.as_ref();
        let mut target_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .with_path(path)?;
        if let Some(val) = mode {
            if crate::chmod(&target_file, 0o600)? {
                println!(
                    "{} updated permissions for {} to 0600.",
                    "[!]".yellow(),
                    path.display()
                );
            }
            let metadata = target_file.metadata()?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(val);
        }

        if comments {
            writedoc!(
                target_file,
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
        }
        target_file
            .write_all(toml::to_string(self).unwrap().as_bytes())
            .with_path(path)?;
        Ok(())
    }

    /// Overwrites the config file if it already exists.
    pub fn write_to_interface(&self, interface: &InterfaceName) -> Result<PathBuf, Error> {
        let path = Self::build_config_file_path(interface)?;
        File::create(&path)
            .with_path(&path)?
            .write_all(toml::to_string(self).unwrap().as_bytes())?;
        Ok(path)
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        Ok(toml::from_slice(&std::fs::read(&path).with_path(path)?)?)
    }

    pub fn from_interface(interface: &InterfaceName) -> Result<Self, Error> {
        let path = Self::build_config_file_path(interface)?;
        let file = File::open(&path).with_path(&path)?;
        if crate::chmod(&file, 0o600)? {
            println!(
                "{} updated permissions for {} to 0600.",
                "[!]".yellow(),
                path.display()
            );
        }
        Self::from_file(path)
    }

    pub fn get_path(interface: &InterfaceName) -> PathBuf {
        CLIENT_CONFIG_PATH
            .join(interface.to_string())
            .with_extension("conf")
    }

    fn build_config_file_path(interface: &InterfaceName) -> Result<PathBuf, Error> {
        ensure_dirs_exist(&[*CLIENT_CONFIG_PATH])?;
        Ok(Self::get_path(interface))
    }
}

impl InterfaceInfo {
    pub fn public_key(&self) -> Result<String, Error> {
        Ok(wgctrl::Key::from_base64(&self.private_key)?
            .generate_public()
            .to_base64())
    }
}
