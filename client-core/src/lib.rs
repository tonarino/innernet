//! This library can be used to control innernet interfaces.
//!
//! This is a work in progress but the final goal is to match the `innernet` CLI API surface.

pub use innernet_shared::{
    CidrTree, Endpoint, HostsOpts, NatOpts, NetworkOpts, WrappedIoError, DEFAULT_HOSTS_PATH,
};
pub use wireguard_control::Backend;

use crate::rest_client::RestError;
use anyhow::Error;
use innernet_shared::wg;
use std::{io, path::Path};
use thiserror::Error;

pub mod data_store;
pub mod interface;
mod nat;
pub mod peer;
pub mod rest_client;

pub const DEFAULT_CONFIG_DIR: &str = "/etc/innernet";

#[cfg(not(target_os = "openbsd"))]
pub const DEFAULT_DATA_DIR: &str = "/var/lib/innernet";
#[cfg(target_os = "openbsd")]
pub const DEFAULT_DATA_DIR: &str = "/var/db/innernet";

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("Error accessing innernet interface config file: {0}")]
    InterfaceConfigAccess(WrappedIoError),
    #[error("Config file for innernet interface {0} already exists.")]
    InterfaceConfigExists(interface::InterfaceName),
    #[error("WireGuard interface {0} already exists.")]
    WireguardInterfaceExists(interface::InterfaceName),
    #[error("Could not resolve server address for endpoint {endpoint}: {error}")]
    ServerAddressResolve {
        endpoint: Endpoint,
        error: io::Error,
    },
    #[error("Error managing the Wireguard interface {interface}: {error}")]
    WireguardOperation {
        interface: interface::InterfaceName,
        error: io::Error,
    },
    #[error("Error making a REST request: {0}")]
    RestRequest(#[from] RestError),
}

/// Set the `listen_port`. `None` value unsets it.
pub fn set_listen_port(
    network_backend: Backend,
    config_dir: &Path,
    interface: &interface::InterfaceName,
    config: &mut interface::InterfaceConfig,
    listen_port: Option<u16>,
) -> Result<(), Error> {
    wg::set_listen_port(interface, listen_port, network_backend)?;
    log::info!("the wireguard interface is updated");

    config.interface.listen_port = listen_port;
    config.save(config_dir, interface)?;
    log::info!("the config file is updated");

    Ok(())
}
