//! This library can be used to control innernet interfaces.
//!
//! This is a work in progress but the final goal is to match the `innernet` CLI API surface.

pub use innernet_shared::{
    interface_config::PeerInvitation, Cidr, CidrContents, CidrTree, Endpoint, HostsOpts, NatOpts,
    NetworkOpts, Peer, WrappedIoError, DEFAULT_HOSTS_PATH,
};
pub use wireguard_control::Backend;

use crate::rest_client::RestClient;
use anyhow::Error;
use innernet_shared::{
    interface_config::{InterfaceConfig, InterfaceInfo, ServerInfo},
    wg,
};
use std::path::PathBuf;
use ureq::Agent;
use wireguard_control::InterfaceName;

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

/// [`Context`] contains data required by most public API functions.
/// - [`Self::interface_info()`] produces an [`InterfaceInfo`] about an innernet interface.
/// - [`Self::server_info()`] produces a [`ServerInfo`] about an innernet server.
/// - [`Self::rest_client()`] produces a [`RestClient`] that can talk to an innernet server.
pub struct Context {
    config_dir: PathBuf,
    interface: InterfaceName,
    interface_config: InterfaceConfig,
    agent: Agent,
}

impl Context {
    // TODO(mbernat): Use a custom error type in the InterfaceConfig methods.
    pub fn new(config_dir: PathBuf, interface: interface::InterfaceName) -> Result<Self, Error> {
        let interface_config = InterfaceConfig::from_interface(&config_dir, &interface)?;
        let agent = RestClient::create_agent();

        Ok(Self {
            config_dir,
            interface,
            interface_config,
            agent,
        })
    }

    pub fn interface_info(&self) -> &InterfaceInfo {
        &self.interface_config.interface
    }

    pub fn server_info(&self) -> &ServerInfo {
        &self.interface_config.server
    }

    pub fn rest_client(&self) -> RestClient<'_> {
        RestClient::new(&self.agent, &self.interface_config.server)
    }
}

/// Set the `listen_port`. `None` value unsets it.
pub fn set_listen_port(
    context: &mut Context,
    network_backend: Backend,
    listen_port: Option<u16>,
) -> Result<(), Error> {
    wg::set_listen_port(&context.interface, listen_port, network_backend)?;
    log::info!("the wireguard interface is updated");

    let config = &mut context.interface_config;
    config.interface.listen_port = listen_port;
    config.save(&context.config_dir, &context.interface)?;
    log::info!("the config file is updated");

    Ok(())
}
