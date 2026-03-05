//! This library can be used to control innernet interfaces.
//!
//! This is a work in progress but the final goal is to match the `innernet` CLI API surface.

pub use innernet_shared::{CidrTree, HostsOpts, NatOpts, NetworkOpts};
pub use wireguard_control::Backend;

use anyhow::Error;
use innernet_shared::wg;
use std::path::Path;

pub mod data_store;
pub mod interface;
mod nat;
pub mod peer;
pub mod rest_client;

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
