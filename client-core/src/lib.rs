//! This library can be used to control innernet interfaces.
//!
//! This is a work in progress but the final goal is to match the `innernet` CLI API surface.

use anyhow::Error;
use innernet_shared::{interface_config::InterfaceConfig, wg};
use std::path::Path;
use wireguard_control::{Backend, InterfaceName};

pub mod data_store;
pub mod peer;
pub mod rest_client;

/// Set the `listen_port`. `None` value unsets it.
pub fn set_listen_port(
    config: &mut InterfaceConfig,
    config_dir: &Path,
    interface: &InterfaceName,
    network_backend: Backend,
    listen_port: Option<u16>,
) -> Result<(), Error> {
    wg::set_listen_port(interface, listen_port, network_backend)?;
    log::info!("the wireguard interface is updated");

    config.interface.listen_port = listen_port;
    config.write_to_interface(config_dir, interface)?;
    log::info!("the config file is updated");

    Ok(())
}
