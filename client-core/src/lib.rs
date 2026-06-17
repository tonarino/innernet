//! This library can be used to control innernet interfaces.
//!
//! This is a work in progress but the final goal is to match the `innernet` CLI API surface.

use crate::interface::interface_is_up;
pub use innernet_shared::{
    interface_config::PeerInvitation, Cidr, CidrTree, Endpoint, HostsOpts, NatOpts, NetworkOpts,
    Peer, WrappedIoError, DEFAULT_HOSTS_PATH,
};
pub use wireguard_control::Backend;
use wireguard_control::{DeviceUpdate, Key, PeerConfigBuilder};

use anyhow::Error;
use innernet_shared::wg;
use std::path::Path;

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

pub fn set_endpoint_override_for_peer(
    network_backend: Backend,
    config_dir: &Path,
    interface: &interface::InterfaceName,
    config: &mut interface::InterfaceConfig,
    peer: &Peer,
    endpoint: Endpoint,
) -> Result<(), Error> {
    config.set_endpoint_override_for_peer(peer.ip, endpoint.clone());
    config.save(config_dir, interface)?;

    if interface_is_up(network_backend, interface) {
        let socket_addr = endpoint.resolve()?;
        let peer_pub_key = Key::from_base64(&peer.public_key).unwrap();

        DeviceUpdate::new()
            .add_peer(PeerConfigBuilder::new(&peer_pub_key).set_endpoint(socket_addr))
            .apply(interface, network_backend)?;
    }

    Ok(())
}

pub fn unset_endpoint_override_for_peer(
    config_dir: &Path,
    interface: &interface::InterfaceName,
    config: &mut interface::InterfaceConfig,
    peer: &Peer,
) -> Result<(), Error> {
    config.unset_endpoint_override_for_peer(peer.ip);
    config.save(config_dir, interface)?;

    Ok(())
}
