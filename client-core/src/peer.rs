pub use innernet_shared::peer::NewPeerInfo;

use crate::{
    rest_client::{RestClient, RestError},
    Cidr, Peer, PeerInvitation,
};
use anyhow::Result;
use innernet_shared::{
    interface_config::{InterfaceConfig, InterfaceInfo, ServerInfo},
    CidrTree,
};
use std::path::Path;
use thiserror::Error;
use wireguard_control::{InterfaceName, KeyPair};

#[derive(Debug, Error)]
pub enum CreatePeerError {
    // TODO(mbernat): Use a custom error type in the InterfaceConfig methods.
    #[error("Error accessing innernet interface config file: {0}")]
    InterfaceConfigAccess(anyhow::Error),
    #[error("Error making a REST request: {0}")]
    RestRequest(#[from] RestError),
    #[error("Root CIDR prefix is longer than the new peer IP. Trying to use IPv4 address on an IPv6 CIDR?")]
    PeerIpPrefixMismatch,
}

/// Create a new innernet [`Peer`] and a [`PeerInvitation`] they can use to join the network.
pub fn create_peer(
    config_dir: &Path,
    interface: &InterfaceName,
    cidrs: &[Cidr],
    peers: &[Peer],
    new_peer_info: NewPeerInfo,
) -> Result<(Peer, PeerInvitation), CreatePeerError> {
    let interface_config = InterfaceConfig::from_interface(config_dir, interface)
        .map_err(CreatePeerError::InterfaceConfigAccess)?;
    let rest_client = RestClient::new(&interface_config.server);

    let keypair = KeyPair::generate();
    let peer_contents = new_peer_info.into_peer_contents(&keypair);
    let peer = rest_client.create_peer(&peer_contents)?;

    let cidr_tree = CidrTree::new(cidrs);
    let address = &cidr_tree
        .ip_net_for(peer.ip)
        .map_err(|_| CreatePeerError::PeerIpPrefixMismatch)?;
    let interface_info = InterfaceInfo::new(interface, &keypair, address);

    let server_peer = peers.iter().find(|p| p.id == 1).unwrap();
    let server_info = ServerInfo::new(server_peer, &interface_config.server.internal_endpoint);

    Ok((peer, PeerInvitation::new(interface_info, server_info)))
}
