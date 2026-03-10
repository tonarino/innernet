pub use innernet_shared::peer::NewPeerInfo;

use crate::{rest_client::RestClient, Cidr, Peer, PeerInvitation};
use anyhow::Result;
use innernet_shared::{
    interface_config::{InterfaceConfig, InterfaceInfo, ServerInfo},
    CidrTree,
};
use std::path::Path;
use wireguard_control::{InterfaceName, KeyPair};

/// Create a new innernet [`Peer`] and a [`PeerInvitation`] they can use to join the network.
//
//  TODO: custom error type
pub fn create_peer(
    config_dir: &Path,
    interface: &InterfaceName,
    cidrs: &[Cidr],
    peers: &[Peer],
    new_peer_info: NewPeerInfo,
) -> Result<(Peer, PeerInvitation)> {
    let interface_config = InterfaceConfig::from_interface(config_dir, interface)?;
    let rest_client = RestClient::new(&interface_config.server);

    let keypair = KeyPair::generate();
    let peer_contents = new_peer_info.into_peer_contents(&keypair);
    let peer = rest_client.create_peer(&peer_contents)?;

    let cidr_tree = CidrTree::new(cidrs);
    let address = &cidr_tree.ip_net_for(peer.ip)?;
    let interface_info = InterfaceInfo::new(interface, &keypair, address);

    let server_peer = peers.iter().find(|p| p.id == 1).unwrap();
    let server_info = ServerInfo::new(server_peer, &interface_config.server.internal_endpoint);

    Ok((peer, PeerInvitation::new(interface_info, server_info)))
}
