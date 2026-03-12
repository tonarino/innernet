pub use innernet_shared::peer::NewPeerInfo;

use crate::{rest_client::RestError, Cidr, Context, Peer, PeerInvitation};
use anyhow::Result;
use innernet_shared::{interface_config::InterfaceInfo, CidrTree};
use thiserror::Error;
use wireguard_control::KeyPair;

#[derive(Debug, Error)]
pub enum CreatePeerError {
    #[error("Error making a REST request: {0}")]
    RestRequest(#[from] RestError),
    #[error("Root CIDR prefix is longer than the new peer IP. Trying to use IPv4 address on an IPv6 CIDR?")]
    PeerIpPrefixMismatch,
}

/// Create a new innernet [`Peer`] and a [`PeerInvitation`] they can use to join the network.
pub fn create_peer(
    context: &Context,
    cidrs: &[Cidr],
    new_peer_info: NewPeerInfo,
) -> Result<(Peer, PeerInvitation), CreatePeerError> {
    let keypair = KeyPair::generate();
    let peer_contents = new_peer_info.into_peer_contents(&keypair);
    let peer = context.rest_client().create_peer(&peer_contents)?;

    let cidr_tree = CidrTree::new(cidrs);
    let address = &cidr_tree
        .ip_net_for(peer.ip)
        .map_err(|_| CreatePeerError::PeerIpPrefixMismatch)?;
    let interface_info = InterfaceInfo::new(&context.interface, &keypair, address);

    Ok((
        peer,
        PeerInvitation::new(interface_info, context.server_info().clone()),
    ))
}
