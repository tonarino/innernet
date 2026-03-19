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
}

/// Create a new innernet [`Peer`] and a [`PeerInvitation`] they can use to join the network.
pub fn create_peer(
    context: &Context,
    existing_cidrs: &[Cidr],
    new_peer_info: NewPeerInfo,
) -> Result<(Peer, PeerInvitation), CreatePeerError> {
    let keypair = KeyPair::generate();
    let peer_contents = new_peer_info.into_peer_contents(&keypair);
    let peer = context.rest_client().create_peer(&peer_contents)?;

    let cidr_tree = CidrTree::new(existing_cidrs);
    let address = &cidr_tree
        .ip_net_for(peer.ip)
        .expect("Peer's IpNet address to be valid because the peer was created successfully.");
    let interface_info = InterfaceInfo::new(&context.interface, &keypair, *address);

    Ok((
        peer,
        PeerInvitation::new(interface_info, context.server_info().clone()),
    ))
}
