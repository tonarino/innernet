use crate::rest_client::RestClient;
use anyhow::Error;
use innernet_shared::{
    interface_config::PeerInvitation,
    peer::{make_peer_contents_and_key_pair, NewPeerInfo},
    CidrTree, Peer,
};
use std::net::SocketAddr;
use wireguard_control::InterfaceName;

/// Create a new innernet [`Peer`] and a [`PeerInvitation`] they can use to join the network.
//
//  TODO(mbernat): The shape of this API is only provisional, it reflects the client-side `add-peer`
//                 CLI, where it was pulled from.
//                 See https://github.com/tonarino/innernet/pull/382#discussion_r2859409122
pub fn create_peer_and_invitation(
    rest_client: &RestClient,
    interface: &InterfaceName,
    cidr_tree: &CidrTree,
    server_peer: &Peer,
    new_peer_info: NewPeerInfo,
    server_api_addr: &SocketAddr,
) -> Result<(Peer, PeerInvitation), Error> {
    let (peer_contents, keypair) = make_peer_contents_and_key_pair(new_peer_info);
    let peer = rest_client.create_peer(&peer_contents)?;
    let invitation = PeerInvitation::new(
        interface,
        &peer,
        server_peer,
        cidr_tree,
        keypair,
        server_api_addr,
    )?;

    Ok((peer, invitation))
}
