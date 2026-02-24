use crate::rest_client::RestClient;
use anyhow::Error;
use innernet_shared::{
    peer::{self, NewPeerInfo},
    CidrTree, Peer,
};
use std::net::SocketAddr;
use wireguard_control::InterfaceName;

pub fn create_peer_and_invitation(
    interface: &InterfaceName,
    rest_client: RestClient,
    cidr_tree: &CidrTree,
    server_peer: &Peer,
    new_peer_info: NewPeerInfo,
    target_path: &str,
    server_api_addr: &SocketAddr,
) -> Result<Peer, Error> {
    let (peer_contents, keypair) = peer::make_peer_contents_and_key_pair(new_peer_info);
    let peer: Peer = rest_client.http_form("POST", "/admin/peers", peer_contents)?;
    peer::write_peer_invitation(
        target_path,
        interface,
        &peer,
        server_peer,
        cidr_tree,
        keypair,
        server_api_addr,
    )?;

    Ok(peer)
}
