use shared::Peer;

use crate::Session;

pub mod admin;
pub mod user;

/// Inject the collected endpoints from the WG interface into a list of peers.
/// This is essentially what adds NAT holepunching functionality.
pub fn inject_endpoints(session: &Session, peers: &mut Vec<Peer>) {
    for peer in peers {
        if peer.contents.endpoint.is_none() {
            if let Some(endpoint) = session.context.endpoints.read().get(&peer.public_key) {
                peer.contents.endpoint = Some(endpoint.to_owned().into());
            }
        }
    }
}
