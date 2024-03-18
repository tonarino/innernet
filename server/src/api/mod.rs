use shared::Peer;

use crate::Session;

pub mod admin;
pub mod user;

/// Inject the collected endpoints from the WG interface into a list of peers.
/// This is essentially what adds NAT holepunching functionality. If a peer
/// already has an endpoint specified (by calling the override-endpoint) API,
/// the relatively recent wireguard endpoint will be added to the list of NAT
/// candidates, so other peers have a better chance of connecting.
pub fn inject_endpoints(session: &Session, peers: &mut Vec<Peer>) {
    for peer in peers {
        let endpoints = session.context.endpoints.read();
        let wg_endpoint = endpoints.get(&peer.public_key);

        if peer.contents.endpoint.is_some() {
            if let Some(wg_endpoint) = wg_endpoint {
                // The peer already has an endpoint specified, but it might be stale.
                // If there is an endpoint reported from wireguard, we should add it
                // to the list of candidates so others can try to connect using it.
                peer.contents.candidates.push(wg_endpoint.to_owned().into());
            }
        } else if let Some(wg_endpoint) = wg_endpoint {
            peer.contents.endpoint = Some(wg_endpoint.to_owned().into());
        }
    }
}
