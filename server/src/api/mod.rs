use std::net::SocketAddr;

use crate::Session;
use shared::{Endpoint, Peer};

pub mod admin;
pub mod user;

/// Implements NAT traversal strategies.
/// (1) NAT holepunching: Report the most recent wireguard endpoint as the peer's
///     endpoint or add it to the list of NAT candidates if an override enpoint is
///     specified. Note that NAT traversal does not always work e.g. if the peer is
///     behind double NAT or address/port restricted cone NAT.
/// (2) Unspecified endpoint IP: A peer may report an override endpoint with
///     an unspecified IP. It typically indicates the peer does not have a fixed
///     global IP, and it needs help from the innernet server to resolve it.
///     Override the endpoint IP with what's most recently reported by wireguard.
pub fn inject_endpoints(session: &Session, peers: &mut Vec<Peer>) {
    for peer in peers {
        let endpoints = session.context.endpoints.read();
        if let Some(wg_endpoint) = endpoints.get(&peer.public_key) {
            let wg_endpoint_ip = wg_endpoint.ip();
            let wg_endpoint: Endpoint = wg_endpoint.to_owned().into();
            if let Some(endpoint) = &mut peer.contents.endpoint {
                if endpoint.is_host_unspecified() {
                    // (2) Unspecified endpoint host
                    *endpoint = SocketAddr::new(wg_endpoint_ip, endpoint.port()).into();
                } else if *endpoint != wg_endpoint {
                    // (1) NAT holepunching
                    // The peer already has an endpoint specified, but it might be stale.
                    // If there is an endpoint reported from wireguard, we should add it
                    // to the list of candidates so others can try to connect using it.
                    peer.contents.candidates.push(wg_endpoint);
                }
            } else {
                // (1) NAT holepunching
                peer.contents.endpoint = Some(wg_endpoint);
            }
        }
    }
}
