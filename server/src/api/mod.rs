use std::net::SocketAddr;

use crate::Session;
use shared::{Endpoint, Peer};

pub mod admin;
pub mod user;

/// Implements NAT traversal strategies.
/// (1) Unspecified endpoint IP: a peer may configure an override endpoint with an unspecified IP.
///     This can be useful if the peer uses a port forwarding with a fixed port but does not have a
///     fixed global IP and it needs help from the innernet server to resolve it. Replace the
///     endpoint IP with the most recent wireguard endpoint's IP.
/// (2) NAT hole punching: Report the most recent wireguard endpoint either (a) as the peer's
///     endpoint or (b) add it to the list of NAT candidates, if an override endpoint is specified.
///     Note that NAT traversal does not always work e.g. if the peer is behind double NAT or
///     address/port restricted cone NAT.
pub fn inject_endpoints(session: &Session, peers: &mut Vec<Peer>) {
    for peer in peers {
        let endpoints = session.context.endpoints.read();
        let wg_endpoint = endpoints.get(&peer.public_key);

        match &mut peer.contents.endpoint {
            None => {
                // 2a. Set the peer endpoint to the wireguard endpoint.
                peer.contents.endpoint = wg_endpoint.map(|e| e.to_owned().into())
            },
            Some(peer_endpoint) => {
                if peer_endpoint.is_host_unspecified() {
                    if let Some(wg_endpoint) = wg_endpoint {
                        // 1. Replace the unspecified peer endpoint host with the wireguard
                        //    endpoint's host.
                        *peer_endpoint =
                            SocketAddr::new(wg_endpoint.ip(), peer_endpoint.port()).into();
                    } else {
                        // There is no way to complete the peer endpoint, unset it.
                        peer.contents.endpoint = None;
                    }
                }
            },
        }

        if let Some(wg_endpoint) = wg_endpoint {
            // 2b. Add the wireguard endpoint to the peer candidates, unless it's already present
            // either in the peer endpoint or in the peer candidates.
            let wg_endpoint: Endpoint = wg_endpoint.to_owned().into();

            if peer.contents.endpoint.as_ref() != Some(&wg_endpoint)
                && !peer.candidates.contains(&wg_endpoint)
            {
                peer.candidates.push(wg_endpoint);
            }
        }
    }
}
