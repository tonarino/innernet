//! ICE-like NAT traversal logic.
//!
//! Doesn't follow the specific ICE protocol, but takes great inspiration from RFC 8445
//! and applies it to a protocol more specific to innernet.

use std::time::{Duration, Instant};

use anyhow::Error;
use shared::{
    wg::{DeviceExt, PeerInfoExt},
    Endpoint, Peer, PeerDiff,
};
use wireguard_control::{Backend, Device, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder};

pub const STEP_INTERVAL: Duration = Duration::from_secs(5);

pub struct NatTraverse<'a> {
    interface: &'a InterfaceName,
    backend: Backend,
    remaining: Vec<Peer>,
}

impl<'a> NatTraverse<'a> {
    pub fn new(
        interface: &'a InterfaceName,
        backend: Backend,
        diffs: &[PeerDiff],
    ) -> Result<Self, Error> {
        // Filter out removed peers from diffs list.
        let mut remaining: Vec<_> = diffs.iter().filter_map(|diff| diff.new).cloned().collect();

        for peer in &mut remaining {
            // Limit reported alternative candidates to 10.
            peer.candidates.truncate(10);

            // Remove server-reported endpoint from elsewhere in the list if it existed.
            let endpoint = peer.endpoint.clone();
            peer.candidates
                .retain(|addr| Some(addr) != endpoint.as_ref());

            // Add the server-reported endpoint to the beginning of the list. In the event
            // no other endpoints worked, the remaining endpoint in the list will be the one
            // assigned to the peer so it should default to the server-reported endpoint.
            // This is inserted at the beginning of the Vec as candidates are popped from
            // the end as the algorithm progresses.
            if let Some(endpoint) = endpoint {
                peer.candidates.insert(0, endpoint);
            }
        }
        let mut nat_traverse = Self {
            interface,
            backend,
            remaining,
        };

        nat_traverse.refresh_remaining()?;

        Ok(nat_traverse)
    }

    pub fn is_finished(&self) -> bool {
        self.remaining.is_empty()
    }

    pub fn remaining(&self) -> usize {
        self.remaining.len()
    }

    /// Refreshes the current state of candidate traversal attempts, filtering out
    /// the peers that have been exhausted of all endpoint options.
    fn refresh_remaining(&mut self) -> Result<(), Error> {
        let device = Device::get(self.interface, self.backend)?;
        // Remove connected and missing peers
        self.remaining.retain(|peer| {
            if let Some(peer_info) = device.get_peer(&peer.public_key) {
                let recently_connected = peer_info.is_recently_connected();
                if recently_connected {
                    log::debug!(
                        "peer {} removed from NAT traverser (connected!).",
                        peer.name
                    );
                }
                !recently_connected
            } else {
                log::debug!(
                    "peer {} removed from NAT traverser (no longer on interface).",
                    peer.name
                );
                false
            }
        });

        self.remaining.retain(|peer| !peer.candidates.is_empty());

        Ok(())
    }

    pub fn step(&mut self) -> Result<(), Error> {
        self.refresh_remaining()?;

        // Set all peers' endpoints to their next available candidate.
        let candidate_updates = self.remaining.iter_mut().filter_map(|peer| {
            let endpoint = peer.candidates.pop();
            if let Some(endpoint) = &endpoint {
                log::debug!("trying endpoint {} for peer {}", endpoint, peer.name);
            }
            set_endpoint(&peer.public_key, endpoint.as_ref())
        });

        let updates: Vec<_> = candidate_updates.collect();

        DeviceUpdate::new()
            .add_peers(&updates)
            .apply(self.interface, self.backend)?;

        let start = Instant::now();
        while start.elapsed() < STEP_INTERVAL {
            self.refresh_remaining()?;

            if self.is_finished() {
                log::debug!("NAT traverser is finished!");
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        Ok(())
    }
}

/// Return a PeerConfigBuilder if an endpoint exists and resolves successfully.
fn set_endpoint(public_key: &str, endpoint: Option<&Endpoint>) -> Option<PeerConfigBuilder> {
    endpoint
        .and_then(|endpoint| endpoint.resolve().ok())
        .map(|addr| {
            PeerConfigBuilder::new(&Key::from_base64(public_key).unwrap()).set_endpoint(addr)
        })
}
