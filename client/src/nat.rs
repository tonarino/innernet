//! ICE-like NAT traversal logic.
//!
//! Doesn't follow the specific ICE protocol, but takes great inspiration from RFC 8445
//! and applies it to a protocol more specific to innernet.

use std::time::{Duration, Instant};

use anyhow::Error;
use shared::{
    wg::{DeviceExt, PeerInfoExt},
    Peer, PeerDiff,
};
use wgctrl::{Backend, Device, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder};

pub struct NatTraverse<'a> {
    interface: &'a InterfaceName,
    backend: Backend,
    remaining: Vec<Peer>,
}

impl<'a> NatTraverse<'a> {
    pub fn new(interface: &'a InterfaceName, backend: Backend, diffs: &[PeerDiff]) -> Self {
        let remaining = diffs
            .iter()
            .filter_map(|diff| diff.new)
            .cloned()
            .collect::<Vec<_>>();
        Self {
            interface,
            backend,
            remaining,
        }
    }

    pub fn is_finished(&self) -> bool {
        self.remaining.is_empty()
    }

    pub fn remaining(&self) -> usize {
        self.remaining.len()
    }

    fn refresh_remaining(&mut self) -> Result<(), Error> {
        let device = Device::get(self.interface, self.backend)?;
        self.remaining.retain(|peer| {
            if peer.endpoint.is_none() && peer.candidates.is_empty() {
                log::debug!(
                    "peer {} removed from NAT traverser (no remaining candidates).",
                    peer.name
                );
                false
            } else if let Some(peer_info) = device.get_peer(&peer.public_key) {
                let recently_connected = peer_info.is_recently_connected();
                if recently_connected {
                    log::debug!("peer {} removed from NAT traverser (connected!).", peer.name);
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
        Ok(())
    }

    pub fn step(&mut self) -> Result<(), Error> {
        self.refresh_remaining()?;

        let updates = self
            .remaining
            .iter_mut()
            .filter_map(|peer| {
                peer.endpoint
                    .take()
                    .or_else(|| peer.candidates.pop())
                    .and_then(|endpoint| endpoint.resolve().ok())
                    .map(|addr| {
                        PeerConfigBuilder::new(&Key::from_base64(&peer.public_key).unwrap())
                            .set_endpoint(addr)
                    })
            })
            .collect::<Vec<_>>();

        DeviceUpdate::new()
            .add_peers(&updates)
            .apply(self.interface, self.backend)?;

        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
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
