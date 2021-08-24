//! ICE-esque connection attempt handler.

use anyhow::{Error};
use shared::{Peer, PeerDiff, wg::{DeviceExt, PeerInfoExt}};
use wgctrl::{Device, DeviceUpdate, Key, PeerConfigBuilder};

pub struct EndpointTester {
    efforts: Vec<Peer>,
}

impl EndpointTester {
    pub fn new(diffs: &[PeerDiff]) -> Self {
        let efforts = diffs.iter()
            .filter_map(|diff| diff.new)
            .cloned()
            .collect::<Vec<_>>();
        Self {
            efforts
        }
    }

    pub fn is_finished(&self) -> bool {
        self.efforts.is_empty()
    }

    pub fn remaining(&self) -> usize {
        self.efforts.len()
    }

    pub fn step(&mut self, device: Device) -> Result<(), Error> {
        self.efforts.retain(|peer| {
            if let Some(peer) = device.get_peer(&peer.public_key) {
                !peer.is_recently_connected()
            } else {
                peer.endpoint.is_some() || !peer.candidates.is_empty()
            }
        });

        let updates = self.efforts.iter_mut()
            .filter_map(|peer| {
                peer.endpoint.take()
                    .or_else(|| peer.candidates.pop())
                    .and_then(|endpoint| endpoint.resolve().ok())
                    .map(|addr| PeerConfigBuilder::new(&Key::from_base64(&peer.public_key).unwrap()).set_endpoint(addr))
            }).collect::<Vec<_>>();

        DeviceUpdate::new()
            .add_peers(&updates)
            .apply(&device.name, device.backend)?;
        Ok(())
    }
}
