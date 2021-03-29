use crossbeam::channel::{self, select};
use dashmap::DashMap;
use wgctrl::DeviceInfo;

use std::{io, net::SocketAddr, sync::Arc, thread, time::Duration};

pub struct Endpoints {
    pub endpoints: Arc<DashMap<String, SocketAddr>>,
    stop_tx: channel::Sender<()>,
}

impl std::ops::Deref for Endpoints {
    type Target = DashMap<String, SocketAddr>;

    fn deref(&self) -> &Self::Target {
        &self.endpoints
    }
}

impl Endpoints {
    pub fn new(iface: &str) -> Result<Self, io::Error> {
        let endpoints = Arc::new(DashMap::new());
        let (stop_tx, stop_rx) = channel::bounded(1);

        let iface = iface.to_owned();
        let thread_endpoints = endpoints.clone();
        log::info!("spawning endpoint watch thread.");
        if cfg!(not(test)) {
            thread::spawn(move || loop {
                select! {
                    recv(stop_rx) -> _ => {
                        break;
                    },
                    default => {
                        if let Ok(info) = DeviceInfo::get_by_name(&iface) {
                            for peer in info.peers {
                                if let Some(endpoint) = peer.config.endpoint {
                                    thread_endpoints.insert(peer.config.public_key.to_base64(), endpoint);
                                }
                            }
                        }

                        thread::sleep(Duration::from_secs(1));
                    }
                }
            });
        }
        Ok(Self { endpoints, stop_tx })
    }
}

impl Drop for Endpoints {
    fn drop(&mut self) {
        let _ = self.stop_tx.send(());
    }
}
