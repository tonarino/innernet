use parking_lot::RwLock;
use wgctrl::{DeviceInfo, InterfaceName};

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{
        mpsc::{sync_channel, SyncSender, TryRecvError},
        Arc,
    },
    thread,
    time::Duration,
};

pub struct Endpoints {
    pub endpoints: Arc<RwLock<HashMap<String, SocketAddr>>>,
    stop_tx: SyncSender<()>,
}

impl std::ops::Deref for Endpoints {
    type Target = RwLock<HashMap<String, SocketAddr>>;

    fn deref(&self) -> &Self::Target {
        &self.endpoints
    }
}

impl Endpoints {
    pub fn new(iface: &InterfaceName) -> Result<Self, io::Error> {
        let endpoints = Arc::new(RwLock::new(HashMap::new()));
        let (stop_tx, stop_rx) = sync_channel(1);

        let iface = iface.to_owned();
        let thread_endpoints = endpoints.clone();
        log::info!("spawning endpoint watch thread.");
        if cfg!(not(test)) {
            thread::spawn(move || loop {
                if matches!(stop_rx.try_recv(), Ok(_) | Err(TryRecvError::Disconnected)) {
                    break;
                }
                if let Ok(info) = DeviceInfo::get_by_name(&iface) {
                    for peer in info.peers {
                        if let Some(endpoint) = peer.config.endpoint {
                            thread_endpoints
                                .write()
                                .insert(peer.config.public_key.to_base64(), endpoint);
                        }
                    }
                }

                thread::sleep(Duration::from_secs(1));
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
