use crate::{
    interface_config::{InterfaceConfig, InterfaceInfo, ServerInfo},
    Cidr, Error, Hostname, Peer, PeerContents, Timestring, PERSISTENT_KEEPALIVE_INTERVAL_SECS,
};
use ipnet::IpNet;
use std::{
    fs::OpenOptions,
    net::{IpAddr, SocketAddr},
    time::SystemTime,
};
use wireguard_control::{InterfaceName, KeyPair};

pub struct NewPeerInfo {
    pub name: Hostname,
    pub ip: IpAddr,
    pub cidr_id: i64,
    pub is_admin: bool,
    pub invite_expires: Timestring,
}

pub fn make_peer_contents_and_key_pair(info: NewPeerInfo) -> (PeerContents, KeyPair) {
    let default_keypair = KeyPair::generate();
    let peer_contents = PeerContents {
        name: info.name,
        ip: info.ip,
        cidr_id: info.cidr_id,
        public_key: default_keypair.public.to_base64(),
        endpoint: None,
        is_admin: info.is_admin,
        is_disabled: false,
        is_redeemed: false,
        persistent_keepalive_interval: Some(PERSISTENT_KEEPALIVE_INTERVAL_SECS),
        invite_expires: Some(SystemTime::now() + info.invite_expires.into()),
        candidates: vec![],
    };

    (peer_contents, default_keypair)
}

pub fn write_peer_invitation(
    target_file_name: &str,
    network_name: &InterfaceName,
    peer: &Peer,
    server_peer: &Peer,
    root_cidr: &Cidr,
    keypair: KeyPair,
    server_api_addr: &SocketAddr,
) -> Result<(), Error> {
    let mut target_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(target_file_name)?;

    let peer_invitation = InterfaceConfig {
        interface: InterfaceInfo {
            network_name: network_name.to_string(),
            private_key: keypair.private.to_base64(),
            address: IpNet::new(peer.ip, root_cidr.prefix_len())?,
            listen_port: None,
        },
        server: ServerInfo {
            external_endpoint: server_peer
                .endpoint
                .clone()
                .expect("The innernet server should have a WireGuard endpoint"),
            internal_endpoint: *server_api_addr,
            public_key: server_peer.public_key.clone(),
        },
    };

    peer_invitation.write_to(&mut target_file, true, None)?;

    Ok(())
}
