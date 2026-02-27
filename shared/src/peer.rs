use crate::{Hostname, PeerContents, Timestring, PERSISTENT_KEEPALIVE_INTERVAL_SECS};
use std::{net::IpAddr, time::SystemTime};
use wireguard_control::KeyPair;

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
