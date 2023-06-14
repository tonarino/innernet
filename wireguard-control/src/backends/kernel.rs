use crate::{
    device::AllowedIp, Backend, Device, DeviceUpdate, InterfaceName, Key, PeerConfig,
    PeerConfigBuilder, PeerInfo, PeerStats,
};
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_REQUEST,
};
use netlink_packet_generic::GenlMessage;
use netlink_packet_route::{
    constants::*,
    link::{
        self,
        nlas::{Info, InfoKind},
    },
    LinkMessage, RtnlMessage,
};
use netlink_packet_utils::traits::Emitable;
use netlink_packet_wireguard::{
    self,
    constants::{WGDEVICE_F_REPLACE_PEERS, WGPEER_F_REMOVE_ME, WGPEER_F_REPLACE_ALLOWEDIPS},
    nlas::{WgAllowedIp, WgAllowedIpAttrs, WgDeviceAttrs, WgPeer, WgPeerAttrs},
    Wireguard, WireguardCmd,
};
use netlink_request::{max_genl_payload_length, netlink_request_genl, netlink_request_rtnl};

use std::{convert::TryFrom, io};

macro_rules! get_nla_value {
    ($nlas:expr, $e:ident, $v:ident) => {
        $nlas.iter().find_map(|attr| match attr {
            $e::$v(value) => Some(value),
            _ => None,
        })
    };
}

impl TryFrom<WgAllowedIp> for AllowedIp {
    type Error = io::Error;

    fn try_from(attrs: WgAllowedIp) -> Result<Self, Self::Error> {
        let address = *get_nla_value!(attrs, WgAllowedIpAttrs, IpAddr)
            .ok_or_else(|| io::ErrorKind::NotFound)?;
        let cidr = *get_nla_value!(attrs, WgAllowedIpAttrs, Cidr)
            .ok_or_else(|| io::ErrorKind::NotFound)?;
        Ok(AllowedIp { address, cidr })
    }
}

impl AllowedIp {
    fn to_nla(&self) -> WgAllowedIp {
        WgAllowedIp(vec![
            WgAllowedIpAttrs::Family(if self.address.is_ipv4() {
                AF_INET
            } else {
                AF_INET6
            }),
            WgAllowedIpAttrs::IpAddr(self.address),
            WgAllowedIpAttrs::Cidr(self.cidr),
        ])
    }
}

impl PeerConfigBuilder {
    fn to_nla(&self) -> WgPeer {
        let mut attrs = vec![WgPeerAttrs::PublicKey(self.public_key.0)];
        let mut flags = 0u32;
        if let Some(endpoint) = self.endpoint {
            attrs.push(WgPeerAttrs::Endpoint(endpoint));
        }
        if let Some(ref key) = self.preshared_key {
            attrs.push(WgPeerAttrs::PresharedKey(key.0));
        }
        if let Some(i) = self.persistent_keepalive_interval {
            attrs.push(WgPeerAttrs::PersistentKeepalive(i));
        }
        let allowed_ips: Vec<_> = self.allowed_ips.iter().map(AllowedIp::to_nla).collect();
        attrs.push(WgPeerAttrs::AllowedIps(allowed_ips));
        if self.remove_me {
            flags |= WGPEER_F_REMOVE_ME;
        }
        if self.replace_allowed_ips {
            flags |= WGPEER_F_REPLACE_ALLOWEDIPS;
        }
        if flags != 0 {
            attrs.push(WgPeerAttrs::Flags(flags));
        }
        WgPeer(attrs)
    }
}

impl TryFrom<WgPeer> for PeerInfo {
    type Error = io::Error;

    fn try_from(attrs: WgPeer) -> Result<Self, Self::Error> {
        let public_key = get_nla_value!(attrs, WgPeerAttrs, PublicKey)
            .map(|key| Key(*key))
            .ok_or(io::ErrorKind::NotFound)?;
        let preshared_key = get_nla_value!(attrs, WgPeerAttrs, PresharedKey).map(|key| Key(*key));
        let endpoint = get_nla_value!(attrs, WgPeerAttrs, Endpoint).cloned();
        let persistent_keepalive_interval =
            get_nla_value!(attrs, WgPeerAttrs, PersistentKeepalive).cloned();
        let allowed_ips = get_nla_value!(attrs, WgPeerAttrs, AllowedIps)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(AllowedIp::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let last_handshake_time = get_nla_value!(attrs, WgPeerAttrs, LastHandshake).cloned();
        let rx_bytes = get_nla_value!(attrs, WgPeerAttrs, RxBytes)
            .cloned()
            .unwrap_or_default();
        let tx_bytes = get_nla_value!(attrs, WgPeerAttrs, TxBytes)
            .cloned()
            .unwrap_or_default();
        Ok(PeerInfo {
            config: PeerConfig {
                public_key,
                preshared_key,
                endpoint,
                persistent_keepalive_interval,
                allowed_ips,
                __cant_construct_me: (),
            },
            stats: PeerStats {
                last_handshake_time,
                rx_bytes,
                tx_bytes,
            },
        })
    }
}

impl<'a> TryFrom<&'a [WgDeviceAttrs]> for Device {
    type Error = io::Error;

    fn try_from(nlas: &'a [WgDeviceAttrs]) -> Result<Self, Self::Error> {
        let name = get_nla_value!(nlas, WgDeviceAttrs, IfName)
            .ok_or_else(|| io::ErrorKind::NotFound)?
            .parse()?;
        let public_key = get_nla_value!(nlas, WgDeviceAttrs, PublicKey).map(|key| Key(*key));
        let private_key = get_nla_value!(nlas, WgDeviceAttrs, PrivateKey).map(|key| Key(*key));
        let listen_port = get_nla_value!(nlas, WgDeviceAttrs, ListenPort).cloned();
        let fwmark = get_nla_value!(nlas, WgDeviceAttrs, Fwmark).cloned();
        let peers = nlas
            .iter()
            .filter_map(|nla| match nla {
                WgDeviceAttrs::Peers(peers) => Some(peers.clone()),
                _ => None,
            })
            .flatten()
            .map(PeerInfo::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Device {
            name,
            public_key,
            private_key,
            listen_port,
            fwmark,
            peers,
            linked_name: None,
            backend: Backend::Kernel,
            __cant_construct_me: (),
        })
    }
}

pub fn enumerate() -> Result<Vec<InterfaceName>, io::Error> {
    let link_responses = netlink_request_rtnl(
        RtnlMessage::GetLink(LinkMessage::default()),
        Some(NLM_F_DUMP | NLM_F_REQUEST),
    )?;
    let links = link_responses
        .into_iter()
        // Filter out non-link messages
        .filter_map(|response| match response {
            NetlinkMessage {
                payload: NetlinkPayload::InnerMessage(RtnlMessage::NewLink(link)),
                ..
            } => Some(link),
            _ => None,
        })
        .filter(|link| {
            for nla in link.nlas.iter() {
                if let link::nlas::Nla::Info(infos) = nla {
                    return infos.iter().any(|info| info == &Info::Kind(InfoKind::Wireguard))
                }
            }
            false
        })
        .filter_map(|link| link.nlas.iter().find_map(|nla| match nla {
            link::nlas::Nla::IfName(name) => Some(name.clone()),
            _ => None,
        }))
        .filter_map(|name| name.parse().ok())
        .collect::<Vec<_>>();

    Ok(links)
}

fn add_del(iface: &InterfaceName, add: bool) -> io::Result<()> {
    let mut message = LinkMessage::default();
    message
        .nlas
        .push(link::nlas::Nla::IfName(iface.as_str_lossy().to_string()));
    message.nlas.push(link::nlas::Nla::Info(vec![Info::Kind(
        link::nlas::InfoKind::Wireguard,
    )]));
    let extra_flags = if add { NLM_F_CREATE | NLM_F_EXCL } else { 0 };
    let rtnl_message = if add {
        RtnlMessage::NewLink(message)
    } else {
        RtnlMessage::DelLink(message)
    };
    match netlink_request_rtnl(rtnl_message, Some(NLM_F_REQUEST | NLM_F_ACK | extra_flags)) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => Err(e),
        _ => Ok(()),
    }
}

pub fn apply(builder: &DeviceUpdate, iface: &InterfaceName) -> io::Result<()> {
    add_del(iface, true)?;
    let mut payload = ApplyPayload::new(iface);
    if let Some(Key(k)) = builder.private_key {
        payload.push(WgDeviceAttrs::PrivateKey(k))?;
    }
    if let Some(f) = builder.fwmark {
        payload.push(WgDeviceAttrs::Fwmark(f))?;
    }
    if let Some(f) = builder.listen_port {
        payload.push(WgDeviceAttrs::ListenPort(f))?;
    }
    if builder.replace_peers {
        payload.push(WgDeviceAttrs::Flags(WGDEVICE_F_REPLACE_PEERS))?;
    }

    builder
        .peers
        .iter()
        .map(|peer| payload.push_peer(peer.to_nla()))
        .collect::<Result<Vec<_>, _>>()?;

    for message in payload.finish() {
        netlink_request_genl(message, Some(NLM_F_REQUEST | NLM_F_ACK))?;
    }
    Ok(())
}

struct ApplyPayload {
    iface: String,
    nlas: Vec<WgDeviceAttrs>,
    current_buffer_len: usize,
    queue: Vec<GenlMessage<Wireguard>>,
}

impl ApplyPayload {
    fn new(iface: &InterfaceName) -> Self {
        let iface_str = iface.as_str_lossy().to_string();
        let nlas = vec![WgDeviceAttrs::IfName(iface_str.clone())];
        let current_buffer_len = nlas.as_slice().buffer_len();
        Self {
            iface: iface_str,
            nlas,
            queue: vec![],
            current_buffer_len,
        }
    }

    fn flush_nlas(&mut self) {
        // // cleanup: clear out any empty peer lists.
        self.nlas
            .retain(|nla| !matches!(nla, WgDeviceAttrs::Peers(peers) if peers.is_empty()));

        let name = WgDeviceAttrs::IfName(self.iface.clone());
        let template = vec![name];

        if !self.nlas.is_empty() && self.nlas != template {
            self.current_buffer_len = template.as_slice().buffer_len();
            let message = GenlMessage::from_payload(Wireguard {
                cmd: WireguardCmd::SetDevice,
                nlas: std::mem::replace(&mut self.nlas, template),
            });
            self.queue.push(message);
        }
    }

    /// Push a device attribute which will be optimally packed into 1 or more netlink messages
    pub fn push(&mut self, nla: WgDeviceAttrs) -> io::Result<()> {
        let max_payload_len = max_genl_payload_length();

        let nla_buffer_len = nla.buffer_len();
        if (self.current_buffer_len + nla_buffer_len) > max_payload_len {
            self.flush_nlas();
        }

        // If the NLA *still* doesn't fit...
        if (self.current_buffer_len + nla_buffer_len) > max_payload_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("encoded NLA ({nla_buffer_len} bytes) is too large: {nla:?}"),
            ));
        }
        self.nlas.push(nla);
        self.current_buffer_len += nla_buffer_len;
        Ok(())
    }

    /// A helper function to assist in breaking up large peer lists across multiple netlink messages
    pub fn push_peer(&mut self, peer: WgPeer) -> io::Result<()> {
        const EMPTY_PEERS: WgDeviceAttrs = WgDeviceAttrs::Peers(vec![]);
        let max_payload_len = max_genl_payload_length();
        let mut needs_peer_nla = !self
            .nlas
            .iter()
            .any(|nla| matches!(nla, WgDeviceAttrs::Peers(_)));
        let peer_buffer_len = peer.buffer_len();
        let mut additional_buffer_len = peer_buffer_len;
        if needs_peer_nla {
            additional_buffer_len += EMPTY_PEERS.buffer_len();
        }
        if (self.current_buffer_len + additional_buffer_len) > max_payload_len {
            self.flush_nlas();
            needs_peer_nla = true;
        }

        if needs_peer_nla {
            self.push(EMPTY_PEERS)?;
        }

        // If the peer *still* doesn't fit...
        if (self.current_buffer_len + peer_buffer_len) > max_payload_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("encoded peer ({peer_buffer_len} bytes) is too large: {peer:?}"),
            ));
        }

        let peers_nla = self
            .nlas
            .iter_mut()
            .find_map(|nla| match nla {
                WgDeviceAttrs::Peers(peers) => Some(peers),
                _ => None,
            })
            .expect("WgDeviceAttrs::Peers missing from NLAs when it should exist.");

        peers_nla.push(peer);
        self.current_buffer_len += peer_buffer_len;

        Ok(())
    }

    pub fn finish(mut self) -> Vec<GenlMessage<Wireguard>> {
        self.flush_nlas();
        self.queue
    }
}

pub fn get_by_name(name: &InterfaceName) -> Result<Device, io::Error> {
    let genlmsg: GenlMessage<Wireguard> = GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::GetDevice,
        nlas: vec![WgDeviceAttrs::IfName(name.as_str_lossy().to_string())],
    });
    let responses = netlink_request_genl(genlmsg, Some(NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK))?;
    log::debug!(
        "get_by_name: got {} response message(s) from netlink request",
        responses.len()
    );

    let nlas = responses.into_iter().fold(Ok(vec![]), |nlas_res, nlmsg| {
        let mut nlas = nlas_res?;
        let mut message = match nlmsg {
            NetlinkMessage {
                payload: NetlinkPayload::InnerMessage(message),
                ..
            } => message,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected netlink payload: {nlmsg:?}"),
                ))
            },
        };
        nlas.append(&mut message.payload.nlas);
        Ok(nlas)
    })?;
    let device = Device::try_from(&nlas[..])?;
    log::debug!(
        "get_by_name: parsed wireguard device {} with {} peer(s)",
        device.name,
        device.peers.len(),
    );
    Ok(device)
}

pub fn delete_interface(iface: &InterfaceName) -> io::Result<()> {
    add_del(iface, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_wireguard::nlas::WgAllowedIp;
    use netlink_request::max_netlink_buffer_length;
    use std::str::FromStr;

    #[test]
    fn test_simple_payload() {
        let mut payload = ApplyPayload::new(&InterfaceName::from_str("wg0").unwrap());
        payload.push(WgDeviceAttrs::PrivateKey([1u8; 32])).unwrap();
        payload.push(WgDeviceAttrs::Fwmark(111)).unwrap();
        payload.push(WgDeviceAttrs::ListenPort(12345)).unwrap();
        payload
            .push(WgDeviceAttrs::Flags(WGDEVICE_F_REPLACE_PEERS))
            .unwrap();
        payload
            .push_peer(WgPeer(vec![
                WgPeerAttrs::PublicKey([2u8; 32]),
                WgPeerAttrs::PersistentKeepalive(25),
                WgPeerAttrs::Endpoint("1.1.1.1:51820".parse().unwrap()),
                WgPeerAttrs::Flags(WGPEER_F_REPLACE_ALLOWEDIPS),
                WgPeerAttrs::AllowedIps(vec![WgAllowedIp(vec![
                    WgAllowedIpAttrs::Family(AF_INET),
                    WgAllowedIpAttrs::IpAddr([10, 1, 1, 1].into()),
                    WgAllowedIpAttrs::Cidr(24),
                ])]),
            ]))
            .unwrap();
        assert_eq!(payload.finish().len(), 1);
    }

    #[test]
    fn test_massive_payload() {
        let mut payload = ApplyPayload::new(&InterfaceName::from_str("wg0").unwrap());
        payload.push(WgDeviceAttrs::PrivateKey([1u8; 32])).unwrap();
        payload.push(WgDeviceAttrs::Fwmark(111)).unwrap();
        payload.push(WgDeviceAttrs::ListenPort(12345)).unwrap();
        payload
            .push(WgDeviceAttrs::Flags(WGDEVICE_F_REPLACE_PEERS))
            .unwrap();

        for i in 0..10_000 {
            payload
                .push_peer(WgPeer(vec![
                    WgPeerAttrs::PublicKey([2u8; 32]),
                    WgPeerAttrs::PersistentKeepalive(25),
                    WgPeerAttrs::Endpoint("1.1.1.1:51820".parse().unwrap()),
                    WgPeerAttrs::Flags(WGPEER_F_REPLACE_ALLOWEDIPS),
                    WgPeerAttrs::AllowedIps(vec![WgAllowedIp(vec![
                        WgAllowedIpAttrs::Family(AF_INET),
                        WgAllowedIpAttrs::IpAddr([10, 1, 1, 1].into()),
                        WgAllowedIpAttrs::Cidr(24),
                    ])]),
                    WgPeerAttrs::Unspec(vec![1u8; (i % 256) as usize]),
                ]))
                .unwrap();
        }

        let messages = payload.finish();
        println!("generated {} messages", messages.len());
        assert!(messages.len() > 1);
        let max_buffer_len = max_netlink_buffer_length();
        for message in messages {
            assert!(NetlinkMessage::from(message).buffer_len() <= max_buffer_len);
        }
    }
}
