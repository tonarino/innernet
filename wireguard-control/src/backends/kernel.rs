use crate::{
    device::AllowedIp, Backend, Device, DeviceUpdate, InterfaceName, PeerConfig,
    PeerConfigBuilder, PeerInfo, PeerStats, Key,
};
use netlink_packet_core::{
    NetlinkDeserializable, NetlinkMessage, NetlinkPayload, NetlinkSerializable, NLM_F_ACK,
    NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST,
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
use netlink_packet_wireguard::{
    self,
    constants::{WGDEVICE_F_REPLACE_PEERS, WGPEER_F_REMOVE_ME, WGPEER_F_REPLACE_ALLOWEDIPS},
    nlas::{WgAllowedIpAttrs, WgDeviceAttrs, WgPeerAttrs},
    Wireguard, WireguardCmd,
};
use netlink_sys::{protocols::NETLINK_ROUTE, Socket};

use std::{convert::TryFrom, io};

macro_rules! get_nla_value {
    ($nlas:expr, $e:ident, $v:ident) => {
        $nlas.iter().find_map(|attr| match attr {
            $e::$v(value) => Some(value),
            _ => None,
        })
    };
}

impl<'a> TryFrom<Vec<WgAllowedIpAttrs>> for AllowedIp {
    type Error = io::Error;

    fn try_from(attrs: Vec<WgAllowedIpAttrs>) -> Result<Self, Self::Error> {
        let address = get_nla_value!(attrs, WgAllowedIpAttrs, IpAddr)
            .ok_or_else(|| io::ErrorKind::NotFound)?
            .clone();
        let cidr = get_nla_value!(attrs, WgAllowedIpAttrs, Cidr)
            .ok_or_else(|| io::ErrorKind::NotFound)?
            .clone();
        Ok(AllowedIp { address, cidr })
    }
}

impl AllowedIp {
    fn to_attrs(&self) -> Vec<WgAllowedIpAttrs> {
        vec![
            WgAllowedIpAttrs::Family(if self.address.is_ipv4() {
                AF_INET
            } else {
                AF_INET6
            }),
            WgAllowedIpAttrs::IpAddr(self.address),
            WgAllowedIpAttrs::Cidr(self.cidr),
        ]
    }
}

impl PeerConfigBuilder {
    fn to_attrs(&self) -> Vec<WgPeerAttrs> {
        let mut attrs = vec![WgPeerAttrs::PublicKey(self.public_key.0)];
        let mut flags = 0u32;
        if let Some(endpoint) = self.endpoint {
            attrs.push(WgPeerAttrs::Endpoint(endpoint));
        }
        if let Some(ref key) = self.preshared_key {
            attrs.push(WgPeerAttrs::PresharedKey(key.0.clone()));
        }
        if let Some(i) = self.persistent_keepalive_interval {
            attrs.push(WgPeerAttrs::PersistentKeepalive(i));
        }
        let allowed_ips: Vec<_> = self.allowed_ips.iter().map(AllowedIp::to_attrs).collect();
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
        attrs
    }
}

impl<'a> TryFrom<Vec<WgPeerAttrs>> for PeerInfo {
    type Error = io::Error;

    fn try_from(attrs: Vec<WgPeerAttrs>) -> Result<Self, Self::Error> {
        let public_key = get_nla_value!(attrs, WgPeerAttrs, PublicKey)
            .map(|key| Key(key.clone()))
            .ok_or_else(|| io::ErrorKind::NotFound)?;
        let preshared_key =
            get_nla_value!(attrs, WgPeerAttrs, PresharedKey).map(|key| Key(key.clone()));
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

impl<'a> TryFrom<&'a Wireguard> for Device {
    type Error = io::Error;

    fn try_from(wg: &'a Wireguard) -> Result<Self, Self::Error> {
        let name = get_nla_value!(wg.nlas, WgDeviceAttrs, IfName)
            .ok_or_else(|| io::ErrorKind::NotFound)?
            .parse()?;
        let public_key =
            get_nla_value!(wg.nlas, WgDeviceAttrs, PublicKey).map(|key| Key(key.clone()));
        let private_key =
            get_nla_value!(wg.nlas, WgDeviceAttrs, PrivateKey).map(|key| Key(key.clone()));
        let listen_port = get_nla_value!(wg.nlas, WgDeviceAttrs, ListenPort).cloned();
        let fwmark = get_nla_value!(wg.nlas, WgDeviceAttrs, Fwmark).cloned();
        let peers = get_nla_value!(wg.nlas, WgDeviceAttrs, Peers)
            .cloned()
            .unwrap_or_default()
            .into_iter()
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

// TODO(jake): refactor - this is the same function in the `shared` crate
fn netlink_call<I>(message: I, flags: Option<u16>) -> Result<Vec<NetlinkMessage<I>>, io::Error>
where
    NetlinkPayload<I>: From<I>,
    I: Clone + std::fmt::Debug + Eq + NetlinkSerializable<I> + NetlinkDeserializable<I>,
{
    let mut req = NetlinkMessage::from(message);
    req.header.flags = flags.unwrap_or(NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE);
    req.finalize();
    let mut buf = [0; 4096];
    req.serialize(&mut buf);
    let len = req.buffer_len();

    let socket = Socket::new(NETLINK_ROUTE)?;
    let kernel_addr = netlink_sys::SocketAddr::new(0, 0);
    socket.connect(&kernel_addr)?;
    let n_sent = socket.send(&buf[..len], 0)?;
    if n_sent != len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "failed to send netlink request",
        ));
    }

    let mut responses = vec![];
    loop {
        let n_received = socket.recv(&mut buf[..], 0)?;
        let mut offset = 0;
        loop {
            let bytes = &buf[offset..];
            let response = NetlinkMessage::<I>::deserialize(bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            responses.push(response.clone());
            match response.payload {
                // We've parsed all parts of the response and can leave the loop.
                NetlinkPayload::Ack(_) | NetlinkPayload::Done => return Ok(responses),
                NetlinkPayload::Error(e) => return Err(e.into()),
                _ => {},
            }
            offset += response.header.length as usize;
            if offset == n_received || response.header.length == 0 {
                // We've fully parsed the datagram, but there may be further datagrams
                // with additional netlink response parts.
                break;
            }
        }
    }
}

pub fn enumerate() -> Result<Vec<InterfaceName>, io::Error> {
    let link_responses = netlink_call(
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

pub fn apply(builder: &DeviceUpdate, iface: &InterfaceName) -> io::Result<()> {
    let mut nlas = vec![WgDeviceAttrs::IfName(iface.as_str_lossy().to_string())];
    if let Some(Key(k)) = builder.private_key {
        nlas.push(WgDeviceAttrs::PrivateKey(k));
    }
    if let Some(f) = builder.fwmark {
        nlas.push(WgDeviceAttrs::Fwmark(f));
    }
    if let Some(f) = builder.listen_port {
        nlas.push(WgDeviceAttrs::ListenPort(f));
    }
    if builder.replace_peers {
        nlas.push(WgDeviceAttrs::Flags(WGDEVICE_F_REPLACE_PEERS));
    }
    let peers: Vec<Vec<_>> = builder
        .peers
        .iter()
        .map(PeerConfigBuilder::to_attrs)
        .collect();
    nlas.push(WgDeviceAttrs::Peers(peers));
    let genlmsg: GenlMessage<Wireguard> = GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::SetDevice,
        nlas,
    });
    netlink_call(genlmsg, Some(NLM_F_REQUEST | NLM_F_ACK))?;
    Ok(())
}

pub fn get_by_name(name: &InterfaceName) -> Result<Device, io::Error> {
    let genlmsg: GenlMessage<Wireguard> = GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::GetDevice,
        nlas: vec![WgDeviceAttrs::IfName(name.as_str_lossy().to_string())],
    });
    let responses = netlink_call(genlmsg, Some(NLM_F_REQUEST | NLM_F_ACK))?;

    match responses.get(0) {
        Some(NetlinkMessage {
            payload: NetlinkPayload::InnerMessage(message),
            ..
        }) => Device::try_from(&message.payload),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Unexpected netlink payload",
        )),
    }
}

pub fn delete_interface(iface: &InterfaceName) -> io::Result<()> {
    let result = unsafe { wireguard_control_sys::wg_del_device(iface.as_ptr()) };

    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
