use crate::{
    device::AllowedIp, Backend, Device, DeviceUpdate, InterfaceName, PeerConfig,
    PeerConfigBuilder, PeerInfo, PeerStats, Key,
};
use netlink_packet_core::{
    NetlinkDeserializable, NetlinkMessage, NetlinkPayload, NetlinkSerializable, NLM_F_ACK,
    NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST,
};
use netlink_packet_generic::{GenlMessage, ctrl::{GenlCtrl, GenlCtrlCmd, nlas::GenlCtrlAttrs}, GenlFamily};
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
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, constants::NETLINK_GENERIC};

use std::{convert::TryFrom, io, fmt::Debug};

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
        let address = *get_nla_value!(attrs, WgAllowedIpAttrs, IpAddr)
            .ok_or_else(|| io::ErrorKind::NotFound)?;
        let cidr = *get_nla_value!(attrs, WgAllowedIpAttrs, Cidr)
            .ok_or_else(|| io::ErrorKind::NotFound)?;
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
            attrs.push(WgPeerAttrs::PresharedKey(key.0));
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
            .map(|key| Key(*key))
            .ok_or(io::ErrorKind::NotFound)?;
        let preshared_key =
            get_nla_value!(attrs, WgPeerAttrs, PresharedKey).map(|key| Key(*key));
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
            get_nla_value!(wg.nlas, WgDeviceAttrs, PublicKey).map(|key| Key(*key));
        let private_key =
            get_nla_value!(wg.nlas, WgDeviceAttrs, PrivateKey).map(|key| Key(*key));
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

fn resolve_family_id<F>(message: &mut GenlMessage<F>) -> Result<(), io::Error> 
where
    F: GenlFamily + Clone + Debug + Eq,
{
    if message.family_id() == 0 {
        let genlmsg: GenlMessage<GenlCtrl> = GenlMessage::from_payload(GenlCtrl {
            cmd: GenlCtrlCmd::GetFamily,
            nlas: vec![GenlCtrlAttrs::FamilyName("wireguard".to_string())],
        });        
        let responses = netlink_call::<GenlMessage<GenlCtrl>>(genlmsg, Some(NLM_F_REQUEST | NLM_F_ACK), None)?;

        match responses.get(0) {
            Some(NetlinkMessage { payload: NetlinkPayload::InnerMessage(GenlMessage { payload: GenlCtrl { nlas, .. }, ..}), .. }) => {
                let family_id = get_nla_value!(nlas, GenlCtrlAttrs, FamilyId)
                    .ok_or_else(|| io::ErrorKind::NotFound)?;
                message.set_resolved_family_id(*family_id);
            },
            _ => return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unexpected netlink payload",
            )),
        };
    }
    Ok(())
}

fn netlink_call<I>(message: I, flags: Option<u16>, socket: Option<isize>) -> Result<Vec<NetlinkMessage<I>>, io::Error>
where
    NetlinkPayload<I>: From<I>,
    I: Clone + Debug + Eq + NetlinkSerializable + NetlinkDeserializable,
{
    let mut req = NetlinkMessage::from(message);
    req.header.flags = flags.unwrap_or(NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE);
    req.finalize();
    let mut buf = [0; 4096];
    println!("request: {:?}", req);
    req.serialize(&mut buf);
    let len = req.buffer_len();

    let socket = Socket::new(socket.unwrap_or(NETLINK_GENERIC))?;
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
        let n_received = socket.recv(&mut &mut buf[..], 0)?;
        let mut offset = 0;
        loop {
            let bytes = &buf[offset..];
            let response = NetlinkMessage::<I>::deserialize(bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            println!("response: {:?}", response);
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

fn netlink_request_generic<F>(mut message: GenlMessage<F>, flags: Option<u16>) -> Result<Vec<NetlinkMessage<GenlMessage<F>>>, io::Error>
where
    F: GenlFamily + Clone + Debug + Eq,
    GenlMessage<F>: Clone + Debug + Eq + NetlinkSerializable + NetlinkDeserializable,
{
    resolve_family_id(&mut message)?;
    netlink_request(message, flags, NETLINK_GENERIC)
}

fn netlink_request<I>(message: I, flags: Option<u16>, socket: isize) -> Result<Vec<NetlinkMessage<I>>, io::Error>
where
    NetlinkPayload<I>: From<I>,
    I: Clone + Debug + Eq + NetlinkSerializable + NetlinkDeserializable,
{
    let mut req = NetlinkMessage::from(message);
    req.header.flags = flags.unwrap_or(NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE);
    req.finalize();
    let mut buf = [0; 4096];
    println!("request: {:?}", req);
    req.serialize(&mut buf);
    let len = req.buffer_len();

    let socket = Socket::new(socket)?;
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
        let n_received = socket.recv(&mut &mut buf[..], 0)?;
        let mut offset = 0;
        loop {
            let bytes = &buf[offset..];
            let response = NetlinkMessage::<I>::deserialize(bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            println!("response: {:?}", response);
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
        None
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
    message.nlas.push(link::nlas::Nla::IfName(iface.as_str_lossy().to_string()));
    message.nlas.push(link::nlas::Nla::Info(vec![Info::Kind(link::nlas::InfoKind::Wireguard)]));
    let extra_flags = if add { NLM_F_CREATE | NLM_F_EXCL } else { 0 };
    let rtnl_message = if add { RtnlMessage::NewLink(message) } else { RtnlMessage::DelLink(message) };
    let result = netlink_call(
        rtnl_message,
        Some(NLM_F_REQUEST | NLM_F_ACK | extra_flags),
        Some(NETLINK_ROUTE),
    );
    match result {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => Err(e),
        _ => Ok(())
    }
}

pub fn apply(builder: &DeviceUpdate, iface: &InterfaceName) -> io::Result<()> {
    add_del(iface, true)?;
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
    netlink_call(genlmsg, Some(NLM_F_REQUEST | NLM_F_ACK), None)?;
    Ok(())
}

pub fn get_by_name(name: &InterfaceName) -> Result<Device, io::Error> {
    let genlmsg: GenlMessage<Wireguard> = GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::GetDevice,
        nlas: vec![WgDeviceAttrs::IfName(name.as_str_lossy().to_string())],
    });
    let responses = netlink_call(genlmsg, Some(NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK), None)?;

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
    add_del(iface, false)
}
