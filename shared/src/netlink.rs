use ipnetwork::IpNetwork;
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST,
};
use netlink_packet_route::{
    address, constants::*, link, route, AddressHeader, AddressMessage, LinkHeader, LinkMessage,
    RouteHeader, RouteMessage, RtnlMessage, RTN_UNICAST, RT_SCOPE_LINK, RT_TABLE_MAIN,
};
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};
use std::io;
use wgctrl::InterfaceName;

fn if_nametoindex(interface: &InterfaceName) -> Result<u32, io::Error> {
    match unsafe { libc::if_nametoindex(interface.as_ptr()) } {
        0 => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("couldn't find interface '{}'.", interface),
        )),
        index => Ok(index),
    }
}

fn netlink_call(
    message: RtnlMessage,
    flags: Option<u16>,
) -> Result<NetlinkMessage<RtnlMessage>, io::Error> {
    let mut req = NetlinkMessage::from(message);
    req.header.flags = flags.unwrap_or(NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE);
    req.finalize();
    let mut buf = [0; 4096];
    req.serialize(&mut buf);
    let len = req.buffer_len();

    log::debug!("netlink request: {:?}", req);
    let socket = Socket::new(NETLINK_ROUTE).unwrap();
    let kernel_addr = SocketAddr::new(0, 0);
    socket.connect(&kernel_addr)?;
    let n_sent = socket.send(&buf[..len], 0).unwrap();
    if n_sent != len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "failed to send netlink request",
        ));
    }

    let n_received = socket.recv(&mut buf[..], 0).unwrap();
    let response = NetlinkMessage::<RtnlMessage>::deserialize(&buf[..n_received])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    log::trace!("netlink response: {:?}", response);
    if let NetlinkPayload::Error(e) = response.payload {
        return Err(e.to_io());
    }
    Ok(response)
}

pub fn set_up(interface: &InterfaceName, mtu: u32) -> Result<(), io::Error> {
    let index = if_nametoindex(interface)?;
    let message = LinkMessage {
        header: LinkHeader {
            index,
            flags: IFF_UP,
            ..Default::default()
        },
        nlas: vec![link::nlas::Nla::Mtu(mtu)],
    };
    netlink_call(RtnlMessage::SetLink(message), None)?;
    Ok(())
}

pub fn set_addr(interface: &InterfaceName, addr: IpNetwork) -> Result<(), io::Error> {
    let index = if_nametoindex(interface)?;
    let (family, nlas) = match addr {
        IpNetwork::V4(network) => {
            let addr_bytes = network.ip().octets().to_vec();
            (
                AF_INET as u8,
                vec![
                    address::Nla::Local(addr_bytes.clone()),
                    address::Nla::Address(addr_bytes),
                ],
            )
        },
        IpNetwork::V6(network) => (
            AF_INET6 as u8,
            vec![address::Nla::Address(network.ip().octets().to_vec())],
        ),
    };
    let message = AddressMessage {
        header: AddressHeader {
            index,
            family,
            prefix_len: addr.prefix(),
            scope: RT_SCOPE_UNIVERSE,
            ..Default::default()
        },
        nlas,
    };
    netlink_call(
        RtnlMessage::NewAddress(message),
        Some(NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE | NLM_F_CREATE),
    )?;
    Ok(())
}

pub fn add_route(interface: &InterfaceName, cidr: IpNetwork) -> Result<bool, io::Error> {
    let if_index = if_nametoindex(interface)?;
    let (address_family, dst) = match cidr {
        IpNetwork::V4(network) => (AF_INET as u8, network.network().octets().to_vec()),
        IpNetwork::V6(network) => (AF_INET6 as u8, network.network().octets().to_vec()),
    };
    let message = RouteMessage {
        header: RouteHeader {
            table: RT_TABLE_MAIN,
            protocol: RTPROT_BOOT,
            scope: RT_SCOPE_LINK,
            kind: RTN_UNICAST,
            destination_prefix_length: cidr.prefix(),
            address_family,
            ..Default::default()
        },
        nlas: vec![route::Nla::Destination(dst), route::Nla::Oif(if_index)],
    };

    match netlink_call(RtnlMessage::NewRoute(message), None) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e),
    }
}
