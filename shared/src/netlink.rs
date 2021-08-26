use ipnetwork::IpNetwork;
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST,
};
use netlink_packet_route::{
    address,
    constants::*,
    link::{self, nlas::State},
    route, AddressHeader, AddressMessage, LinkHeader, LinkMessage, RouteHeader, RouteMessage,
    RtnlMessage, RTN_UNICAST, RT_SCOPE_LINK, RT_TABLE_MAIN,
};
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};
use std::{
    io,
    net::{IpAddr, Ipv4Addr},
};
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
) -> Result<Vec<NetlinkMessage<RtnlMessage>>, io::Error> {
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

    let mut responses = vec![];
    'outer: loop {
        let n_received = socket.recv(&mut buf[..], 0).unwrap();
        let mut offset = 0;
        'inner: loop {
            let bytes = &buf[offset..];
            let response = NetlinkMessage::<RtnlMessage>::deserialize(bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            if let NetlinkPayload::Error(e) = response.payload {
                return Err(e.to_io());
            }
            responses.push(response.clone());
            log::trace!("netlink response: {:?}", response);
            if (req.header.flags & NLM_F_DUMP) == 0 || response.payload == NetlinkPayload::Done {
                // We've parsed all parts of the response and can leave the loop.
                break 'outer;
            }
            offset += response.header.length as usize;
            if offset == n_received || response.header.length == 0 {
                // We've fully parsed the datagram, but there may be further datagrams
                // with additional netlink response parts.
                break 'inner;
            }
        }
    }
    Ok(responses)
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

pub fn get_local_addrs() -> Result<Vec<IpAddr>, io::Error> {
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
        // Filter out loopback links
        .filter_map(|link| if link.header.flags & IFF_LOOPBACK == 0 {
                Some(link.nlas)
            } else {
                None
            })
        // Find and filter out addresses for interfaces
        .filter(|nlas| nlas.iter().any(|nla| nla == &link::nlas::Nla::OperState(State::Up)))
        .filter_map(|nlas| nlas.iter().find_map(|nla| match nla {
            link::nlas::Nla::IfName(name) => Some(name.clone()),
            _ => None,
        }))
        .collect::<Vec<_>>();
    let addr_responses = netlink_call(
        RtnlMessage::GetAddress(AddressMessage::default()),
        Some(NLM_F_DUMP | NLM_F_REQUEST),
    )?;
    let addrs = addr_responses
        .into_iter()
        // Filter out non-link messages
        .filter_map(|response| match response {
            NetlinkMessage {
                payload: NetlinkPayload::InnerMessage(RtnlMessage::NewAddress(addr)),
                ..
            } => Some(addr),
            _ => None,
        })
        // Filter out non-global-scoped addresses
        .filter_map(|link| if link.header.scope == RT_SCOPE_UNIVERSE {
                Some(link.nlas)
            } else {
                None
            })
        // Only select addresses for helpful links
        .filter(|nlas| nlas.iter().any(|nla| matches!(nla, address::nlas::Nla::Label(label) if links.contains(label))))
        .filter_map(|nlas| nlas.iter().find_map(|nla| match nla {
            // TODO(jake): support IPv6 addresses as well.
            address::nlas::Nla::Address(name) if name.len() == 4 => {
                Some(IpAddr::V4(Ipv4Addr::new(name[0], name[1], name[2], name[3])))
            },
            _ => None,
        }))
        .collect::<Vec<_>>();
    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_addrs() {
        get_local_addrs().unwrap();
    }
}
