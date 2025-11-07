use ipnet::IpNet;
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_REPLACE,
    NLM_F_REQUEST,
};
use netlink_packet_route::{
    address::{self, AddressHeader, AddressMessage},
    link::{self, LinkFlags, LinkHeader, LinkMessage, State},
    route::{self, RouteHeader, RouteMessage},
    AddressFamily, RouteNetlinkMessage,
};
use netlink_request::netlink_request_rtnl;
use std::{io, net::IpAddr};
use wireguard_control::InterfaceName;

fn if_nametoindex(interface: &InterfaceName) -> Result<u32, io::Error> {
    match unsafe { libc::if_nametoindex(interface.as_ptr()) } {
        0 => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("couldn't find interface '{interface}'."),
        )),
        index => Ok(index),
    }
}

pub fn set_up(interface: &InterfaceName, mtu: u32) -> Result<(), io::Error> {
    let index = if_nametoindex(interface)?;
    let header = LinkHeader {
        index,
        flags: LinkFlags::Up,
        ..Default::default()
    };
    let mut message = LinkMessage::default();
    message.header = header;
    message.attributes = vec![link::LinkAttribute::Mtu(mtu)];
    netlink_request_rtnl(RouteNetlinkMessage::SetLink(message), None)?;
    log::debug!("set interface {} up with mtu {}", interface, mtu);
    Ok(())
}

pub fn set_addr(interface: &InterfaceName, addr: IpNet) -> Result<(), io::Error> {
    let index = if_nametoindex(interface)?;
    let (family, nlas) = match addr {
        IpNet::V4(network) => {
            let addr = IpAddr::V4(network.addr());
            (
                AddressFamily::Inet,
                vec![
                    address::AddressAttribute::Local(addr),
                    address::AddressAttribute::Address(addr),
                ],
            )
        },
        IpNet::V6(network) => (
            AddressFamily::Inet6,
            vec![address::AddressAttribute::Address(IpAddr::V6(
                network.addr(),
            ))],
        ),
    };
    let header = AddressHeader {
        index,
        family,
        prefix_len: addr.prefix_len(),
        scope: address::AddressScope::Universe,
        ..Default::default()
    };

    let mut message = AddressMessage::default();
    message.header = header;
    message.attributes = nlas;
    netlink_request_rtnl(
        RouteNetlinkMessage::NewAddress(message),
        Some(NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE | NLM_F_CREATE),
    )?;
    log::debug!("set address {} on interface {}", addr, interface);
    Ok(())
}

pub fn add_route(interface: &InterfaceName, cidr: IpNet) -> Result<bool, io::Error> {
    let if_index = if_nametoindex(interface)?;
    let (address_family, dst) = match cidr {
        IpNet::V4(network) => (
            AddressFamily::Inet,
            route::RouteAttribute::Destination(route::RouteAddress::Inet(network.network())),
        ),
        IpNet::V6(network) => (
            AddressFamily::Inet6,
            route::RouteAttribute::Destination(route::RouteAddress::Inet6(network.network())),
        ),
    };
    let header = RouteHeader {
        table: RouteHeader::RT_TABLE_MAIN,
        protocol: route::RouteProtocol::Boot,
        scope: route::RouteScope::Link,
        kind: route::RouteType::Unicast,
        destination_prefix_length: cidr.prefix_len(),
        address_family,
        ..Default::default()
    };
    let mut message = RouteMessage::default();
    message.header = header;
    message.attributes = vec![dst, route::RouteAttribute::Oif(if_index)];

    match netlink_request_rtnl(RouteNetlinkMessage::NewRoute(message), None) {
        Ok(_) => {
            log::debug!("added route {} to interface {}", cidr, interface);
            Ok(true)
        },
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            log::debug!("route {} already existed.", cidr);
            Ok(false)
        },
        Err(e) => Err(e),
    }
}

fn get_links() -> Result<Vec<String>, io::Error> {
    let link_responses = netlink_request_rtnl(
        RouteNetlinkMessage::GetLink(LinkMessage::default()),
        Some(NLM_F_DUMP | NLM_F_REQUEST),
    )?;
    let links = link_responses
        .into_iter()
        // Filter out non-link messages
        .filter_map(|response| match response {
            NetlinkMessage {
                payload: NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)),
                ..
            } => Some(link),
            _ => None,
        })
        // Filter out loopback links
        .filter_map(|link| if !link.header.flags.contains(LinkFlags::Loopback) {
                Some(link.attributes)
            } else {
                None
            })
        // Find and filter out addresses for interfaces
        .filter(|nlas| nlas.iter().any(|nla| nla == &link::LinkAttribute::OperState(State::Up)))
        .filter_map(|nlas| nlas.iter().find_map(|nla| match nla {
            link::LinkAttribute::IfName(name) => Some(name.clone()),
            _ => None,
        }))
        .collect::<Vec<_>>();

    Ok(links)
}

pub fn get_local_addrs() -> Result<impl Iterator<Item = IpAddr>, io::Error> {
    let links = get_links()?;
    let addr_responses = netlink_request_rtnl(
        RouteNetlinkMessage::GetAddress(AddressMessage::default()),
        Some(NLM_F_DUMP | NLM_F_REQUEST),
    )?;
    let addrs = addr_responses
        .into_iter()
        // Filter out non-link messages
        .filter_map(|response| match response {
            NetlinkMessage {
                payload: NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(addr)),
                ..
            } => Some(addr),
            _ => None,
        })
        // Filter out non-global-scoped addresses
        .filter_map(|link| if link.header.scope == address::AddressScope::Universe {
                Some(link.attributes)
            } else {
                None
            })
        // Only select addresses for helpful links
        .filter(move |nlas| nlas.iter().any(|nla| {
            matches!(nla, address::AddressAttribute::Label(label) if links.contains(label))
            || matches!(nla, address::AddressAttribute::Address(IpAddr::V6(_addr)))
        }))
        .filter_map(|nlas| nlas.iter().find_map(|nla| match nla {
            address::AddressAttribute::Address(IpAddr::V4(addr)) => Some(IpAddr::V4(*addr)),
            address::AddressAttribute::Address(IpAddr::V6(addr)) => Some(IpAddr::V6(*addr)),
            _ => None,
        }));
    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_addrs() {
        let addrs = get_local_addrs().unwrap();
        println!("{:?}", addrs.collect::<Vec<_>>());
    }
}
