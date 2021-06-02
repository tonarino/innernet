use crate::Error;
use ipnetwork::IpNetwork;
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST,
};
use netlink_packet_route::{
    constants::*, route::Nla, RouteHeader, RouteMessage, RtnlMessage, RTN_UNICAST, RT_SCOPE_LINK,
    RT_TABLE_MAIN,
};
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};
use wgctrl::InterfaceName;

pub fn add_route(interface: &InterfaceName, cidr: IpNetwork) -> Result<bool, Error> {
    let if_index = unsafe { libc::if_nametoindex(interface.as_ptr()) };
    if if_index == 0 {
        return Err("add_route: couldn't find interface with that name.".into());
    }
    let mut message = RouteMessage {
        header: RouteHeader {
            table: RT_TABLE_MAIN,
            protocol: RTPROT_BOOT,
            scope: RT_SCOPE_LINK,
            kind: RTN_UNICAST,
            address_family: AF_INET as u8,
            destination_prefix_length: cidr.prefix(),
            ..Default::default()
        },
        nlas: vec![],
    };
    match cidr {
        IpNetwork::V4(network) => {
            let dst = network.ip().octets().to_vec();
            message.nlas.push(Nla::Destination(dst))
        },
        IpNetwork::V6(network) => {
            let dst = network.ip().octets().to_vec();
            message.nlas.push(Nla::Destination(dst))
        },
    }
    message.nlas.push(Nla::Oif(if_index));
    let mut req = NetlinkMessage::from(RtnlMessage::NewRoute(message));
    req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
    req.finalize();
    let mut buf = [0; 4096];
    req.serialize(&mut buf);
    let len = req.buffer_len();

    log::debug!("request: {:?}", req);
    let socket = Socket::new(NETLINK_ROUTE).unwrap();
    let kernel_addr = SocketAddr::new(0, 0);
    socket.connect(&kernel_addr)?;
    let n_sent = socket.send(&buf[..len], 0).unwrap();
    if n_sent != len {
        return Err("failed to send netlink request".into());
    }

    let n_received = socket.recv(&mut buf[..], 0).unwrap();
    log::debug!("response bytes: {:?}", &buf[..n_received]);
    let response = NetlinkMessage::<RtnlMessage>::deserialize(&buf[..n_received])?;
    log::debug!("response: {:?}", response);
    if let NetlinkPayload::Error(e) = response.payload {
        return Err(format!("netlink error {}", e.code).into());
    }

    Ok(false)
}
