// use wireguard_control::{Backend, Device};

// fn main() {
//     let devices = Device::list(Backend::Kernel).unwrap();
//     let device = Device::get(&"frands".parse().unwrap(), Backend::Kernel).unwrap();
//     println!("{:?}", devices);
// }

use futures::StreamExt;
use genetlink::new_connection;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST, NetlinkSerializable};
use netlink_packet_generic::{GenlMessage, ctrl::{GenlCtrl, GenlCtrlCmd, nlas::GenlCtrlAttrs}, GenlFamily};
use netlink_packet_wireguard::{
    nlas::{WgAllowedIpAttrs, WgDeviceAttrs, WgPeerAttrs},
    Wireguard,
    WireguardCmd,
};
use netlink_packet_core::{
    NetlinkDeserializable, NLM_F_ACK,
    NLM_F_CREATE, NLM_F_EXCL,
};
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
};
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, constants::NETLINK_GENERIC};
use std::{env::args, io};

macro_rules! get_nla_value {
    ($nlas:expr, $e:ident, $v:ident) => {
        $nlas.iter().find_map(|attr| match attr {
            $e::$v(value) => Some(value),
            _ => None,
        })
    };
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let argv: Vec<String> = args().collect();
    if argv.len() < 2 {
        eprintln!("Usage: get_wireguard_info <ifname>");
        return;
    }

    let (connection, mut handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    let mut genlmsg: GenlMessage<Wireguard> = GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::GetDevice,
        nlas: vec![WgDeviceAttrs::IfName(argv[1].clone())],
    });
    let mut nlmsg = NetlinkMessage::from(genlmsg.clone());
    nlmsg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;

    let mut res = handle.request(nlmsg).await.unwrap();

    while let Some(result) = res.next().await {
        let rx_packet = result.unwrap();
        match rx_packet.payload {
            NetlinkPayload::InnerMessage(genlmsg) => {
                print_wg_payload(genlmsg.payload);
            }
            NetlinkPayload::Error(e) => {
                eprintln!("Error: {:?}", e.to_io());
            }
            _ => (),
        };
    }

    resolve_family_id(&mut genlmsg).unwrap();
    let netlink_call_res = netlink_call(genlmsg, Some(NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK), None).unwrap();
    for message in netlink_call_res {
        println!("message: {:?}", message);
        match message.payload {
            NetlinkPayload::InnerMessage(genlmsg) => {
                print_wg_payload(genlmsg.payload);
            }
            NetlinkPayload::Error(e) => {
                eprintln!("Error: {:?}", e.to_io());
            }
            _ => (),
        };
    }
}

fn print_wg_payload(wg: Wireguard) {
    for nla in &wg.nlas {
        match nla {
            WgDeviceAttrs::IfIndex(v) => println!("IfIndex: {}", v),
            WgDeviceAttrs::IfName(v) => println!("IfName: {}", v),
            WgDeviceAttrs::PrivateKey(_) => println!("PrivateKey: (hidden)"),
            WgDeviceAttrs::PublicKey(v) => println!("PublicKey: {}", base64::encode(v)),
            WgDeviceAttrs::ListenPort(v) => println!("ListenPort: {}", v),
            WgDeviceAttrs::Fwmark(v) => println!("Fwmark: {}", v),
            WgDeviceAttrs::Peers(nlas) => {
                for peer in nlas {
                    println!("Peer: ");
                    print_wg_peer(peer);
                }
            }
            _ => (),
        }
    }
}

fn print_wg_peer(nlas: &[WgPeerAttrs]) {
    for nla in nlas {
        match nla {
            WgPeerAttrs::PublicKey(v) => println!("  PublicKey: {}", base64::encode(v)),
            WgPeerAttrs::PresharedKey(_) => println!("  PresharedKey: (hidden)"),
            WgPeerAttrs::Endpoint(v) => println!("  Endpoint: {}", v),
            WgPeerAttrs::PersistentKeepalive(v) => println!("  PersistentKeepalive: {}", v),
            WgPeerAttrs::LastHandshake(v) => println!("  LastHandshake: {:?}", v),
            WgPeerAttrs::RxBytes(v) => println!("  RxBytes: {}", v),
            WgPeerAttrs::TxBytes(v) => println!("  TxBytes: {}", v),
            WgPeerAttrs::AllowedIps(nlas) => {
                for ip in nlas {
                    print_wg_allowedip(ip);
                }
            }
            _ => (),
        }
    }
}

fn print_wg_allowedip(nlas: &[WgAllowedIpAttrs]) -> Option<()> {
    let ipaddr = nlas.iter().find_map(|nla| {
        if let WgAllowedIpAttrs::IpAddr(addr) = nla {
            Some(*addr)
        } else {
            None
        }
    })?;
    let cidr = nlas.iter().find_map(|nla| {
        if let WgAllowedIpAttrs::Cidr(cidr) = nla {
            Some(*cidr)
        } else {
            None
        }
    })?;
    println!("  AllowedIp: {}/{}", ipaddr, cidr);
    Some(())
}

fn resolve_family_id<T>(message: &mut GenlMessage<T>) -> Result<(), io::Error> 
where
    T: GenlFamily + Clone + std::fmt::Debug + Eq,
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

// TODO(jake): refactor - this is the same function in the `shared` crate
fn netlink_call<I>(message: I, flags: Option<u16>, socket: Option<isize>) -> Result<Vec<NetlinkMessage<I>>, io::Error>
where
    NetlinkPayload<I>: From<I>,
    I: Clone + std::fmt::Debug + Eq + NetlinkSerializable + NetlinkDeserializable,
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