use crate::{
    device::AllowedIp, Backend, Device, DeviceUpdate,
    InterfaceName, Key, PeerInfo
};

use core::str;
use std::{
    io, iter::Peekable, net::{IpAddr, SocketAddr},
    process::Command, str::FromStr, time::{Duration, SystemTime}
};

const IFCONFIG_PARSING_ERROR: &str = "Unable to parse ifconfig output";

pub fn enumerate() -> Result<Vec<InterfaceName>, io::Error> {

    let interfaces = nix::net::if_::if_nameindex()?;
    let mut ifs = vec![];
    for iface in &interfaces {
        let name = iface.name().to_string_lossy().to_string();
        if name.starts_with("wg") {
            let interface_name = name.parse::<InterfaceName>()?;
            ifs.push(interface_name);
        }
    }
    Ok(ifs)
}

fn interface_exists(iface : &InterfaceName) -> Result<bool, io::Error> {
    let devices = enumerate()?;
    Ok(devices.contains(iface))
}

pub fn apply(builder: &DeviceUpdate, iface: &InterfaceName) -> io::Result<()> {

    let mut cmd = Command::new("ifconfig");
    cmd.arg(iface.as_str_lossy().as_ref());
    if !interface_exists(iface)? {
        cmd.arg("create");
    }

    if let Some(private_key) = &builder.private_key {
        cmd.arg("wgkey");
        cmd.arg(private_key.to_base64());
    }

    if let Some(port) = &builder.listen_port {
        cmd.arg("wgport");
        cmd.arg(port.to_string());
    }

    if builder.peers.len() > 0 {
        for peer in &builder.peers {
            cmd.arg("wgpeer");
            cmd.arg(peer.public_key().to_base64());
            if let Some(preshared_key) = &peer.preshared_key {
                cmd.arg("wgpsk");
                cmd.arg(preshared_key.to_base64());
            }
            if let Some(endpoint) = &peer.endpoint {
                cmd.arg("wgendpoint");
                cmd.arg(endpoint.ip().to_string());
                cmd.arg(endpoint.port().to_string());
            }
            if let Some(keepalive) = &peer.persistent_keepalive_interval {
                cmd.arg("wgpka");
                cmd.arg(keepalive.to_string());
            }
            for aip in  &peer.allowed_ips {
                cmd.arg("wgaip");
                let ip_cidr_str = format!("{}/{}" , aip.address, aip.cidr.to_string());
                cmd.arg(ip_cidr_str);
            }
        }
    }

    let output = cmd.output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        eprintln!("Failed to set interface: {}" ,stderr);
        return Err(io::ErrorKind::Other.into());
    }
    Ok(())
}

fn parse_peer_attributes(peer : &mut PeerInfo, lines : &mut Peekable<str::Lines>)
{
    while let Some(peer_attr) = &mut lines.next_if(|&subline| subline.starts_with("\t\t")) {

        let peer_attr_clean = peer_attr.trim_start_matches("\t\t");
        let mut peer_attr_tokens = peer_attr_clean.split_whitespace().peekable();

        if let Some(key) = peer_attr_tokens.next(){
            match key {
                "wgdescr:" => {},
                "wgpsk" => {},
                "wgpka" => {},
                "wgendpoint" => {
                    let ip_token = peer_attr_tokens
                        .next()
                        .expect(IFCONFIG_PARSING_ERROR);

                    let ip = IpAddr::from_str(ip_token)
                        .expect(IFCONFIG_PARSING_ERROR);

                    let port = peer_attr_tokens
                        .next()
                        .expect(IFCONFIG_PARSING_ERROR)
                        .parse::<u16>()
                        .expect(IFCONFIG_PARSING_ERROR);

                    peer.config.endpoint = Some(SocketAddr::new(ip, port));
                },
                "wgaip" => {
                    let aip_token = peer_attr_tokens
                        .next()
                        .expect(IFCONFIG_PARSING_ERROR);

                    let aip = AllowedIp::from_str(aip_token)
                        .expect(IFCONFIG_PARSING_ERROR);

                    peer.config.allowed_ips.push(aip);
                },
                "tx:" => {
                    peer.stats.tx_bytes = peer_attr_tokens
                        .next()
                        .expect(IFCONFIG_PARSING_ERROR)
                        .trim_end_matches(",")
                        .parse()
                        .expect(IFCONFIG_PARSING_ERROR);

                    peer_attr_tokens.next(); // skip "rx:" token

                    peer.stats.rx_bytes = peer_attr_tokens
                        .next()
                        .expect(IFCONFIG_PARSING_ERROR)
                        .parse()
                        .expect(IFCONFIG_PARSING_ERROR);
                },
                "last" => {
                    peer_attr_tokens.next(); // skip "handshake:" token

                    let sec_since_last_hs = peer_attr_tokens
                        .next()
                        .expect(IFCONFIG_PARSING_ERROR)
                        .parse()
                        .expect(IFCONFIG_PARSING_ERROR);

                    let now = SystemTime::now();
                    let duration_since_last_hs = Duration::from_secs(sec_since_last_hs);
                    peer.stats.last_handshake_time = Some(now - duration_since_last_hs);
                },
                _ => {}
            }
        }
    }
}

pub fn get_by_name(name: &InterfaceName) -> Result<Device, io::Error> {
    let output = Command::new("ifconfig")
        .arg(name.as_str_lossy().as_ref())
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut device = Device {
        name: *name,
        public_key: None,
        private_key: None,
        fwmark: None,
        listen_port: None,
        peers: Vec::new(),
        linked_name: None,
        backend: Backend::KernelOpenBSD,
    };

    let mut lines = stdout.lines().peekable();

    while let Some(line) = lines.next() {

        let mut tokens = line.split_whitespace();
        if let Some(token) = tokens.next(){
            match token {
                "wgport" => {
                    device.listen_port = tokens
                        .next()
                        .map(|port_str| port_str.parse()
                        .expect(IFCONFIG_PARSING_ERROR)
                    );
                },
                "wgpubkey" => {
                    device.public_key = tokens
                        .next()
                        .map(|token|  Key::from_base64 (token))
                        .map(|r|r.expect(IFCONFIG_PARSING_ERROR));
                },
                "wgpeer" => {
                    let peer_key = Key::from_base64(tokens.next()
                        .expect(IFCONFIG_PARSING_ERROR))
                        .expect(IFCONFIG_PARSING_ERROR);
                    let mut peer = PeerInfo::new(peer_key);
                    parse_peer_attributes(&mut peer, &mut lines);
                    device.peers.push(peer);
                },
                _ => {}
            }
        }
    }
    Ok(device)
}

pub fn delete_interface(iface: &InterfaceName) -> io::Result<()> {
    let output = Command::new("ifconfig")
        .arg(iface.as_str_lossy().as_ref())
        .arg("destroy")
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        eprintln!("Failed to destory interface: {}" ,stderr);
        return Err(io::ErrorKind::Other.into());
    }
    Ok(())
}

/*
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
*/
