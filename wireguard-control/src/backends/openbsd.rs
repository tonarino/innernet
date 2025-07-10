use crate::{device::AllowedIp, Backend, Device, DeviceUpdate, InterfaceName, Key, PeerInfo};

use core::str;
use std::{
    io,
    iter::Peekable,
    net::{IpAddr, SocketAddr},
    process::Command,
    str::FromStr,
    time::{Duration, SystemTime},
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

fn interface_exists(iface: &InterfaceName) -> Result<bool, io::Error> {
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
        if builder.replace_peers {
            for peer in &builder.peers {
                cmd.arg("-wgpeer");
                cmd.arg(peer.public_key().to_base64());
            }
        }

        for peer in &builder.peers {
            if peer.remove_me {
                cmd.arg("-wgpeer");
                cmd.arg(peer.public_key().to_base64());
                continue;
            }
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
            for aip in &peer.allowed_ips {
                cmd.arg("wgaip");
                let ip_cidr_str = format!("{}/{}", aip.address, aip.cidr.to_string());
                cmd.arg(ip_cidr_str);
            }
        }
    }

    let output = cmd.output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        eprintln!("Failed to set interface: {}", stderr);
        return Err(io::ErrorKind::Other.into());
    }
    Ok(())
}

fn parse_peer_attributes(peer: &mut PeerInfo, lines: &mut Peekable<str::Lines>) {
    while let Some(peer_attr) = &mut lines.next_if(|&subline| subline.starts_with("\t\t")) {
        let peer_attr_clean = peer_attr.trim_start_matches("\t\t");
        let mut peer_attr_tokens = peer_attr_clean.split_whitespace().peekable();

        if let Some(key) = peer_attr_tokens.next() {
            match key {
                "wgdescr:" => {},
                "wgpsk" => {},
                "wgpka" => {},
                "wgendpoint" => {
                    let ip_token = peer_attr_tokens.next().expect(IFCONFIG_PARSING_ERROR);

                    let ip = IpAddr::from_str(ip_token).expect(IFCONFIG_PARSING_ERROR);

                    let port = peer_attr_tokens
                        .next()
                        .expect(IFCONFIG_PARSING_ERROR)
                        .parse::<u16>()
                        .expect(IFCONFIG_PARSING_ERROR);

                    peer.config.endpoint = Some(SocketAddr::new(ip, port));
                },
                "wgaip" => {
                    let aip_token = peer_attr_tokens.next().expect(IFCONFIG_PARSING_ERROR);

                    let aip = AllowedIp::from_str(aip_token).expect(IFCONFIG_PARSING_ERROR);

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
                _ => {},
            }
        }
    }
}

pub fn get_by_name(name: &InterfaceName) -> Result<Device, io::Error> {
    let output = Command::new("ifconfig")
        .arg(name.as_str_lossy().as_ref())
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        eprintln!("Failed to get interface: {}", stderr);
        return Err(io::ErrorKind::Other.into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut device = Device {
        name: *name,
        public_key: None,
        private_key: None,
        fwmark: None,
        listen_port: None,
        peers: Vec::new(),
        linked_name: None,
        backend: Backend::OpenBSD,
    };

    let mut lines = stdout.lines().peekable();

    while let Some(line) = lines.next() {
        let mut tokens = line.split_whitespace();
        if let Some(token) = tokens.next() {
            match token {
                "wgport" => {
                    device.listen_port = tokens
                        .next()
                        .map(|port_str| port_str.parse().expect(IFCONFIG_PARSING_ERROR));
                },
                "wgpubkey" => {
                    device.public_key = tokens
                        .next()
                        .map(|token| Key::from_base64(token))
                        .map(|r| r.expect(IFCONFIG_PARSING_ERROR));
                },
                "wgpeer" => {
                    let peer_key = Key::from_base64(tokens.next().expect(IFCONFIG_PARSING_ERROR))
                        .expect(IFCONFIG_PARSING_ERROR);
                    let mut peer = PeerInfo::new(peer_key);
                    parse_peer_attributes(&mut peer, &mut lines);
                    device.peers.push(peer);
                },
                _ => {},
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
        eprintln!("Failed to destory interface: {}", stderr);
        return Err(io::ErrorKind::Other.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PeerConfigBuilder;
    #[test]
    fn test_add_delete() {
        let iface = InterfaceName::from_str("wg5").unwrap();
        let peer1 = PeerConfigBuilder::new(
            &Key::from_base64("LdxcIAOY4EuSZpI0SRiBM7cZbhVSqmDSzgXfDikafyU=").unwrap(),
        )
        .set_endpoint("33.22.11.0:8684".parse().unwrap())
        .add_allowed_ip("100.0.0.1".parse().unwrap(), 8);

        let config = DeviceUpdate::new()
            .set_private_key(
                Key::from_base64("Y/NG0R2i1Gtvollv5o/U3YaOlewG6HeyTLIUlrTrKg4=").unwrap(),
            )
            .set_listen_port(1233)
            .add_peer(peer1);
        apply(&config, &iface).unwrap();

        let dev = get_by_name(&iface).unwrap();
        assert_eq!(dev.name, iface);

        delete_interface(&iface).unwrap();
    }
}
