use crate::{
    device::AllowedIp, Backend, Device, DeviceUpdate, InterfaceName, Key, PeerConfig,
    PeerConfigBuilder, PeerInfo, PeerStats,
};

use std::{convert::TryFrom, io};

pub fn enumerate() -> Result<Vec<InterfaceName>, io::Error> {
    todo!("enum");
}

pub fn apply(builder: &DeviceUpdate, iface: &InterfaceName) -> io::Result<()> {
    todo!("{}" ,iface.to_string());
}

pub fn get_by_name(name: &InterfaceName) -> Result<Device, io::Error> {
    todo!("{}" ,name.to_string());
}

pub fn delete_interface(iface: &InterfaceName) -> io::Result<()> {
    todo!("{}" ,iface.to_string());
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
