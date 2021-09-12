use crate::{
    device::AllowedIp, Backend, Device, DeviceUpdate, InterfaceName, InvalidInterfaceName,
    InvalidKey, PeerConfig, PeerConfigBuilder, PeerInfo, PeerStats,
};
use wgctrl_sys::{timespec64, wg_device_flags as wgdf, wg_peer_flags as wgpf};

use std::{
    ffi::{CStr, CString},
    io,
    net::{IpAddr, SocketAddr},
    os::raw::c_char,
    ptr, str,
    time::{Duration, SystemTime},
};

impl<'a> From<&'a wgctrl_sys::wg_allowedip> for AllowedIp {
    fn from(raw: &wgctrl_sys::wg_allowedip) -> AllowedIp {
        let addr = match i32::from(raw.family) {
            libc::AF_INET => IpAddr::V4(unsafe { raw.__bindgen_anon_1.ip4.s_addr }.to_be().into()),
            libc::AF_INET6 => {
                IpAddr::V6(unsafe { raw.__bindgen_anon_1.ip6.__in6_u.__u6_addr8 }.into())
            },
            _ => unreachable!(format!("Unsupported socket family {}!", raw.family)),
        };

        AllowedIp {
            address: addr,
            cidr: raw.cidr,
        }
    }
}

impl<'a> From<&'a wgctrl_sys::wg_peer> for PeerInfo {
    fn from(raw: &wgctrl_sys::wg_peer) -> PeerInfo {
        PeerInfo {
            config: PeerConfig {
                public_key: Key::from_raw(raw.public_key),
                preshared_key: if (raw.flags & wgpf::WGPEER_HAS_PRESHARED_KEY).0 > 0 {
                    Some(Key::from_raw(raw.preshared_key))
                } else {
                    None
                },
                endpoint: parse_endpoint(&raw.endpoint),
                persistent_keepalive_interval: match raw.persistent_keepalive_interval {
                    0 => None,
                    x => Some(x),
                },
                allowed_ips: parse_allowed_ips(raw),
                __cant_construct_me: (),
            },
            stats: PeerStats {
                last_handshake_time: match (
                    raw.last_handshake_time.tv_sec,
                    raw.last_handshake_time.tv_nsec,
                ) {
                    (0, 0) => None,
                    (s, ns) => Some(SystemTime::UNIX_EPOCH + Duration::new(s as u64, ns as u32)),
                },
                rx_bytes: raw.rx_bytes,
                tx_bytes: raw.tx_bytes,
            },
        }
    }
}

impl<'a> From<&'a wgctrl_sys::wg_device> for Device {
    fn from(raw: &wgctrl_sys::wg_device) -> Device {
        // SAFETY: The name string buffer came directly from wgctrl so its NUL terminated.
        let name = unsafe { InterfaceName::from_wg(raw.name) };
        Device {
            name,
            public_key: if (raw.flags & wgdf::WGDEVICE_HAS_PUBLIC_KEY).0 > 0 {
                Some(Key::from_raw(raw.public_key))
            } else {
                None
            },
            private_key: if (raw.flags & wgdf::WGDEVICE_HAS_PRIVATE_KEY).0 > 0 {
                Some(Key::from_raw(raw.private_key))
            } else {
                None
            },
            fwmark: match raw.fwmark {
                0 => None,
                x => Some(x),
            },
            listen_port: match raw.listen_port {
                0 => None,
                x => Some(x),
            },
            peers: parse_peers(raw),
            linked_name: None,
            backend: Backend::Kernel,
            __cant_construct_me: (),
        }
    }
}

fn parse_peers(dev: &wgctrl_sys::wg_device) -> Vec<PeerInfo> {
    let mut result = Vec::new();

    let mut current_peer = dev.first_peer;

    if current_peer.is_null() {
        return result;
    }

    loop {
        let peer = unsafe { &*current_peer };

        result.push(PeerInfo::from(peer));

        if current_peer == dev.last_peer {
            break;
        }
        current_peer = peer.next_peer;
    }

    result
}

fn parse_allowed_ips(peer: &wgctrl_sys::wg_peer) -> Vec<AllowedIp> {
    let mut result = Vec::new();

    let mut current_ip: *mut wgctrl_sys::wg_allowedip = peer.first_allowedip;

    if current_ip.is_null() {
        return result;
    }

    loop {
        let ip = unsafe { &*current_ip };

        result.push(AllowedIp::from(ip));

        if current_ip == peer.last_allowedip {
            break;
        }
        current_ip = ip.next_allowedip;
    }

    result
}

fn parse_endpoint(endpoint: &wgctrl_sys::wg_peer__bindgen_ty_1) -> Option<SocketAddr> {
    let addr = unsafe { endpoint.addr };
    match i32::from(addr.sa_family) {
        libc::AF_INET => {
            let addr4 = unsafe { endpoint.addr4 };
            Some(SocketAddr::new(
                IpAddr::V4(u32::from_be(addr4.sin_addr.s_addr).into()),
                u16::from_be(addr4.sin_port),
            ))
        },
        libc::AF_INET6 => {
            let addr6 = unsafe { endpoint.addr6 };
            let bytes = unsafe { addr6.sin6_addr.__in6_u.__u6_addr8 };
            Some(SocketAddr::new(
                IpAddr::V6(bytes.into()),
                u16::from_be(addr6.sin6_port),
            ))
        },
        0 => None,
        _ => unreachable!(format!("Unsupported socket family: {}!", addr.sa_family)),
    }
}

fn encode_allowedips(
    allowed_ips: &[AllowedIp],
) -> (*mut wgctrl_sys::wg_allowedip, *mut wgctrl_sys::wg_allowedip) {
    if allowed_ips.is_empty() {
        return (ptr::null_mut(), ptr::null_mut());
    }

    let mut first_ip = ptr::null_mut();
    let mut last_ip: *mut wgctrl_sys::wg_allowedip = ptr::null_mut();

    for ip in allowed_ips {
        let mut wg_allowedip = Box::new(wgctrl_sys::wg_allowedip {
            family: 0,
            __bindgen_anon_1: Default::default(),
            cidr: ip.cidr,
            next_allowedip: first_ip,
        });

        match ip.address {
            IpAddr::V4(a) => {
                wg_allowedip.family = libc::AF_INET as u16;
                wg_allowedip.__bindgen_anon_1.ip4.s_addr = u32::to_be(a.into());
            },
            IpAddr::V6(a) => {
                wg_allowedip.family = libc::AF_INET6 as u16;
                wg_allowedip.__bindgen_anon_1.ip6.__in6_u.__u6_addr8 = a.octets();
            },
        }

        first_ip = Box::into_raw(wg_allowedip);
        if last_ip.is_null() {
            last_ip = first_ip;
        }
    }

    (first_ip, last_ip)
}

fn encode_endpoint(endpoint: Option<SocketAddr>) -> wgctrl_sys::wg_peer__bindgen_ty_1 {
    match endpoint {
        Some(SocketAddr::V4(s)) => {
            let mut peer = wgctrl_sys::wg_peer__bindgen_ty_1::default();
            peer.addr4 = wgctrl_sys::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_addr: wgctrl_sys::in_addr {
                    s_addr: u32::from_be((*s.ip()).into()),
                },
                sin_port: u16::to_be(s.port()),
                sin_zero: [0; 8],
            };
            peer
        },
        Some(SocketAddr::V6(s)) => {
            let mut peer = wgctrl_sys::wg_peer__bindgen_ty_1::default();
            let in6_addr = wgctrl_sys::in6_addr__bindgen_ty_1 {
                __u6_addr8: s.ip().octets(),
            };
            peer.addr6 = wgctrl_sys::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as u16,
                sin6_addr: wgctrl_sys::in6_addr { __in6_u: in6_addr },
                sin6_port: u16::to_be(s.port()),
                sin6_flowinfo: 0,
                sin6_scope_id: 0,
            };
            peer
        },
        None => wgctrl_sys::wg_peer__bindgen_ty_1::default(),
    }
}

fn encode_peers(
    peers: &[PeerConfigBuilder],
) -> (*mut wgctrl_sys::wg_peer, *mut wgctrl_sys::wg_peer) {
    let mut first_peer = ptr::null_mut();
    let mut last_peer: *mut wgctrl_sys::wg_peer = ptr::null_mut();

    for peer in peers {
        let (first_allowedip, last_allowedip) = encode_allowedips(&peer.allowed_ips);

        let mut wg_peer = Box::new(wgctrl_sys::wg_peer {
            public_key: peer.public_key.0,
            preshared_key: wgctrl_sys::wg_key::default(),
            endpoint: encode_endpoint(peer.endpoint),
            last_handshake_time: timespec64 {
                tv_sec: 0,
                tv_nsec: 0,
            },
            tx_bytes: 0,
            rx_bytes: 0,
            persistent_keepalive_interval: 0,
            first_allowedip,
            last_allowedip,
            next_peer: first_peer,
            flags: wgpf::WGPEER_HAS_PUBLIC_KEY,
        });

        if let Some(Key(k)) = peer.preshared_key {
            wg_peer.flags |= wgpf::WGPEER_HAS_PRESHARED_KEY;
            wg_peer.preshared_key = k;
        }

        if let Some(n) = peer.persistent_keepalive_interval {
            wg_peer.persistent_keepalive_interval = n;
            wg_peer.flags |= wgpf::WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL;
        }

        if peer.replace_allowed_ips {
            wg_peer.flags |= wgpf::WGPEER_REPLACE_ALLOWEDIPS;
        }

        if peer.remove_me {
            wg_peer.flags |= wgpf::WGPEER_REMOVE_ME;
        }

        first_peer = Box::into_raw(wg_peer);
        if last_peer.is_null() {
            last_peer = first_peer;
        }
    }

    (first_peer, last_peer)
}

pub fn enumerate() -> Result<Vec<InterfaceName>, io::Error> {
    let base = unsafe { wgctrl_sys::wg_list_device_names() };

    if base.is_null() {
        return Err(io::Error::last_os_error());
    }

    let mut current = base;
    let mut result = Vec::new();

    loop {
        let next_dev = unsafe { CStr::from_ptr(current).to_bytes() };

        let len = next_dev.len();

        if len == 0 {
            break;
        }

        current = unsafe { current.add(len + 1) };

        let interface: InterfaceName = str::from_utf8(next_dev)
            .map_err(|_| InvalidInterfaceName::InvalidChars)?
            .parse()?;

        result.push(interface);
    }

    unsafe { libc::free(base as *mut libc::c_void) };

    Ok(result)
}

pub fn apply(builder: &DeviceUpdate, iface: &InterfaceName) -> io::Result<()> {
    let (first_peer, last_peer) = encode_peers(&builder.peers);

    let result = unsafe { wgctrl_sys::wg_add_device(iface.as_ptr()) };
    match result {
        0 | -17 => {},
        _ => return Err(io::Error::last_os_error()),
    };

    let mut wg_device = Box::new(wgctrl_sys::wg_device {
        name: iface.into_inner(),
        ifindex: 0,
        public_key: wgctrl_sys::wg_key::default(),
        private_key: wgctrl_sys::wg_key::default(),
        fwmark: 0,
        listen_port: 0,
        first_peer,
        last_peer,
        flags: wgdf(0),
    });

    if let Some(Key(k)) = builder.public_key {
        wg_device.public_key = k;
        wg_device.flags |= wgdf::WGDEVICE_HAS_PUBLIC_KEY;
    }

    if let Some(Key(k)) = builder.private_key {
        wg_device.private_key = k;
        wg_device.flags |= wgdf::WGDEVICE_HAS_PRIVATE_KEY;
    }

    if let Some(f) = builder.fwmark {
        wg_device.fwmark = f;
        wg_device.flags |= wgdf::WGDEVICE_HAS_FWMARK;
    }

    if let Some(f) = builder.listen_port {
        wg_device.listen_port = f;
        wg_device.flags |= wgdf::WGDEVICE_HAS_LISTEN_PORT;
    }

    if builder.replace_peers {
        wg_device.flags |= wgdf::WGDEVICE_REPLACE_PEERS;
    }

    let ptr = Box::into_raw(wg_device);
    let result = unsafe { wgctrl_sys::wg_set_device(ptr) };

    unsafe { wgctrl_sys::wg_free_device(ptr) };

    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn get_by_name(name: &InterfaceName) -> Result<Device, io::Error> {
    let mut device: *mut wgctrl_sys::wg_device = ptr::null_mut();

    let result = unsafe {
        wgctrl_sys::wg_get_device(
            (&mut device) as *mut _ as *mut *mut wgctrl_sys::wg_device,
            name.as_ptr(),
        )
    };

    let result = if result == 0 {
        Ok(Device::from(unsafe { &*device }))
    } else {
        Err(io::Error::last_os_error())
    };

    unsafe { wgctrl_sys::wg_free_device(device) };

    result
}

pub fn delete_interface(iface: &InterfaceName) -> io::Result<()> {
    let result = unsafe { wgctrl_sys::wg_del_device(iface.as_ptr()) };

    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Represents a WireGuard encryption key.
///
/// WireGuard makes no meaningful distinction between public,
/// private and preshared keys - any sequence of 32 bytes
/// can be used as either of those.
///
/// This means that you need to be careful when working with
/// `Key`s, especially ones created from external data.
#[cfg(target_os = "linux")]
#[derive(PartialEq, Eq, Clone)]
pub struct Key(wgctrl_sys::wg_key);

#[cfg(target_os = "linux")]
impl Key {
    /// Creates a new `Key` from raw bytes.
    pub fn from_raw(key: wgctrl_sys::wg_key) -> Self {
        Self(key)
    }

    /// Generates and returns a new private key.
    pub fn generate_private() -> Self {
        let mut private_key = wgctrl_sys::wg_key::default();

        unsafe {
            wgctrl_sys::wg_generate_private_key(private_key.as_mut_ptr());
        }

        Self(private_key)
    }

    /// Generates and returns a new preshared key.
    pub fn generate_preshared() -> Self {
        let mut preshared_key = wgctrl_sys::wg_key::default();

        unsafe {
            wgctrl_sys::wg_generate_preshared_key(preshared_key.as_mut_ptr());
        }

        Self(preshared_key)
    }

    /// Generates a public key for this private key.
    pub fn generate_public(&self) -> Self {
        let mut public_key = wgctrl_sys::wg_key::default();

        unsafe {
            wgctrl_sys::wg_generate_public_key(
                public_key.as_mut_ptr(),
                &self.0 as *const u8 as *mut u8,
            );
        }

        Self(public_key)
    }

    /// Generates an all-zero key.
    pub fn zero() -> Self {
        Self(wgctrl_sys::wg_key::default())
    }

    /// Checks if this key is all-zero.
    pub fn is_zero(&self) -> bool {
        unsafe { wgctrl_sys::wg_key_is_zero(&self.0 as *const u8 as *mut u8) }
    }

    /// Converts the key to a standardized base64 representation, as used by the `wg` utility and `wg-quick`.
    pub fn to_base64(&self) -> String {
        let mut key_b64: wgctrl_sys::wg_key_b64_string = [0; 45];
        unsafe {
            wgctrl_sys::wg_key_to_base64(key_b64.as_mut_ptr(), &self.0 as *const u8 as *mut u8);

            str::from_utf8_unchecked(&*(&key_b64[..44] as *const [c_char] as *const [u8])).into()
        }
    }

    /// Converts a base64 representation of the key to the raw bytes.
    ///
    /// This can fail, as not all text input is valid base64 - in this case
    /// `Err(InvalidKey)` is returned.
    pub fn from_base64(key: &str) -> Result<Self, InvalidKey> {
        let mut decoded = wgctrl_sys::wg_key::default();

        let key_str = CString::new(key)?;
        let result = unsafe {
            wgctrl_sys::wg_key_from_base64(decoded.as_mut_ptr(), key_str.as_ptr() as *mut _)
        };

        if result == 0 {
            Ok(Self { 0: decoded })
        } else {
            Err(InvalidKey)
        }
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, InvalidKey> {
        let bytes = hex::decode(hex_str).map_err(|_| InvalidKey)?;
        Self::from_base64(&base64::encode(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_endpoint() -> Result<(), Box<dyn std::error::Error>> {
        let endpoint = Some("1.2.3.4:51820".parse()?);
        let endpoint6: Option<SocketAddr> = Some("[2001:db8:1::1]:51820".parse()?);
        let encoded = encode_endpoint(endpoint);
        let encoded6 = encode_endpoint(endpoint6);
        assert_eq!(endpoint, parse_endpoint(&encoded));
        assert_eq!(endpoint6, parse_endpoint(&encoded6));
        Ok(())
    }
}
