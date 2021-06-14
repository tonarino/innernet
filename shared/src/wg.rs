use crate::{Error, IoErrorContext, NetworkOpt};
use ipnetwork::IpNetwork;
use std::net::{IpAddr, SocketAddr};
use wgctrl::{Backend, Device, DeviceUpdate, InterfaceName, PeerConfigBuilder};

#[cfg(target_os = "macos")]
fn cmd(bin: &str, args: &[&str]) -> Result<std::process::Output, Error> {
    let output = std::process::Command::new(bin).args(args).output()?;
    log::debug!("cmd: {} {}", bin, args.join(" "));
    log::debug!("status: {:?}", output.status.code());
    log::trace!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    log::trace!("stderr: {}", String::from_utf8_lossy(&output.stderr));
    if output.status.success() {
        Ok(output)
    } else {
        Err(anyhow::anyhow!(
            "failed to run {} {} command: {}",
            bin,
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

#[cfg(target_os = "macos")]
pub fn set_addr(interface: &InterfaceName, addr: IpNetwork) -> Result<(), Error> {
    let real_interface =
        wgctrl::backends::userspace::resolve_tun(interface).with_str(interface.to_string())?;

    if addr.is_ipv4() {
        cmd(
            "ifconfig",
            &[
                &real_interface,
                "inet",
                &addr.to_string(),
                &addr.ip().to_string(),
                "alias",
            ],
        )
        .map(|_output| ())
    } else {
        cmd(
            "ifconfig",
            &[&real_interface, "inet6", &addr.to_string(), "alias"],
        )
        .map(|_output| ())
    }
}

#[cfg(target_os = "macos")]
pub fn set_up(interface: &InterfaceName, mtu: u32) -> Result<(), Error> {
    let real_interface =
        wgctrl::backends::userspace::resolve_tun(interface).with_str(interface.to_string())?;
    cmd("ifconfig", &[&real_interface, "mtu", &mtu.to_string()])?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub use super::netlink::set_addr;

#[cfg(target_os = "linux")]
pub use super::netlink::set_up;

pub fn up(
    interface: &InterfaceName,
    private_key: &str,
    address: IpNetwork,
    listen_port: Option<u16>,
    peer: Option<(&str, IpAddr, SocketAddr)>,
    network: NetworkOpt,
) -> Result<(), Error> {
    let mut device = DeviceUpdate::new();
    if let Some((public_key, address, endpoint)) = peer {
        let prefix = if address.is_ipv4() { 32 } else { 128 };
        let peer_config = PeerConfigBuilder::new(&wgctrl::Key::from_base64(&public_key)?)
            .add_allowed_ip(address, prefix)
            .set_endpoint(endpoint);
        device = device.add_peer(peer_config);
    }
    if let Some(listen_port) = listen_port {
        device = device.set_listen_port(listen_port);
    }
    device
        .set_private_key(wgctrl::Key::from_base64(&private_key).unwrap())
        .apply(interface, network.backend)?;
    set_addr(interface, address)?;
    set_up(interface, 1420)?;
    if !network.no_routing {
        add_route(interface, address)?;
    }
    Ok(())
}

pub fn set_listen_port(
    interface: &InterfaceName,
    listen_port: Option<u16>,
    backend: Backend,
) -> Result<(), Error> {
    let mut device = DeviceUpdate::new();
    if let Some(listen_port) = listen_port {
        device = device.set_listen_port(listen_port);
    } else {
        device = device.randomize_listen_port();
    }
    device.apply(interface, backend)?;

    Ok(())
}

pub fn down(interface: &InterfaceName, backend: Backend) -> Result<(), Error> {
    Ok(Device::get(interface, backend)
        .with_str(interface.as_str_lossy())?
        .delete()
        .with_str(interface.as_str_lossy())?)
}

/// Add a route in the OS's routing table to get traffic flowing through this interface.
/// Returns an error if the process doesn't exit successfully, otherwise returns
/// true if the route was changed, false if the route already exists.
#[cfg(target_os = "macos")]
pub fn add_route(interface: &InterfaceName, cidr: IpNetwork) -> Result<bool, Error> {
    let real_interface =
        wgctrl::backends::userspace::resolve_tun(interface).with_str(interface.to_string())?;
    let output = cmd(
        "route",
        &[
            "-n",
            "add",
            if cidr.is_ipv4() { "-inet" } else { "-inet6" },
            &cidr.to_string(),
            "-interface",
            &real_interface,
        ],
    )?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        Err(anyhow::anyhow!(
            "failed to add route for device {} ({}): {}",
            &interface,
            real_interface,
            stderr
        ))
    } else {
        Ok(!stderr.contains("File exists"))
    }
}

#[cfg(target_os = "linux")]
pub use super::netlink::add_route;
