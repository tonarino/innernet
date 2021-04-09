use crate::{Error, IoErrorContext};
use ipnetwork::IpNetwork;
use std::{
    net::{IpAddr, SocketAddr},
    process::{self, Command},
};
use wgctrl::{DeviceConfigBuilder, InterfaceName, PeerConfigBuilder};

fn cmd(bin: &str, args: &[&str]) -> Result<process::Output, Error> {
    let output = Command::new(bin).args(args).output()?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(format!(
            "failed to run {} {} command: {}",
            bin,
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        )
        .into())
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
        )?;
    } else {
        cmd(
            "ifconfig",
            &[&real_interface, "inet6", &addr.to_string(), "alias"],
        )?;
    }
    cmd("ifconfig", &[&real_interface, "mtu", "1420"])?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn set_addr(interface: &InterfaceName, addr: IpNetwork) -> Result<(), Error> {
    let interface = interface.to_string();
    cmd(
        "ip",
        &["address", "replace", &addr.to_string(), "dev", &interface],
    )?;
    let _ = cmd(
        "ip",
        &["link", "set", "mtu", "1420", "up", "dev", &interface],
    );
    Ok(())
}

pub fn up(
    interface: &InterfaceName,
    private_key: &str,
    address: IpNetwork,
    listen_port: Option<u16>,
    peer: Option<(&str, IpAddr, SocketAddr)>,
) -> Result<(), Error> {
    let mut device = DeviceConfigBuilder::new();
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
        .apply(interface)?;
    set_addr(interface, address)?;
    add_route(interface, address)?;
    Ok(())
}

pub fn set_listen_port(interface: &InterfaceName, listen_port: Option<u16>) -> Result<(), Error> {
    let mut device = DeviceConfigBuilder::new();
    if let Some(listen_port) = listen_port {
        device = device.set_listen_port(listen_port);
    } else {
        device = device.randomize_listen_port();
    }
    device.apply(interface)?;

    Ok(())
}

#[cfg(target_os = "linux")]
pub fn down(interface: &InterfaceName) -> Result<(), Error> {
    Ok(wgctrl::delete_interface(&interface).with_str(interface.to_string())?)
}

#[cfg(not(target_os = "linux"))]
pub fn down(interface: &InterfaceName) -> Result<(), Error> {
    wgctrl::backends::userspace::delete_interface(interface)
        .with_str(interface.to_string())
        .map_err(Error::from)
}

/// Add a route in the OS's routing table to get traffic flowing through this interface.
/// Returns an error if the process doesn't exit successfully, otherwise returns
/// true if the route was changed, false if the route already exists.
pub fn add_route(interface: &InterfaceName, cidr: IpNetwork) -> Result<bool, Error> {
    if cfg!(target_os = "macos") {
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
            Err(format!(
                "failed to add route for device {} ({}): {}",
                &interface, real_interface, stderr
            )
            .into())
        } else {
            Ok(!stderr.contains("File exists"))
        }
    } else {
        // TODO(mcginty): use the netlink interface on linux to modify routing table.
        let _ = cmd(
            "ip",
            &[
                "route",
                "add",
                &cidr.to_string(),
                "dev",
                &interface.to_string(),
            ],
        );
        Ok(false)
    }
}
