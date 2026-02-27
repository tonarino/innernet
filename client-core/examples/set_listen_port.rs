use anyhow::{Context as _, Error};
use env_logger::Env;
use innernet_client_core::set_listen_port;
use innernet_shared::interface_config::InterfaceConfig;
use log::info;
use std::{env, path::Path};
use wireguard_control::InterfaceName;

fn main() -> Result<(), Error> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let interface = env::args()
        .nth(1)
        .context("Usage: add_peer <interface> [listen_port]")?;
    let interface: InterfaceName = interface.parse()?;

    let listen_port: Option<u16> = env::args().nth(2).map(|port| port.parse()).transpose()?;

    let config_dir = Path::new("/etc/innernet");
    let mut config = InterfaceConfig::from_interface(config_dir, &interface)?;
    let network_backend = Default::default();

    info!("Current listen port: {:?}", config.interface.listen_port);

    set_listen_port(
        network_backend,
        config_dir,
        &interface,
        &mut config,
        listen_port,
    )?;

    Ok(())
}
