use anyhow::{Context as _, Error};
use env_logger::Env;
use innernet_client_core::{
    interface::InterfaceName, set_listen_port, Context, DEFAULT_CONFIG_DIR,
};
use log::info;
use std::{env, path::Path};

fn main() -> Result<(), Error> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let interface = env::args()
        .nth(1)
        .context("Usage: set_listen_port <interface> [listen_port]")?;
    let interface: InterfaceName = interface.parse()?;
    let config_dir = Path::new(DEFAULT_CONFIG_DIR);
    let mut context = Context::new(config_dir.into(), interface)?;

    info!(
        "Current listen port: {:?}",
        context.interface_info().listen_port
    );

    let network_backend = Default::default();
    let listen_port: Option<u16> = env::args().nth(2).map(|port| port.parse()).transpose()?;
    set_listen_port(&mut context, network_backend, listen_port)?;

    Ok(())
}
