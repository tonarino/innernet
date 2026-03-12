use anyhow::{Context, Error};
use env_logger::Env;
use innernet_client_core::{
    interface::{InterfaceConfig, InterfaceName},
    rest_client::RestClient,
    CidrContents, DEFAULT_CONFIG_DIR,
};
use std::{env, path::Path};

fn main() -> Result<(), Error> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let config_dir = Path::new(DEFAULT_CONFIG_DIR);
    let interface = env::args().nth(1).context("Usage: add_cidr <interface>")?;

    let interface: InterfaceName = interface.parse()?;
    let interface_config = InterfaceConfig::from_interface(config_dir, &interface)?;
    let rest_client = RestClient::new(&interface_config.server);
    let cidrs = rest_client.get_cidrs()?;

    let name = "example".to_owned();
    let cidr = "10.49.65.0/24".parse()?;
    let parent = &cidrs[0];

    let cidr_contents = CidrContents::new(name, cidr, parent);
    let cidr = rest_client.create_cidr(&cidr_contents)?;
    dbg!(&cidr);

    Ok(())
}
