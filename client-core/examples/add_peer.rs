use anyhow::{Context, Error};
use env_logger::Env;
use innernet_client_core::{
    interface::{InterfaceConfig, InterfaceName},
    peer::{create_peer, NewPeerInfo},
    rest_client::RestClient,
    DEFAULT_CONFIG_DIR,
};
use innernet_shared::prompts;
use std::{
    env,
    net::{IpAddr, Ipv4Addr},
    path::Path,
};

fn main() -> Result<(), Error> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let config_dir = Path::new(DEFAULT_CONFIG_DIR);
    let interface = env::args().nth(1).context("Usage: add_peer <interface>")?;

    let interface: InterfaceName = interface.parse()?;
    let interface_config = InterfaceConfig::from_interface(config_dir, &interface)?;
    let rest_client = RestClient::new(&interface_config.server);
    let cidrs = rest_client.get_cidrs()?;
    let peers = rest_client.get_peers()?;

    let new_peer_info = NewPeerInfo {
        name: "joe".parse().unwrap(),
        ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        cidr_id: cidrs[0].id,
        is_admin: false,
        invite_expires: "1m".parse().unwrap(),
    };

    let target_path = "invitation.toml";
    let (peer, invitation) = create_peer(config_dir, &interface, &cidrs, &peers, new_peer_info)?;
    invitation.save_new(target_path)?;
    prompts::print_invitation_info(&peer, target_path);

    Ok(())
}
