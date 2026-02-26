use anyhow::{Context, Error};
use innernet_client_core::{peer, rest_api::RestApi, rest_client::RestClient};
use innernet_shared::{interface_config::InterfaceConfig, peer::NewPeerInfo, CidrTree};
use std::{
    net::{IpAddr, Ipv4Addr},
    path::Path,
};
use wireguard_control::InterfaceName;

fn main() -> Result<(), Error> {
    let config_dir = Path::new("/etc/innernet");
    let interface = std::env::args()
        .nth(1)
        .context("Usage: add_peer <interface>")?;

    let interface: InterfaceName = interface.parse()?;
    let interface_config = InterfaceConfig::from_interface(config_dir, &interface)?;
    let rest_client = RestClient::new(&interface_config.server);
    let rest_api = RestApi::new(rest_client);

    let peers = rest_api.get_peers()?;
    let server_peer = peers.iter().find(|p| p.id == 1).unwrap();

    let cidrs = rest_api.get_cidrs()?;
    let cidr_tree = CidrTree::new(&cidrs);

    let new_peer_info = NewPeerInfo {
        name: "joe".parse().unwrap(),
        ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        cidr_id: cidrs[0].id,
        is_admin: false,
        invite_expires: "1m".parse().unwrap(),
    };

    let target_path = "invitation.toml";
    let server_api_addr = &interface_config.server.internal_endpoint;

    peer::create_peer_and_invitation(
        rest_api,
        &interface,
        &cidr_tree,
        server_peer,
        new_peer_info,
        target_path,
        server_api_addr,
    )?;

    Ok(())
}
