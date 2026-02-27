use crate::{
    data_store::DataStore,
    nat::{self, NatTraverse},
    rest_client::RestClient,
};
use anyhow::{bail, Context as _, Error};
use colored::{ColoredString, Colorize};
use innernet_shared::{
    get_local_addrs,
    interface_config::InterfaceConfig,
    update_hosts_file,
    wg::{self, DeviceExt as _},
    Endpoint, HostsOpts, NatOpts, NetworkOpts, PeerChange, PeerDiff, RedeemContents, State,
    REDEEM_TRANSITION_WAIT,
};
use std::{
    net::SocketAddr,
    path::Path,
    thread,
    time::{Duration, Instant},
};
use wireguard_control::{Device, DeviceUpdate, InterfaceName, PeerConfigBuilder};

pub fn install(
    config_dir: &Path,
    data_dir: &Path,
    network_opts: &NetworkOpts,
    hosts_opts: &HostsOpts,
    nat_opts: &NatOpts,
    interface: &str,
    config: InterfaceConfig,
) -> Result<(), Error> {
    let interface = interface.parse()?;
    let config_path = InterfaceConfig::build_config_file_path(config_dir, &interface)?;
    if config_path.exists() {
        bail!(
            "An existing innernet network with the name \"{}\" already exists.",
            interface
        );
    }

    if Device::list(network_opts.backend)
        .iter()
        .flatten()
        .any(|name| name == &interface)
    {
        bail!(
            "An existing WireGuard interface with the name \"{}\" already exists.",
            interface
        );
    }

    redeem_invite(network_opts, &interface, &config_path, config).map_err(|e| {
        log::error!("failed to start the interface: {}.", e);
        log::info!("bringing down the interface.");
        if let Err(e) = wg::down(&interface, network_opts.backend) {
            log::warn!("failed to bring down interface: {}.", e);
        };
        log::error!("Failed to redeem invite. Now's a good time to make sure the server is started and accessible!");
        e
    })?;

    let mut fetch_success = false;
    for _ in 0..3 {
        if fetch(
            config_dir,
            data_dir,
            network_opts,
            hosts_opts,
            nat_opts,
            &interface,
            true,
        )
        .is_ok()
        {
            fetch_success = true;
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }
    if !fetch_success {
        log::warn!(
            "Failed to fetch peers from server, you will need to manually run the 'up' command.",
        );
    }

    Ok(())
}
pub fn fetch(
    config_dir: &Path,
    data_dir: &Path,
    network_opts: &NetworkOpts,
    hosts_opts: &HostsOpts,
    nat: &NatOpts,
    interface: &InterfaceName,
    bring_up_interface: bool,
) -> Result<(), Error> {
    let config = InterfaceConfig::from_interface(config_dir, interface)?;
    let interface_up = match Device::list(network_opts.backend) {
        Ok(interfaces) => interfaces.iter().any(|name| name == interface),
        _ => false,
    };

    if !interface_up {
        if !bring_up_interface {
            bail!(
                "Interface is not up. Use 'innernet up {}' instead",
                interface
            );
        }

        log::info!(
            "bringing up interface {}.",
            interface.as_str_lossy().yellow()
        );
        let resolved_endpoint = config
            .server
            .external_endpoint
            .resolve()
            .context(config.server.external_endpoint.to_string())?;
        wg::up(
            interface,
            &config.interface.private_key,
            config.interface.address,
            config.interface.listen_port,
            Some((
                &config.server.public_key,
                config.server.internal_endpoint.ip(),
                resolved_endpoint,
            )),
            network_opts,
        )
        .context(interface.to_string())?;
    }

    log::info!(
        "fetching state for {} from server...",
        interface.as_str_lossy().yellow()
    );
    let mut store = DataStore::open_or_create(data_dir, interface)?;
    let rest_client = RestClient::new(&config.server);
    let (State { peers, cidrs }, server_is_reachable) = match rest_client.http("GET", "/user/state")
    {
        Ok(state) => (state, true),
        Err(ureq::Error::Transport(_)) => {
            if store.peers().is_empty() {
                bail!(
                    "Could not connect to the innernet server and there are no cached peers, \
                     exiting."
                )
            }

            log::warn!(
                "Could not connect to the innernet server, proceeding with cached state instead."
            );
            let state = State {
                peers: store.peers().to_vec(),
                cidrs: store.cidrs().to_vec(),
            };
            (state, false)
        },
        Err(e) => bail!(e),
    };

    let device = Device::get(interface, network_opts.backend)?;
    let modifications = device.diff(&peers);

    let updates = modifications
        .iter()
        .inspect(|diff| print_peer_diff(&store, diff))
        .cloned()
        .map(PeerConfigBuilder::from)
        .collect::<Vec<_>>();

    if !updates.is_empty() || !interface_up {
        DeviceUpdate::new()
            .add_peers(&updates)
            .apply(interface, network_opts.backend)
            .context(interface.to_string())?;

        if !hosts_opts.no_write_hosts {
            update_hosts_file(interface, hosts_opts, &peers)?;
        }

        println!();
        log::info!("updated interface {}\n", interface.as_str_lossy().yellow());
    } else {
        log::info!("{}", "peers are already up to date".green());
    }
    let interface_updated_time = Instant::now();

    store
        .update_peers_and_set_cidrs(&peers, cidrs)
        .context(interface.to_string())?;

    let listen_port = device.listen_port.unwrap_or(51820);
    if server_is_reachable {
        report_candidates(&rest_client, nat, listen_port)?;
    }

    if nat.no_nat_traversal {
        log::debug!("NAT traversal explicitly disabled, not attempting.");
    } else {
        let mut nat_traverse = NatTraverse::new(interface, network_opts.backend, &modifications)?;

        // Give time for handshakes with recently changed endpoints to complete before attempting traversal.
        if !nat_traverse.is_finished() {
            thread::sleep(nat::STEP_INTERVAL - interface_updated_time.elapsed());
        }
        loop {
            if nat_traverse.is_finished() {
                break;
            }
            log::info!(
                "Attempting to establish connection with {} remaining unconnected peers...",
                nat_traverse.remaining()
            );
            nat_traverse.step()?;
        }
    }

    Ok(())
}

fn redeem_invite(
    network_opts: &NetworkOpts,
    iface: &InterfaceName,
    config_path: &Path,
    mut config: InterfaceConfig,
) -> Result<(), Error> {
    log::info!("bringing up interface {}.", iface.as_str_lossy().yellow());
    let resolved_endpoint = config
        .server
        .external_endpoint
        .resolve()
        .context(config.server.external_endpoint.to_string())?;
    wg::up(
        iface,
        &config.interface.private_key,
        config.interface.address,
        None,
        Some((
            &config.server.public_key,
            config.server.internal_endpoint.ip(),
            resolved_endpoint,
        )),
        network_opts,
    )
    .context(iface.to_string())?;

    log::info!("Generating new keypair.");
    let keypair = wireguard_control::KeyPair::generate();

    log::info!(
        "Registering keypair with server (at {}).",
        &config.server.internal_endpoint
    );
    RestClient::new(&config.server).http_form::<_, ()>(
        "POST",
        "/user/redeem",
        RedeemContents {
            public_key: keypair.public.to_base64(),
        },
    )?;

    config.interface.private_key = keypair.private.to_base64();
    config.write_to_path(config_path, false, Some(0o600))?;
    log::info!(
        "New keypair registered. Copied config to {}.\n",
        config_path.to_string_lossy().yellow()
    );

    log::info!("Changing keys and waiting 5s for server's WireGuard interface to transition.",);
    DeviceUpdate::new()
        .set_private_key(keypair.private)
        .apply(iface, network_opts.backend)
        .context(iface.to_string())?;
    thread::sleep(REDEEM_TRANSITION_WAIT);

    Ok(())
}

#[derive(Debug, Copy, Clone, PartialEq)]
enum ChangeAction {
    Added,
    Modified,
    Removed,
}

impl ChangeAction {
    fn colored_output(&self) -> ColoredString {
        match self {
            Self::Added => "added".green(),
            Self::Modified => "modified".yellow(),
            Self::Removed => "removed".red(),
        }
    }
}

fn print_peer_diff(store: &DataStore, diff: &PeerDiff) {
    let public_key = diff.public_key().to_base64();

    let change_action = match (diff.old, diff.new) {
        (None, Some(_)) => ChangeAction::Added,
        (Some(_), Some(_)) => ChangeAction::Modified,
        (Some(_), None) => ChangeAction::Removed,
        _ => unreachable!("PeerDiff can't be None -> None"),
    };

    // Grab the peer name from either the new data, or the historical data (if the peer is removed).
    let peer_hostname = match diff.new {
        Some(peer) => Some(peer.name.clone()),
        None => store
            .peers()
            .iter()
            .find(|p| p.public_key == public_key)
            .map(|p| p.name.clone()),
    };
    let peer_name = peer_hostname.as_deref().unwrap_or("[unknown]");

    if change_action == ChangeAction::Modified
        && diff
            .changes()
            .iter()
            .all(|c| *c == PeerChange::NatTraverseReattempt)
    {
        // If this peer was "modified" but the only change is a NAT Traversal Reattempt,
        // don't bother printing this peer.
        return;
    }

    log::info!(
        "  peer {} ({}...) was {}.",
        peer_name.yellow(),
        &public_key[..10].dimmed(),
        change_action.colored_output(),
    );

    for change in diff.changes() {
        if let PeerChange::Endpoint { .. } = change {
            log::info!("    {}", change);
        } else {
            log::debug!("    {}", change);
        }
    }
}

fn report_candidates(
    rest_client: &RestClient,
    nat: &NatOpts,
    listen_port: u16,
) -> Result<(), Error> {
    let candidates: Vec<Endpoint> = get_local_addrs()?
        .filter(|ip| !nat.is_excluded(*ip))
        .map(|addr| SocketAddr::from((addr, listen_port)).into())
        .collect::<Vec<Endpoint>>();
    log::info!(
        "reporting {} interface address{} as NAT traversal candidates",
        candidates.len(),
        if candidates.len() == 1 { "" } else { "es" },
    );
    for candidate in &candidates {
        log::debug!("  candidate: {}", candidate);
    }
    match rest_client.http_form::<_, ()>("PUT", "/user/candidates", &candidates) {
        Err(ureq::Error::Status(404, _)) => {
            log::warn!("your network is using an old version of innernet-server that doesn't support NAT traversal candidate reporting.")
        },
        Err(e) => return Err(e.into()),
        _ => {},
    }

    log::debug!("candidates successfully reported");
    Ok(())
}
