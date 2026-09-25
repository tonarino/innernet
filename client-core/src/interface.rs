pub use innernet_shared::interface_config::InterfaceConfig;
pub use wireguard_control::InterfaceName;

use crate::{
    data_store::DataStore,
    nat::{self, NatTraverse},
    rest_client::{RestClient, RestError},
    HostsOpts, NatOpts, NetworkOpts, WrappedIoError,
};
use anyhow::{bail, Context as _, Error};
use colored::{ColoredString, Colorize};
use innernet_shared::{
    get_local_addrs, update_hosts_file,
    wg::{self, DeviceExt as _, PeerInfoExt as _},
    Endpoint, PeerChange, PeerDiff, RedeemContents, State, REDEEM_TRANSITION_WAIT,
};
use std::{
    io,
    net::SocketAddr,
    path::Path,
    thread,
    time::{Duration, Instant},
};
use thiserror::Error;
use wireguard_control::{Backend, Device, DeviceUpdate, Key, PeerConfigBuilder};

/// Time allowed for a handshake with the server over one external endpoint. It exceeds
/// WireGuard's 5 s handshake retry interval, so a single lost handshake packet does not cause
/// a switch of endpoints.
const SERVER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(7);

#[derive(Debug, Error)]
pub enum RedeemInviteError {
    #[error("Error accessing innernet interface config file: {0}")]
    InterfaceConfigAccess(WrappedIoError),
    #[error("Config file for innernet interface {0} already exists.")]
    InterfaceConfigExists(InterfaceName),
    #[error("Error making a REST request: {0}")]
    RestRequest(#[from] RestError),
    #[error("Could not resolve server address for endpoint {endpoint}: {error}")]
    ServerAddressResolve {
        endpoint: Endpoint,
        error: io::Error,
    },
    #[error("WireGuard interface {0} already exists.")]
    WireguardInterfaceExists(InterfaceName),
    #[error("Error managing the Wireguard interface {interface}: {error}")]
    WireguardOperation {
        interface: InterfaceName,
        error: io::Error,
    },
}

/// Redeem an invitation to join an innernet network.
///
/// - Brings the WireGuard interface up.
/// - Generates a fresh key pair and uses the public part to redeem the invite and the private part
///   to update the WireGuard interface.
/// - Bails if either a WireGuard or an innernet `interface` of the same name already exists and
///   brings the interface down if it was already up.
pub fn redeem_invite(
    config_dir: &Path,
    network_opts: &NetworkOpts,
    interface: &InterfaceName,
    config: InterfaceConfig,
) -> Result<(), RedeemInviteError> {
    let config_path = InterfaceConfig::build_config_file_path(config_dir, interface)
        .map_err(RedeemInviteError::InterfaceConfigAccess)?;

    if config_path.exists() {
        return Err(RedeemInviteError::InterfaceConfigExists(*interface));
    }

    if Device::list(network_opts.backend)
        .iter()
        .flatten()
        .any(|name| name == interface)
    {
        return Err(RedeemInviteError::WireguardInterfaceExists(*interface));
    }

    log::info!(
        "bringing up interface {}.",
        interface.as_str_lossy().yellow()
    );

    connect_to_server(network_opts, interface, &config)?;

    update_keypair(network_opts, interface, &config_path, config).inspect_err(|e| {
        log::error!("failed to update keypair (is the innernet server reachable?): {e}.",);
        log::info!("bringing down the interface.");
        if let Err(e) = wg::down(interface, network_opts.backend) {
            log::warn!("failed to bring down interface: {}.", e);
        };
    })?;

    Ok(())
}

/// Brings the interface up with the server as its only peer.
///
/// The server's external endpoint is used first. Its IPv6 external endpoint is used instead
/// when the external endpoint does not resolve or no handshake completes over it within
/// [`SERVER_HANDSHAKE_TIMEOUT`]. If neither endpoint completes a handshake, the first one is
/// restored.
fn connect_to_server(
    network_opts: &NetworkOpts,
    interface: &InterfaceName,
    config: &InterfaceConfig,
) -> Result<(), RedeemInviteError> {
    let resolve = |endpoint: &Endpoint| {
        endpoint
            .resolve()
            .map_err(|error| RedeemInviteError::ServerAddressResolve {
                endpoint: endpoint.clone(),
                error,
            })
    };
    let wireguard_error = |error| RedeemInviteError::WireguardOperation {
        interface: *interface,
        error,
    };

    let server = &config.server;
    let fallback = server
        .external_endpoint_v6
        .as_ref()
        .map(resolve)
        .transpose()?;
    let (initial, fallback) = match (resolve(&server.external_endpoint), fallback) {
        (Ok(primary), fallback) => (primary, fallback),
        (Err(e), Some(fallback)) => {
            log::warn!("{e}; using the IPv6 external endpoint {fallback}.");
            (fallback, None)
        },
        (Err(e), None) => return Err(e),
    };

    wg::up(
        interface,
        &config.interface.private_key,
        config.interface.address,
        config.interface.listen_port,
        Some((&server.public_key, server.internal_endpoint.ip(), initial)),
        network_opts,
    )
    .map_err(wireguard_error)?;

    let Some(fallback) = fallback else {
        return Ok(());
    };
    let handshake_completes = || {
        wait_for_handshake(network_opts.backend, interface, &server.public_key)
            .map_err(wireguard_error)
    };
    let set_endpoint = |endpoint: SocketAddr| {
        let public_key = Key::from_base64(&server.public_key)
            .map_err(|e| wireguard_error(io::Error::new(io::ErrorKind::InvalidInput, e)))?;
        DeviceUpdate::new()
            .add_peer(PeerConfigBuilder::new(&public_key).set_endpoint(endpoint))
            .apply(interface, network_opts.backend)
            .map_err(wireguard_error)
    };

    if handshake_completes()? {
        return Ok(());
    }
    log::info!("no handshake with the server over {initial}, switching to {fallback}.");
    set_endpoint(fallback)?;

    if handshake_completes()? {
        return Ok(());
    }
    log::warn!("no handshake with the server over {fallback} either, switching back to {initial}.");
    set_endpoint(initial)
}

/// Returns whether a handshake with the peer completes within [`SERVER_HANDSHAKE_TIMEOUT`].
fn wait_for_handshake(
    backend: Backend,
    interface: &InterfaceName,
    public_key: &str,
) -> Result<bool, io::Error> {
    let start = Instant::now();
    while start.elapsed() < SERVER_HANDSHAKE_TIMEOUT {
        let device = Device::get(interface, backend)?;
        if device
            .get_peer(public_key)
            .is_some_and(|peer| peer.is_recently_connected())
        {
            return Ok(true);
        }
        thread::sleep(Duration::from_millis(100));
    }
    Ok(false)
}

fn update_keypair(
    network_opts: &NetworkOpts,
    interface: &InterfaceName,
    config_path: &Path,
    mut config: InterfaceConfig,
) -> Result<(), RedeemInviteError> {
    log::info!("Generating new keypair.");
    let keypair = wireguard_control::KeyPair::generate();

    log::info!(
        "Registering keypair with server (at {}).",
        config.server.internal_endpoint
    );
    RestClient::new(&config.server).http_form::<_, ()>(
        "POST",
        "/user/redeem",
        RedeemContents {
            public_key: keypair.public.to_base64(),
        },
    )?;

    config.interface.private_key = keypair.private.to_base64();
    config
        .save_new(config_path, 0o600)
        .map_err(RedeemInviteError::InterfaceConfigAccess)?;
    log::info!(
        "New keypair registered. Copied config to {}.\n",
        config_path.to_string_lossy().yellow()
    );

    log::info!("Changing keys and waiting 5s for server's WireGuard interface to transition.",);
    DeviceUpdate::new()
        .set_private_key(keypair.private)
        .apply(interface, network_opts.backend)
        .map_err(|e| RedeemInviteError::WireguardOperation {
            interface: *interface,
            error: e,
        })?;
    thread::sleep(REDEEM_TRANSITION_WAIT);

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
    let interface_up = interface_is_up(network_opts.backend, interface);

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
        connect_to_server(network_opts, interface, &config)?;
    }

    log::info!(
        "fetching state for {} from server...",
        interface.as_str_lossy().yellow()
    );
    let mut store = DataStore::open_or_create(data_dir, interface)?;
    let rest_client = RestClient::new(&config.server);
    let (State { mut peers, cidrs }, server_is_reachable) = match rest_client
        .http("GET", "/user/state")
    {
        Ok(state) => (state, true),
        Err(e) => {
            if e.is_transport_error() {
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
            } else {
                bail!(e)
            }
        },
    };

    // Apply the local peer endpoint overrides.
    for (peer_ip, endpoint_override) in config.peer_endpoint_overrides() {
        log::debug!(
            "overriding peer IP {} with endpoint {}",
            peer_ip,
            endpoint_override
        );

        if let Some(peer) = peers.iter_mut().find(|p| p.ip == *peer_ip) {
            peer.endpoint = Some(endpoint_override.clone());
        }
    }

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
        let mut nat_traverse =
            NatTraverse::new(interface, &config, network_opts.backend, &modifications)?;

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
        public_key[..10].dimmed(),
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
    if let Err(e) = rest_client.http_form::<_, ()>("PUT", "/user/candidates", &candidates) {
        if e.has_status_of(404) {
            log::warn!("your network is using an old version of innernet-server that doesn't support NAT traversal candidate reporting.")
        } else {
            return Err(e.into());
        }
    }

    log::debug!("candidates successfully reported");
    Ok(())
}

pub fn interface_is_up(backend: Backend, interface_name: &InterfaceName) -> bool {
    match Device::list(backend) {
        Ok(interfaces) => interfaces.contains(interface_name),
        _ => false,
    }
}
