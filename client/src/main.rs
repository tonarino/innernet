use anyhow::{anyhow, bail};
use colored::*;
use dialoguer::{Confirm, Input};
use hostsfile::HostsBuilder;
use indoc::eprintdoc;
use shared::{
    interface_config::InterfaceConfig, prompts, AddAssociationOpts, AddCidrOpts, AddPeerOpts,
    Association, AssociationContents, Cidr, CidrTree, DeleteCidrOpts, EndpointContents,
    InstallOpts, Interface, IoErrorContext, NetworkOpt, Peer, PeerDiff, RedeemContents,
    RenamePeerOpts, State, WrappedIoError, CLIENT_CONFIG_DIR, REDEEM_TRANSITION_WAIT,
};
use std::{
    fmt, io,
    path::{Path, PathBuf},
    thread,
    time::{Duration, SystemTime},
};
use structopt::{clap::AppSettings, StructOpt};
use wgctrl::{Device, DeviceUpdate, InterfaceName, PeerConfigBuilder, PeerInfo};

mod data_store;
mod util;

use data_store::DataStore;
use shared::{wg, Error};
use util::{human_duration, human_size, Api};

struct PeerState<'a> {
    peer: &'a Peer,
    info: Option<&'a PeerInfo>,
}

macro_rules! println_pad {
    ($pad:expr, $($arg:tt)*) => {
        print!("{:pad$}", "", pad = $pad);
        println!($($arg)*);
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "innernet", about, global_settings(&[AppSettings::ColoredHelp, AppSettings::DeriveDisplayOrder, AppSettings::VersionlessSubcommands, AppSettings::UnifiedHelpMessage]))]
struct Opts {
    #[structopt(subcommand)]
    command: Option<Command>,

    /// Verbose output, use -vv for even higher verbositude.
    #[structopt(short, long, parse(from_occurrences))]
    verbose: u64,

    #[structopt(flatten)]
    network: NetworkOpt,
}

#[derive(Debug, StructOpt)]
struct HostsOpt {
    /// The path to write hosts to.
    #[structopt(long = "hosts-path", default_value = "/etc/hosts")]
    hosts_path: PathBuf,

    /// Don't write to any hosts files.
    #[structopt(long = "no-write-hosts", conflicts_with = "hosts-path")]
    no_write_hosts: bool,
}

impl From<HostsOpt> for Option<PathBuf> {
    fn from(opt: HostsOpt) -> Self {
        (!opt.no_write_hosts).then(|| opt.hosts_path)
    }
}

#[derive(Debug, StructOpt)]
enum Command {
    /// Install a new innernet config.
    #[structopt(alias = "redeem")]
    Install {
        /// Path to the invitation file
        invite: PathBuf,

        #[structopt(flatten)]
        hosts: HostsOpt,

        #[structopt(flatten)]
        opts: InstallOpts,
    },

    /// Enumerate all innernet connections.
    #[structopt(alias = "list")]
    Show {
        /// One-line peer list
        #[structopt(short, long)]
        short: bool,

        /// Display peers in a tree based on the CIDRs
        #[structopt(short, long)]
        tree: bool,

        interface: Option<Interface>,
    },

    /// Bring up your local interface, and update it with latest peer list.
    Up {
        /// Enable daemon mode i.e. keep the process running, while fetching
        /// the latest peer list periodically.
        #[structopt(short, long)]
        daemon: bool,

        /// Keep fetching the latest peer list at the specified interval in
        /// seconds. Valid only in daemon mode.
        #[structopt(long, default_value = "60")]
        interval: u64,

        #[structopt(flatten)]
        hosts: HostsOpt,

        interface: Interface,
    },

    /// Fetch and update your local interface with the latest peer list.
    Fetch {
        interface: Interface,

        #[structopt(flatten)]
        hosts: HostsOpt,
    },

    /// Uninstall an innernet network.
    Uninstall { interface: Interface },

    /// Bring down the interface (equivalent to "wg-quick down <interface>")
    Down { interface: Interface },

    /// Add a new peer.
    ///
    /// By default, you'll be prompted interactively to create a peer, but you can
    /// also specify all the options in the command, eg:
    ///
    /// --name "person" --cidr "humans" --admin false --auto-ip --save-config "person.toml" --yes
    AddPeer {
        interface: Interface,

        #[structopt(flatten)]
        opts: AddPeerOpts,
    },

    /// Rename a peer.
    ///
    /// By default, you'll be prompted interactively to select a peer, but you can
    /// also specify all the options in the command, eg:
    ///
    /// --name "person" --new-name "human"
    RenamePeer {
        interface: Interface,

        #[structopt(flatten)]
        opts: RenamePeerOpts,
    },

    /// Add a new CIDR.
    AddCidr {
        interface: Interface,

        #[structopt(flatten)]
        opts: AddCidrOpts,
    },

    /// Delete a CIDR.
    DeleteCidr {
        interface: Interface,

        #[structopt(flatten)]
        opts: DeleteCidrOpts,
    },

    /// List CIDRs.
    ListCidrs {
        interface: Interface,

        /// Display CIDRs in tree format
        #[structopt(short, long)]
        tree: bool,
    },

    /// Disable an enabled peer.
    DisablePeer { interface: Interface },

    /// Enable a disabled peer.
    EnablePeer { interface: Interface },

    /// Add an association between CIDRs.
    AddAssociation {
        interface: Interface,

        #[structopt(flatten)]
        opts: AddAssociationOpts,
    },

    /// Delete an association between CIDRs.
    DeleteAssociation { interface: Interface },

    /// List existing assocations between CIDRs.
    ListAssociations { interface: Interface },

    /// Set the local listen port.
    SetListenPort {
        interface: Interface,

        /// Unset the local listen port to use a randomized port.
        #[structopt(short, long)]
        unset: bool,
    },

    /// Override your external endpoint that the server sends to other peers.
    OverrideEndpoint {
        interface: Interface,

        /// Unset an existing override to use the automatic endpoint discovery.
        #[structopt(short, long)]
        unset: bool,
    },

    /// Generate shell completion scripts
    Completions {
        #[structopt(possible_values = &structopt::clap::Shell::variants(), case_insensitive = true)]
        shell: structopt::clap::Shell,
    },
}

/// Application-level error.
#[derive(Debug, Clone)]
pub(crate) struct ClientError(String);

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

fn update_hosts_file(
    interface: &InterfaceName,
    hosts_path: PathBuf,
    peers: &[Peer],
) -> Result<(), WrappedIoError> {
    log::info!("updating {} with the latest peers.", "/etc/hosts".yellow());

    let mut hosts_builder = HostsBuilder::new(format!("innernet {}", interface));
    for peer in peers {
        hosts_builder.add_hostname(
            peer.contents.ip,
            &format!("{}.{}.wg", peer.contents.name, interface),
        );
    }
    if let Err(e) = hosts_builder.write_to(&hosts_path).with_path(hosts_path) {
        log::warn!("failed to update hosts ({})", e);
    }

    Ok(())
}

fn install(
    invite: &Path,
    hosts_file: Option<PathBuf>,
    opts: InstallOpts,
    network: NetworkOpt,
) -> Result<(), Error> {
    shared::ensure_dirs_exist(&[*CLIENT_CONFIG_DIR])?;
    let config = InterfaceConfig::from_file(invite)?;

    let iface = if opts.default_name {
        config.interface.network_name.clone()
    } else if let Some(ref iface) = opts.name {
        iface.clone()
    } else {
        Input::with_theme(&*prompts::THEME)
            .with_prompt("Interface name")
            .default(config.interface.network_name.clone())
            .interact()?
    };

    let target_conf = CLIENT_CONFIG_DIR.join(&iface).with_extension("conf");
    if target_conf.exists() {
        bail!(
            "An existing innernet network with the name \"{}\" already exists.",
            iface
        );
    }
    let iface = iface.parse()?;
    if Device::list(network.backend)
        .iter()
        .flatten()
        .any(|name| name == &iface)
    {
        bail!(
            "An existing WireGuard interface with the name \"{}\" already exists.",
            iface
        );
    }

    redeem_invite(&iface, config, target_conf, network).map_err(|e| {
        log::error!("failed to start the interface: {}.", e);
        log::info!("bringing down the interface.");
        if let Err(e) = wg::down(&iface, network.backend) {
            log::warn!("failed to bring down interface: {}.", e.to_string());
        };
        log::error!("Failed to redeem invite. Now's a good time to make sure the server is started and accessible!");
        e
    })?;

    let mut fetch_success = false;
    for _ in 0..3 {
        if fetch(&iface, true, hosts_file.clone(), network).is_ok() {
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

    if opts.delete_invite
        || Confirm::with_theme(&*prompts::THEME)
            .wait_for_newline(true)
            .with_prompt(&format!(
                "Delete invitation file \"{}\" now? (It's no longer needed)",
                invite.to_string_lossy().yellow()
            ))
            .default(true)
            .interact()?
    {
        std::fs::remove_file(invite).with_path(invite)?;
    }

    eprintdoc!(
        "
        {star} Done!

            {interface} has been {installed}.

            It's recommended to now keep the interface automatically refreshing via systemd:

                {systemctl_enable}{interface}

            By default, innernet will write to your /etc/hosts file for peer name
            resolution. To disable this behavior, use the --no-write-hosts or --write-hosts [PATH]
            options.

            See the manpage or innernet GitHub repo for more detailed instruction on managing your
            interface and network. Have fun!

    ",
        star = "[*]".dimmed(),
        interface = iface.to_string().yellow(),
        installed = "installed".green(),
        systemctl_enable = "systemctl enable --now innernet@".yellow(),
    );
    Ok(())
}

fn redeem_invite(
    iface: &InterfaceName,
    mut config: InterfaceConfig,
    target_conf: PathBuf,
    network: NetworkOpt,
) -> Result<(), Error> {
    log::info!("bringing up the interface.");
    let resolved_endpoint = config
        .server
        .external_endpoint
        .resolve()
        .with_str(config.server.external_endpoint.to_string())?;
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
        network,
    )
    .with_str(iface.to_string())?;

    log::info!("Generating new keypair.");
    let keypair = wgctrl::KeyPair::generate();

    log::info!(
        "Registering keypair with server (at {}).",
        &config.server.internal_endpoint
    );
    Api::new(&config.server).http_form(
        "POST",
        "/user/redeem",
        RedeemContents {
            public_key: keypair.public.to_base64(),
        },
    )?;

    config.interface.private_key = keypair.private.to_base64();
    config.write_to_path(&target_conf, false, Some(0o600))?;
    log::info!(
        "New keypair registered. Copied config to {}.\n",
        target_conf.to_string_lossy().yellow()
    );

    log::info!("Changing keys and waiting for server's WireGuard interface to transition.",);
    DeviceUpdate::new()
        .set_private_key(keypair.private)
        .apply(iface, network.backend)
        .with_str(iface.to_string())?;
    thread::sleep(*REDEEM_TRANSITION_WAIT);

    Ok(())
}

fn up(
    interface: &InterfaceName,
    loop_interval: Option<Duration>,
    hosts_path: Option<PathBuf>,
    routing: NetworkOpt,
) -> Result<(), Error> {
    loop {
        fetch(interface, true, hosts_path.clone(), routing)?;
        match loop_interval {
            Some(interval) => thread::sleep(interval),
            None => break,
        }
    }

    Ok(())
}

fn fetch(
    interface: &InterfaceName,
    bring_up_interface: bool,
    hosts_path: Option<PathBuf>,
    network: NetworkOpt,
) -> Result<(), Error> {
    let config = InterfaceConfig::from_interface(interface)?;
    let interface_up = match Device::list(network.backend) {
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

        log::info!("bringing up the interface.");
        let resolved_endpoint = config
            .server
            .external_endpoint
            .resolve()
            .with_str(config.server.external_endpoint.to_string())?;
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
            network,
        )
        .with_str(interface.to_string())?;
    }

    log::info!("fetching state from server.");
    let mut store = DataStore::open_or_create(interface)?;
    let State { peers, cidrs } = Api::new(&config.server).http("GET", "/user/state")?;

    let device_info = Device::get(interface, network.backend).with_str(interface.as_str_lossy())?;
    let interface_public_key = device_info
        .public_key
        .as_ref()
        .map(|k| k.to_base64())
        .unwrap_or_default();
    let existing_peers = &device_info.peers;

    // Match existing peers (by pubkey) to new peer information from the server.
    let modifications = peers.iter().filter_map(|peer| {
        if peer.is_disabled || peer.public_key == interface_public_key {
            None
        } else {
            let existing_peer = existing_peers
                .iter()
                .find(|p| p.config.public_key.to_base64() == peer.public_key);

            Some(PeerDiff::new(existing_peer.map(|p| &p.config), Some(peer)).unwrap())
        }
    });

    // Remove any peers on the interface that aren't in the server's peer list any more.
    let removals = existing_peers.iter().filter_map(|existing| {
        let public_key = existing.config.public_key.to_base64();
        if peers.iter().any(|p| p.public_key == public_key) {
            None
        } else {
            Some(PeerDiff::new(Some(&existing.config), None).unwrap())
        }
    });

    let updates = modifications
        .chain(removals)
        .inspect(|diff| {
            let public_key = diff.public_key().to_base64();

            let text = match (diff.old, diff.new) {
                (None, Some(_)) => "added",
                (Some(_), Some(_)) => "modified",
                (Some(_), None) => "removed",
                _ => unreachable!("PeerDiff can't be None -> None"),
            };

            let peer_hostname = match diff {
                PeerDiff {
                    new: Some(peer), ..
                } => Some(peer.name.clone()),
                _ => store
                    .peers()
                    .iter()
                    .find(|p| p.public_key == public_key)
                    .map(|p| p.name.clone()),
            };
            let peer_name = peer_hostname.as_deref().unwrap_or("[unknown]");

            println!(
                "    peer {} ({}...) was {}.",
                peer_name.yellow(),
                &public_key[..10].dimmed(),
                text
            );
        })
        .map(PeerConfigBuilder::from)
        .collect::<Vec<_>>();

    if !updates.is_empty() {
        DeviceUpdate::new()
            .add_peers(&updates)
            .apply(interface, network.backend)
            .with_str(interface.to_string())?;

        if let Some(path) = hosts_path {
            update_hosts_file(interface, path, &peers)?;
        }

        println!();
        log::info!("updated interface {}\n", interface.as_str_lossy().yellow());
    } else {
        log::info!("{}", "peers are already up to date.".green());
    }
    store.set_cidrs(cidrs);
    store.update_peers(peers)?;
    store.write().with_str(interface.to_string())?;

    Ok(())
}

fn uninstall(interface: &InterfaceName, network: NetworkOpt) -> Result<(), Error> {
    if Confirm::with_theme(&*prompts::THEME)
        .with_prompt(&format!(
            "Permanently delete network \"{}\"?",
            interface.as_str_lossy().yellow()
        ))
        .default(false)
        .interact()?
    {
        log::info!("bringing down interface (if up).");
        wg::down(interface, network.backend).ok();
        let config = InterfaceConfig::get_path(interface);
        let data = DataStore::get_path(interface);
        std::fs::remove_file(&config)
            .with_path(&config)
            .map_err(|e| log::warn!("{}", e.to_string().yellow()))
            .ok();
        std::fs::remove_file(&data)
            .with_path(&data)
            .map_err(|e| log::warn!("{}", e.to_string().yellow()))
            .ok();
        log::info!(
            "network {} is uninstalled.",
            interface.as_str_lossy().yellow()
        );
    }
    Ok(())
}

fn add_cidr(interface: &InterfaceName, opts: AddCidrOpts) -> Result<(), Error> {
    let InterfaceConfig { server, .. } = InterfaceConfig::from_interface(interface)?;
    log::info!("Fetching CIDRs");
    let api = Api::new(&server);
    let cidrs: Vec<Cidr> = api.http("GET", "/admin/cidrs")?;

    if let Some(cidr_request) = prompts::add_cidr(&cidrs, &opts)? {
        log::info!("Creating CIDR...");
        let cidr: Cidr = api.http_form("POST", "/admin/cidrs", cidr_request)?;

        eprintdoc!(
            "
            CIDR \"{cidr_name}\" added.

            Right now, peers within {cidr_name} can only see peers in the same CIDR
            , and in the special \"infra\" CIDR that includes the innernet server peer.

            You'll need to add more associations for peers in diffent CIDRs to communicate.
            ",
            cidr_name = cidr.name.bold()
        );
    } else {
        log::info!("exited without creating CIDR.");
    }

    Ok(())
}

fn delete_cidr(interface: &InterfaceName, opts: DeleteCidrOpts) -> Result<(), Error> {
    let InterfaceConfig { server, .. } = InterfaceConfig::from_interface(interface)?;
    println!("Fetching eligible CIDRs");
    let api = Api::new(&server);
    let cidrs: Vec<Cidr> = api.http("GET", "/admin/cidrs")?;
    let peers: Vec<Peer> = api.http("GET", "/admin/peers")?;

    let cidr_id = prompts::delete_cidr(&cidrs, &peers, &opts)?;

    println!("Deleting CIDR...");
    let _ = api.http("DELETE", &*format!("/admin/cidrs/{}", cidr_id))?;

    println!("CIDR deleted.");

    Ok(())
}

fn list_cidrs(interface: &InterfaceName, tree: bool) -> Result<(), Error> {
    let data_store = DataStore::open(interface)?;
    if tree {
        let cidr_tree = CidrTree::new(data_store.cidrs());
        colored::control::set_override(false);
        print_tree(&cidr_tree, &[], 0);
        colored::control::unset_override();
    } else {
        for cidr in data_store.cidrs() {
            println!("{} {}", cidr.cidr, cidr.name);
        }
    }
    Ok(())
}

fn add_peer(interface: &InterfaceName, opts: AddPeerOpts) -> Result<(), Error> {
    let InterfaceConfig { server, .. } = InterfaceConfig::from_interface(interface)?;
    let api = Api::new(&server);

    log::info!("Fetching CIDRs");
    let cidrs: Vec<Cidr> = api.http("GET", "/admin/cidrs")?;
    log::info!("Fetching peers");
    let peers: Vec<Peer> = api.http("GET", "/admin/peers")?;
    let cidr_tree = CidrTree::new(&cidrs[..]);

    if let Some(result) = prompts::add_peer(&peers, &cidr_tree, &opts)? {
        let (peer_request, keypair, target_path, mut target_file) = result;
        log::info!("Creating peer...");
        let peer: Peer = api.http_form("POST", "/admin/peers", peer_request)?;
        let server_peer = peers.iter().find(|p| p.id == 1).unwrap();
        prompts::write_peer_invitation(
            (&mut target_file, &target_path),
            interface,
            &peer,
            server_peer,
            &cidr_tree,
            keypair,
            &server.internal_endpoint,
        )?;
    } else {
        log::info!("Exited without creating peer.");
    }

    Ok(())
}

fn rename_peer(interface: &InterfaceName, opts: RenamePeerOpts) -> Result<(), Error> {
    let InterfaceConfig { server, .. } = InterfaceConfig::from_interface(interface)?;
    let api = Api::new(&server);

    log::info!("Fetching peers");
    let peers: Vec<Peer> = api.http("GET", "/admin/peers")?;

    if let Some((peer_request, old_name)) = prompts::rename_peer(&peers, &opts)? {
        log::info!("Renaming peer...");

        let id = peers
            .iter()
            .filter(|p| p.name == old_name)
            .map(|p| p.id)
            .next()
            .ok_or_else(|| anyhow!("Peer not found."))?;

        let _ = api.http_form("PUT", &format!("/admin/peers/{}", id), peer_request)?;
        log::info!("Peer renamed.");
    } else {
        log::info!("exited without renaming peer.");
    }

    Ok(())
}

fn enable_or_disable_peer(interface: &InterfaceName, enable: bool) -> Result<(), Error> {
    let InterfaceConfig { server, .. } = InterfaceConfig::from_interface(interface)?;
    let api = Api::new(&server);

    log::info!("Fetching peers.");
    let peers: Vec<Peer> = api.http("GET", "/admin/peers")?;

    if let Some(peer) = prompts::enable_or_disable_peer(&peers[..], enable)? {
        let Peer { id, mut contents } = peer;
        contents.is_disabled = !enable;
        api.http_form("PUT", &format!("/admin/peers/{}", id), contents)?;
    } else {
        log::info!("exiting without disabling peer.");
    }

    Ok(())
}

fn add_association(interface: &InterfaceName, opts: AddAssociationOpts) -> Result<(), Error> {
    let InterfaceConfig { server, .. } = InterfaceConfig::from_interface(interface)?;
    let api = Api::new(&server);

    log::info!("Fetching CIDRs");
    let cidrs: Vec<Cidr> = api.http("GET", "/admin/cidrs")?;

    let association = if let (Some(ref cidr1), Some(ref cidr2)) = (opts.cidr1, opts.cidr2) {
        let cidr1 = cidrs
            .iter()
            .find(|c| &c.name == cidr1)
            .ok_or_else(|| anyhow!("can't find cidr '{}'", cidr1))?;
        let cidr2 = cidrs
            .iter()
            .find(|c| &c.name == cidr2)
            .ok_or_else(|| anyhow!("can't find cidr '{}'", cidr2))?;
        (cidr1, cidr2)
    } else if let Some((cidr1, cidr2)) = prompts::add_association(&cidrs[..])? {
        (cidr1, cidr2)
    } else {
        log::info!("exiting without adding association.");
        return Ok(());
    };

    api.http_form(
        "POST",
        "/admin/associations",
        AssociationContents {
            cidr_id_1: association.0.id,
            cidr_id_2: association.1.id,
        },
    )?;

    Ok(())
}

fn delete_association(interface: &InterfaceName) -> Result<(), Error> {
    let InterfaceConfig { server, .. } = InterfaceConfig::from_interface(interface)?;
    let api = Api::new(&server);

    log::info!("Fetching CIDRs");
    let cidrs: Vec<Cidr> = api.http("GET", "/admin/cidrs")?;
    log::info!("Fetching associations");
    let associations: Vec<Association> = api.http("GET", "/admin/associations")?;

    if let Some(association) = prompts::delete_association(&associations[..], &cidrs[..])? {
        api.http("DELETE", &format!("/admin/associations/{}", association.id))?;
    } else {
        log::info!("exiting without adding association.");
    }

    Ok(())
}

fn list_associations(interface: &InterfaceName) -> Result<(), Error> {
    let InterfaceConfig { server, .. } = InterfaceConfig::from_interface(interface)?;
    let api = Api::new(&server);

    log::info!("Fetching CIDRs");
    let cidrs: Vec<Cidr> = api.http("GET", "/admin/cidrs")?;
    log::info!("Fetching associations");
    let associations: Vec<Association> = api.http("GET", "/admin/associations")?;

    for association in associations {
        println!(
            "{}: {} <=> {}",
            association.id,
            &cidrs
                .iter()
                .find(|c| c.id == association.cidr_id_1)
                .unwrap()
                .name
                .yellow(),
            &cidrs
                .iter()
                .find(|c| c.id == association.cidr_id_2)
                .unwrap()
                .name
                .yellow()
        );
    }

    Ok(())
}

fn set_listen_port(
    interface: &InterfaceName,
    unset: bool,
    network: NetworkOpt,
) -> Result<(), Error> {
    let mut config = InterfaceConfig::from_interface(interface)?;

    if let Some(listen_port) = prompts::set_listen_port(&config.interface, unset)? {
        wg::set_listen_port(interface, listen_port, network.backend)?;
        log::info!("the interface is updated");

        config.interface.listen_port = listen_port;
        config.write_to_interface(interface)?;
        log::info!("the config file is updated");
    } else {
        log::info!("exiting without updating the listen port.");
    }

    Ok(())
}

fn override_endpoint(
    interface: &InterfaceName,
    unset: bool,
    network: NetworkOpt,
) -> Result<(), Error> {
    let config = InterfaceConfig::from_interface(interface)?;
    if !unset && config.interface.listen_port.is_none() {
        println!(
            "{}: you need to set a listen port for your interface first.",
            "note".bold().yellow()
        );
        set_listen_port(interface, unset, network)?;
    }

    if let Some(endpoint) = prompts::override_endpoint(unset)? {
        log::info!("Updating endpoint.");
        Api::new(&config.server).http_form(
            "PUT",
            "/user/endpoint",
            EndpointContents::from(endpoint),
        )?;
    } else {
        log::info!("exiting without overriding endpoint.");
    }

    Ok(())
}

fn show(
    short: bool,
    tree: bool,
    interface: Option<Interface>,
    network: NetworkOpt,
) -> Result<(), Error> {
    let interfaces = interface.map_or_else(
        || Device::list(network.backend),
        |interface| Ok(vec![*interface]),
    )?;

    let devices = interfaces
        .into_iter()
        .filter_map(|name| {
            match DataStore::open(&name) {
                Ok(store) => {
                    let device = Device::get(&name, network.backend).with_str(name.as_str_lossy());
                    Some(device.map(|device| (device, store)))
                },
                // Skip WireGuard interfaces that aren't managed by innernet.
                Err(e) if e.kind() == io::ErrorKind::NotFound => None,
                // Error on interfaces that *are* managed by innernet but are not readable.
                Err(e) => Some(Err(e)),
            }
        })
        .collect::<Result<Vec<_>, _>>()?;

    if devices.is_empty() {
        log::info!("No innernet networks currently running.");
        return Ok(());
    }

    for (device_info, store) in devices {
        let peers = store.peers();
        let cidrs = store.cidrs();
        let me = peers
            .iter()
            .find(|p| p.public_key == device_info.public_key.as_ref().unwrap().to_base64())
            .ok_or_else(|| anyhow!("missing peer info"))?;

        let mut peer_states = device_info
            .peers
            .iter()
            .map(|info| {
                let public_key = info.config.public_key.to_base64();
                match peers.iter().find(|p| p.public_key == public_key) {
                    Some(peer) => Ok(PeerState {
                        peer,
                        info: Some(info),
                    }),
                    None => Err(anyhow!("peer {} isn't an innernet peer.", public_key)),
                }
            })
            .collect::<Result<Vec<PeerState>, _>>()?;
        peer_states.push(PeerState {
            peer: me,
            info: None,
        });

        print_interface(&device_info, short || tree)?;
        peer_states.sort_by_key(|peer| peer.peer.ip);

        if tree {
            let cidr_tree = CidrTree::new(cidrs);
            print_tree(&cidr_tree, &peer_states, 1);
        } else {
            for peer_state in peer_states {
                print_peer(&peer_state, short, 1);
            }
        }
    }
    Ok(())
}

fn print_tree(cidr: &CidrTree, peers: &[PeerState], level: usize) {
    println_pad!(
        level * 2,
        "{} {}",
        cidr.cidr.to_string().bold().blue(),
        cidr.name.blue(),
    );

    let mut children: Vec<_> = cidr.children().collect();
    children.sort();
    children
        .iter()
        .for_each(|child| print_tree(child, peers, level + 1));

    for peer in peers.iter().filter(|p| p.peer.cidr_id == cidr.id) {
        print_peer(peer, true, level);
    }
}

fn print_interface(device_info: &Device, short: bool) -> Result<(), Error> {
    if short {
        let listen_port_str = device_info
            .listen_port
            .map(|p| format!("(:{}) ", p))
            .unwrap_or_default();
        println!(
            "{} {}",
            device_info.name.to_string().green().bold(),
            listen_port_str.dimmed(),
        );
    } else {
        println!(
            "{}: {}",
            "network".green().bold(),
            device_info.name.to_string().green(),
        );
        if let Some(listen_port) = device_info.listen_port {
            println!("  {}: {}", "listening port".bold(), listen_port);
        }
    }
    Ok(())
}

fn print_peer(peer: &PeerState, short: bool, level: usize) {
    let pad = level * 2;
    let PeerState { peer, info } = peer;
    if short {
        let last_handshake = info
            .and_then(|i| i.stats.last_handshake_time)
            .and_then(|t| t.elapsed().ok())
            .unwrap_or_else(|| SystemTime::UNIX_EPOCH.elapsed().unwrap());

        let online = last_handshake <= Duration::from_secs(180) || info.is_none();

        println_pad!(
            pad,
            "| {} {}: {} ({}{}…)",
            if online { "◉".bold() } else { "◯".dimmed() },
            peer.ip.to_string().yellow().bold(),
            peer.name.yellow(),
            if info.is_none() { "you, " } else { "" },
            &peer.public_key[..6].dimmed(),
        );
    } else {
        println_pad!(
            pad,
            "{}: {} ({}...)",
            "peer".yellow().bold(),
            peer.name.yellow(),
            &peer.public_key[..10].yellow(),
        );
        println_pad!(pad, "  {}: {}", "ip".bold(), peer.ip);
        if let Some(ref endpoint) = peer.endpoint {
            println_pad!(pad, "  {}: {}", "endpoint".bold(), endpoint);
        }
        if let Some(info) = info {
            if let Some(last_handshake) = info.stats.last_handshake_time {
                let duration = last_handshake.elapsed().expect("horrible clock problem");
                println_pad!(
                    pad,
                    "  {}: {}",
                    "last handshake".bold(),
                    human_duration(duration),
                );
            }
            if info.stats.tx_bytes > 0 || info.stats.rx_bytes > 0 {
                println_pad!(
                    pad,
                    "  {}: {} received, {} sent",
                    "transfer".bold(),
                    human_size(info.stats.rx_bytes),
                    human_size(info.stats.tx_bytes),
                );
            }
        }
    }
}

fn main() {
    let opt = Opts::from_args();
    util::init_logger(opt.verbose);

    if let Err(e) = run(opt) {
        println!();
        log::error!("{}\n", e);
        if let Some(e) = e.downcast_ref::<WrappedIoError>() {
            util::permissions_helptext(e);
        }
        if let Some(e) = e.downcast_ref::<io::Error>() {
            util::permissions_helptext(e);
        }
        std::process::exit(1);
    }
}

fn run(opt: Opts) -> Result<(), Error> {
    let command = opt.command.unwrap_or(Command::Show {
        short: false,
        tree: false,
        interface: None,
    });

    match command {
        Command::Install {
            invite,
            hosts,
            opts,
        } => install(&invite, hosts.into(), opts, opt.network)?,
        Command::Show {
            short,
            tree,
            interface,
        } => show(short, tree, interface, opt.network)?,
        Command::Fetch { interface, hosts } => fetch(&interface, false, hosts.into(), opt.network)?,
        Command::Up {
            interface,
            daemon,
            hosts,
            interval,
        } => up(
            &interface,
            daemon.then(|| Duration::from_secs(interval)),
            hosts.into(),
            opt.network,
        )?,
        Command::Down { interface } => wg::down(&interface, opt.network.backend)?,
        Command::Uninstall { interface } => uninstall(&interface, opt.network)?,
        Command::AddPeer { interface, opts } => add_peer(&interface, opts)?,
        Command::RenamePeer { interface, opts } => rename_peer(&interface, opts)?,
        Command::AddCidr { interface, opts } => add_cidr(&interface, opts)?,
        Command::DeleteCidr { interface, opts } => delete_cidr(&interface, opts)?,
        Command::ListCidrs { interface, tree } => list_cidrs(&interface, tree)?,
        Command::DisablePeer { interface } => enable_or_disable_peer(&interface, false)?,
        Command::EnablePeer { interface } => enable_or_disable_peer(&interface, true)?,
        Command::AddAssociation { interface, opts } => add_association(&interface, opts)?,
        Command::DeleteAssociation { interface } => delete_association(&interface)?,
        Command::ListAssociations { interface } => list_associations(&interface)?,
        Command::SetListenPort { interface, unset } => {
            set_listen_port(&interface, unset, opt.network)?
        },
        Command::OverrideEndpoint { interface, unset } => {
            override_endpoint(&interface, unset, opt.network)?
        },
        Command::Completions { shell } => {
            Opts::clap().gen_completions_to("innernet", shell, &mut std::io::stdout());
            std::process::exit(0);
        },
    }

    Ok(())
}
