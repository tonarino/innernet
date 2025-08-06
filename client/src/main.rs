use anyhow::{anyhow, bail};
use clap::{ArgAction, Args, Parser, Subcommand};
use colored::*;
use dialoguer::{Confirm, Input};
use hostsfile::HostsBuilder;
use indoc::eprintdoc;
use shared::{
    get_local_addrs,
    interface_config::InterfaceConfig,
    prompts,
    wg::{DeviceExt, PeerInfoExt},
    AddCidrOpts, AddDeleteAssociationOpts, AddPeerOpts, Association, AssociationContents, Cidr,
    CidrTree, DeleteCidrOpts, EnableDisablePeerOpts, Endpoint, EndpointContents, Info, InstallOpts,
    Interface, IoErrorContext, ListenPortOpts, NatOpts, NetworkOpts, OverrideEndpointOpts, Peer,
    RedeemContents, RenameCidrOpts, RenamePeerOpts, State, WrappedIoError, REDEEM_TRANSITION_WAIT,
};
use std::{
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};
use wireguard_control::{Device, DeviceUpdate, InterfaceName, PeerConfigBuilder, PeerInfo};

mod data_store;
mod nat;
mod util;

use data_store::DataStore;
use nat::NatTraverse;
use shared::{wg, Error};
use util::{human_duration, human_size, Api};

use crate::util::all_installed;
use semver::Version;

const VERSION: &str = env!("CARGO_PKG_VERSION");

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

pub enum ApparentServerInfo {
    Present(Info),
    Missing,
}

impl ApparentServerInfo {
    fn supports_unspecified_ip_resolution(&self) -> bool {
        matches!(self, ApparentServerInfo::Present(_))
    }
}

#[derive(Clone, Debug, Parser)]
#[command(name = "innernet", author, version, about)]
struct Opts {
    #[clap(subcommand)]
    command: Option<Command>,

    /// Verbose output, use -vv for even higher verbositude
    #[clap(short, long, action = ArgAction::Count)]
    verbose: u8,

    #[clap(short, long, default_value = "/etc/innernet")]
    config_dir: PathBuf,

    #[cfg_attr(
        not(target_os = "openbsd"),
        clap(short, long, default_value = "/var/lib/innernet")
    )]
    #[cfg_attr(
        target_os = "openbsd",
        clap(short, long, default_value = "/var/db/innernet")
    )]
    data_dir: PathBuf,

    #[clap(flatten)]
    network: NetworkOpts,
}

#[derive(Clone, Debug, Args)]
struct HostsOpt {
    /// The path to write hosts to
    #[clap(long = "hosts-path", default_value = "/etc/hosts")]
    hosts_path: PathBuf,

    /// Don't write to any hosts files
    #[clap(long = "no-write-hosts", conflicts_with = "hosts_path")]
    no_write_hosts: bool,
}

impl From<HostsOpt> for Option<PathBuf> {
    fn from(opt: HostsOpt) -> Self {
        (!opt.no_write_hosts).then_some(opt.hosts_path)
    }
}

#[derive(Clone, Debug, Subcommand)]
enum Command {
    /// Install a new innernet config
    #[clap(alias = "redeem")]
    Install {
        /// Path to the invitation file
        invite: PathBuf,

        #[clap(flatten)]
        hosts: HostsOpt,

        #[clap(flatten)]
        install_opts: InstallOpts,

        #[clap(flatten)]
        nat: NatOpts,
    },

    /// Enumerate all innernet connections
    #[clap(alias = "list")]
    Show {
        /// One-line peer list
        #[clap(short, long)]
        short: bool,

        /// Display peers in a tree based on the CIDRs
        #[clap(short, long)]
        tree: bool,

        interface: Option<Interface>,
    },

    /// Bring up your local interface, and update it with latest peer list
    Up {
        /// Enable daemon mode i.e. keep the process running, while fetching
        /// the latest peer list periodically
        #[clap(short, long)]
        daemon: bool,

        /// Keep fetching the latest peer list at the specified interval in
        /// seconds. Valid only in daemon mode
        #[clap(long, default_value = "60")]
        interval: u64,

        #[clap(flatten)]
        hosts: HostsOpt,

        #[clap(flatten)]
        nat: NatOpts,

        interface: Option<Interface>,
    },

    /// Fetch and update your local interface with the latest peer list
    Fetch {
        interface: Interface,

        #[clap(flatten)]
        hosts: HostsOpt,

        #[clap(flatten)]
        nat: NatOpts,
    },

    /// Uninstall an innernet network.
    Uninstall {
        interface: Interface,

        /// Bypass confirmation
        #[clap(long)]
        yes: bool,
    },

    /// Bring down the interface (equivalent to 'wg-quick down <interface>')
    Down { interface: Interface },

    /// Add a new peer
    ///
    /// By default, you'll be prompted interactively to create a peer, but you can
    /// also specify all the options in the command, eg:
    ///
    /// --name 'person' --cidr 'humans' --admin false --auto-ip --save-config 'person.toml' --yes
    AddPeer {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: AddPeerOpts,
    },

    /// Rename a peer
    ///
    /// By default, you'll be prompted interactively to select a peer, but you can
    /// also specify all the options in the command, eg:
    ///
    /// --name 'person' --new-name 'human'
    RenamePeer {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: RenamePeerOpts,
    },

    /// Add a new CIDR
    AddCidr {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: AddCidrOpts,
    },

    /// Rename a CIDR
    ///
    /// By default, you'll be prompted interactively to select a CIDR, but you can
    /// also specify all the options in the command, eg:
    ///
    /// --name 'group' --new-name 'family'
    RenameCidr {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: RenameCidrOpts,
    },

    /// Delete a CIDR
    DeleteCidr {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: DeleteCidrOpts,
    },

    /// List CIDRs
    ListCidrs {
        interface: Interface,

        /// Display CIDRs in tree format
        #[clap(short, long)]
        tree: bool,
    },

    /// Disable an enabled peer
    DisablePeer {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: EnableDisablePeerOpts,
    },

    /// Enable a disabled peer
    EnablePeer {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: EnableDisablePeerOpts,
    },

    /// Add an association between CIDRs
    AddAssociation {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: AddDeleteAssociationOpts,
    },

    /// Delete an association between CIDRs
    DeleteAssociation {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: AddDeleteAssociationOpts,
    },

    /// List existing assocations between CIDRs
    ListAssociations { interface: Interface },

    /// Set the local listen port.
    SetListenPort {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: ListenPortOpts,
    },

    /// Override your external endpoint that the server sends to other peers
    OverrideEndpoint {
        interface: Interface,

        #[clap(flatten)]
        sub_opts: OverrideEndpointOpts,
    },

    /// Generate shell completion scripts
    Completions {
        #[clap(value_enum)]
        shell: clap_complete::Shell,
    },
}

fn update_hosts_file(
    interface: &InterfaceName,
    hosts_path: PathBuf,
    peers: &[Peer],
) -> Result<(), WrappedIoError> {
    let mut hosts_builder = HostsBuilder::new(format!("innernet {interface}"));
    for peer in peers {
        hosts_builder.add_hostname(
            peer.contents.ip,
            format!("{}.{}.wg", peer.contents.name, interface),
        );
    }
    match hosts_builder.write_to(&hosts_path).with_path(&hosts_path) {
        Ok(has_written) if has_written => {
            log::info!(
                "updated {} with the latest peers.",
                hosts_path.to_string_lossy().yellow()
            )
        },
        Ok(_) => {},
        Err(e) => log::warn!("failed to update hosts ({})", e),
    };

    Ok(())
}

fn install(
    opts: &Opts,
    invite: &Path,
    hosts_file: Option<PathBuf>,
    install_opts: InstallOpts,
    nat: &NatOpts,
) -> Result<(), Error> {
    shared::ensure_dirs_exist(&[&opts.config_dir])?;
    let config = InterfaceConfig::from_file(invite)?;

    let iface = if install_opts.default_name {
        config.interface.network_name.clone()
    } else if let Some(ref iface) = install_opts.name {
        iface.clone()
    } else {
        Input::with_theme(&*prompts::THEME)
            .with_prompt("Interface name")
            .default(config.interface.network_name.clone())
            .interact()?
    };

    let target_conf = opts.config_dir.join(&iface).with_extension("conf");
    if target_conf.exists() {
        bail!(
            "An existing innernet network with the name \"{}\" already exists.",
            iface
        );
    }
    let iface = iface.parse()?;
    if Device::list(opts.network.backend)
        .iter()
        .flatten()
        .any(|name| name == &iface)
    {
        bail!(
            "An existing WireGuard interface with the name \"{}\" already exists.",
            iface
        );
    }

    redeem_invite(&iface, config, target_conf, opts.network).map_err(|e| {
        log::error!("failed to start the interface: {}.", e);
        log::info!("bringing down the interface.");
        if let Err(e) = wg::down(&iface, opts.network.backend) {
            log::warn!("failed to bring down interface: {}.", e.to_string());
        };
        log::error!("Failed to redeem invite. Now's a good time to make sure the server is started and accessible!");
        e
    })?;

    let mut fetch_success = false;
    for _ in 0..3 {
        if fetch(&iface, opts, true, hosts_file.clone(), nat).is_ok() {
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

    if install_opts.delete_invite
        || Confirm::with_theme(&*prompts::THEME)
            .wait_for_newline(true)
            .with_prompt(format!(
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

            By default, innernet will write to your /etc/hosts file for peer name
            resolution. To disable this behavior, use the --no-write-hosts or --write-hosts [PATH]
            options.

            See the manpage or innernet GitHub repo for more detailed instruction on managing your
            interface and network. Have fun!

    ",
        star = "[*]".dimmed(),
        interface = iface.to_string().yellow(),
        installed = "installed".green(),
    );
    if cfg!(target_os = "linux") {
        eprintdoc!(
            "
                It's recommended to now keep the interface automatically refreshing via systemd:

                    {systemctl_enable}{interface}
        ",
            interface = iface.to_string().yellow(),
            systemctl_enable = "systemctl enable --now innernet@".yellow(),
        );
    } else if cfg!(target_os = "macos") {
        eprintdoc!("
            It's recommended to now keep the interface automatically refreshing, which you can
            do via a launchd script (easier macOS helpers to be added to innernet in a later version).

            Ex. to run innernet in a 60s update loop:

                {daemon_mode} {interface}
        ",
            interface = iface.to_string().yellow(),
            daemon_mode = "innernet up -d --interval 60".yellow());
    } else {
        eprintdoc!(
            "
            It's recommended to now keep the interface automatically refreshing via whatever service
            system your distribution provides.

            Ex. to run innernet in a 60s update loop:

                {daemon_mode} {interface}
        ",
            interface = iface.to_string().yellow(),
            daemon_mode = "innernet up -d --interval 60".yellow()
        );
    }
    Ok(())
}

fn redeem_invite(
    iface: &InterfaceName,
    mut config: InterfaceConfig,
    target_conf: PathBuf,
    network: NetworkOpts,
) -> Result<(), Error> {
    log::info!("bringing up interface {}.", iface.as_str_lossy().yellow());
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
    let keypair = wireguard_control::KeyPair::generate();

    log::info!(
        "Registering keypair with server (at {}).",
        &config.server.internal_endpoint
    );
    Api::new(&config.server).http_form::<_, ()>(
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

    log::info!("Changing keys and waiting 5s for server's WireGuard interface to transition.",);
    DeviceUpdate::new()
        .set_private_key(keypair.private)
        .apply(iface, network.backend)
        .with_str(iface.to_string())?;
    thread::sleep(REDEEM_TRANSITION_WAIT);

    Ok(())
}

fn up(
    interface: Option<Interface>,
    opts: &Opts,
    loop_interval: Option<Duration>,
    hosts_path: Option<PathBuf>,
    nat: &NatOpts,
) -> Result<(), Error> {
    loop {
        let interfaces = match &interface {
            Some(iface) => vec![iface.clone()],
            None => all_installed(&opts.config_dir)?,
        };

        for iface in interfaces {
            fetch(&iface, opts, true, hosts_path.clone(), nat)?;
        }

        match loop_interval {
            Some(interval) => thread::sleep(interval),
            None => break,
        }
    }

    Ok(())
}

fn fetch(
    interface: &InterfaceName,
    opts: &Opts,
    bring_up_interface: bool,
    hosts_path: Option<PathBuf>,
    nat: &NatOpts,
) -> Result<(), Error> {
    let config = InterfaceConfig::from_interface(&opts.config_dir, interface)?;
    let interface_up = match Device::list(opts.network.backend) {
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
            opts.network,
        )
        .with_str(interface.to_string())?;
    }

    log::info!(
        "fetching state for {} from server...",
        interface.as_str_lossy().yellow()
    );
    let mut store = DataStore::open_or_create(&opts.data_dir, interface)?;
    let api = Api::new(&config.server);
    let State { peers, cidrs } = api.http("GET", "/user/state")?;

    let device = Device::get(interface, opts.network.backend)?;
    let modifications = device.diff(&peers);

    let updates = modifications
        .iter()
        .inspect(|diff| util::print_peer_diff(&store, diff))
        .cloned()
        .map(PeerConfigBuilder::from)
        .collect::<Vec<_>>();

    if !updates.is_empty() || !interface_up {
        DeviceUpdate::new()
            .add_peers(&updates)
            .apply(interface, opts.network.backend)
            .with_str(interface.to_string())?;

        if let Some(path) = hosts_path {
            update_hosts_file(interface, path, &peers)?;
        }

        println!();
        log::info!("updated interface {}\n", interface.as_str_lossy().yellow());
    } else {
        log::info!("{}", "peers are already up to date".green());
    }
    let interface_updated_time = Instant::now();

    store.set_cidrs(cidrs);
    store.update_peers(&peers)?;
    store.write().with_str(interface.to_string())?;

    let candidates: Vec<Endpoint> = get_local_addrs()?
        .filter(|ip| !nat.is_excluded(*ip))
        .map(|addr| SocketAddr::from((addr, device.listen_port.unwrap_or(51820))).into())
        .collect::<Vec<Endpoint>>();
    log::info!(
        "reporting {} interface address{} as NAT traversal candidates",
        candidates.len(),
        if candidates.len() == 1 { "" } else { "es" },
    );
    for candidate in &candidates {
        log::debug!("  candidate: {}", candidate);
    }
    match api.http_form::<_, ()>("PUT", "/user/candidates", &candidates) {
        Err(ureq::Error::Status(404, _)) => {
            log::warn!("your network is using an old version of innernet-server that doesn't support NAT traversal candidate reporting.")
        },
        Err(e) => return Err(e.into()),
        _ => {},
    }
    log::debug!("candidates successfully reported");

    if nat.no_nat_traversal {
        log::debug!("NAT traversal explicitly disabled, not attempting.");
    } else {
        let mut nat_traverse = NatTraverse::new(interface, opts.network.backend, &modifications)?;

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

fn uninstall(interface: &InterfaceName, opts: &Opts, yes: bool) -> Result<(), Error> {
    let config = InterfaceConfig::get_path(&opts.config_dir, interface);
    let data = DataStore::get_path(&opts.data_dir, interface);

    if !config.exists() && !data.exists() {
        bail!(
            "No network named \"{}\" exists.",
            interface.as_str_lossy().yellow()
        );
    }

    if yes
        || Confirm::with_theme(&*prompts::THEME)
            .with_prompt(format!(
                "Permanently delete network \"{}\"?",
                interface.as_str_lossy().yellow()
            ))
            .default(false)
            .wait_for_newline(true)
            .interact()?
    {
        log::info!("bringing down interface (if up).");
        wg::down(interface, opts.network.backend).ok();
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

fn add_cidr(interface: &InterfaceName, opts: &Opts, sub_opts: AddCidrOpts) -> Result<(), Error> {
    let InterfaceConfig { server, .. } =
        InterfaceConfig::from_interface(&opts.config_dir, interface)?;
    log::info!("Fetching CIDRs");
    let api = Api::new(&server);
    let cidrs: Vec<Cidr> = api.http("GET", "/admin/cidrs")?;

    if let Some(cidr_request) = prompts::add_cidr(&cidrs, &sub_opts)? {
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

fn rename_cidr(
    interface: &InterfaceName,
    opts: &Opts,
    sub_opts: RenameCidrOpts,
) -> Result<(), Error> {
    let InterfaceConfig { server, .. } =
        InterfaceConfig::from_interface(&opts.config_dir, interface)?;
    let api = Api::new(&server);

    log::info!("Fetching CIDRs");
    let cidrs: Vec<Cidr> = api.http("GET", "/admin/cidrs")?;

    if let Some((cidr_request, old_name)) = prompts::rename_cidr(&cidrs, &sub_opts)? {
        log::info!("Renaming CIDR...");

        let id = cidrs
            .iter()
            .find(|c| c.name == old_name)
            .ok_or_else(|| anyhow!("CIDR not found."))?
            .id;

        api.http_form::<_, ()>("PUT", &format!("/admin/cidrs/{id}"), cidr_request)?;
        log::info!("CIDR renamed.");
    } else {
        log::info!("Exited without renaming CIDR.");
    }

    Ok(())
}

fn delete_cidr(
    interface: &InterfaceName,
    opts: &Opts,
    sub_opts: DeleteCidrOpts,
) -> Result<(), Error> {
    let InterfaceConfig { server, .. } =
        InterfaceConfig::from_interface(&opts.config_dir, interface)?;
    println!("Fetching eligible CIDRs");
    let api = Api::new(&server);
    let cidrs: Vec<Cidr> = api.http("GET", "/admin/cidrs")?;
    let peers: Vec<Peer> = api.http("GET", "/admin/peers")?;

    let cidr_id = prompts::delete_cidr(&cidrs, &peers, &sub_opts)?;

    println!("Deleting CIDR...");
    api.http::<()>("DELETE", &format!("/admin/cidrs/{cidr_id}"))?;

    println!("CIDR deleted.");

    Ok(())
}

fn list_cidrs(interface: &InterfaceName, opts: &Opts, tree: bool) -> Result<(), Error> {
    let data_store = DataStore::open(&opts.data_dir, interface)?;
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

fn add_peer(interface: &InterfaceName, opts: &Opts, sub_opts: AddPeerOpts) -> Result<(), Error> {
    let InterfaceConfig { server, .. } =
        InterfaceConfig::from_interface(&opts.config_dir, interface)?;
    let api = Api::new(&server);

    log::info!("Fetching CIDRs");
    let cidrs: Vec<Cidr> = api.http("GET", "/admin/cidrs")?;
    log::info!("Fetching peers");
    let peers: Vec<Peer> = api.http("GET", "/admin/peers")?;
    let cidr_tree = CidrTree::new(&cidrs[..]);

    if let Some(result) = prompts::add_peer(&peers, &cidr_tree, &sub_opts)? {
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

fn rename_peer(
    interface: &InterfaceName,
    opts: &Opts,
    sub_opts: RenamePeerOpts,
) -> Result<(), Error> {
    let InterfaceConfig { server, .. } =
        InterfaceConfig::from_interface(&opts.config_dir, interface)?;
    let api = Api::new(&server);

    log::info!("Fetching peers");
    let peers: Vec<Peer> = api.http("GET", "/admin/peers")?;

    if let Some((peer_request, old_name)) = prompts::rename_peer(&peers, &sub_opts)? {
        log::info!("Renaming peer...");

        let id = peers
            .iter()
            .filter(|p| p.name == old_name)
            .map(|p| p.id)
            .next()
            .ok_or_else(|| anyhow!("Peer not found."))?;

        api.http_form::<_, ()>("PUT", &format!("/admin/peers/{id}"), peer_request)?;
        log::info!("Peer renamed.");
    } else {
        log::info!("exited without renaming peer.");
    }

    Ok(())
}

fn enable_or_disable_peer(
    interface: &InterfaceName,
    opts: &Opts,
    sub_opts: EnableDisablePeerOpts,
    enable: bool,
) -> Result<(), Error> {
    let InterfaceConfig { server, .. } =
        InterfaceConfig::from_interface(&opts.config_dir, interface)?;
    let api = Api::new(&server);

    log::info!("Fetching peers.");
    let peers: Vec<Peer> = api.http("GET", "/admin/peers")?;

    if let Some(peer) = prompts::enable_or_disable_peer(&peers[..], &sub_opts, enable)? {
        let Peer { id, mut contents } = peer;
        contents.is_disabled = !enable;
        api.http_form::<_, ()>("PUT", &format!("/admin/peers/{id}"), contents)?;
    } else {
        log::info!("exiting without enabling or disabling peer.");
    }

    Ok(())
}

fn add_association(
    interface: &InterfaceName,
    opts: &Opts,
    sub_opts: AddDeleteAssociationOpts,
) -> Result<(), Error> {
    let InterfaceConfig { server, .. } =
        InterfaceConfig::from_interface(&opts.config_dir, interface)?;
    let api = Api::new(&server);

    log::info!("Fetching CIDRs");
    let cidrs: Vec<Cidr> = api.http("GET", "/admin/cidrs")?;

    let association = if let (Some(ref cidr1), Some(ref cidr2)) = (&sub_opts.cidr1, &sub_opts.cidr2)
    {
        let cidr1 = cidrs
            .iter()
            .find(|c| &c.name == cidr1)
            .ok_or_else(|| anyhow!("can't find cidr '{}'", cidr1))?;
        let cidr2 = cidrs
            .iter()
            .find(|c| &c.name == cidr2)
            .ok_or_else(|| anyhow!("can't find cidr '{}'", cidr2))?;
        (cidr1, cidr2)
    } else if let Some((cidr1, cidr2)) = prompts::add_association(&cidrs[..], &sub_opts)? {
        (cidr1, cidr2)
    } else {
        log::info!("exiting without adding association.");
        return Ok(());
    };

    api.http_form::<_, ()>(
        "POST",
        "/admin/associations",
        AssociationContents {
            cidr_id_1: association.0.id,
            cidr_id_2: association.1.id,
        },
    )?;

    Ok(())
}

fn delete_association(
    interface: &InterfaceName,
    opts: &Opts,
    sub_opts: AddDeleteAssociationOpts,
) -> Result<(), Error> {
    let InterfaceConfig { server, .. } =
        InterfaceConfig::from_interface(&opts.config_dir, interface)?;
    let api = Api::new(&server);

    log::info!("Fetching CIDRs");
    let cidrs: Vec<Cidr> = api.http("GET", "/admin/cidrs")?;
    log::info!("Fetching associations");
    let associations: Vec<Association> = api.http("GET", "/admin/associations")?;

    if let Some(association) =
        prompts::delete_association(&associations[..], &cidrs[..], &sub_opts)?
    {
        api.http::<()>("DELETE", &format!("/admin/associations/{}", association.id))?;
    } else {
        log::info!("exiting without adding association.");
    }

    Ok(())
}

fn list_associations(interface: &InterfaceName, opts: &Opts) -> Result<(), Error> {
    let InterfaceConfig { server, .. } =
        InterfaceConfig::from_interface(&opts.config_dir, interface)?;
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
    opts: &Opts,
    sub_opts: ListenPortOpts,
) -> Result<Option<u16>, Error> {
    let mut config = InterfaceConfig::from_interface(&opts.config_dir, interface)?;

    let listen_port = prompts::set_listen_port(&config.interface, sub_opts)?;
    if let Some(listen_port) = listen_port {
        wg::set_listen_port(interface, listen_port, opts.network.backend)?;
        log::info!("the interface is updated");

        config.interface.listen_port = listen_port;
        config.write_to_interface(&opts.config_dir, interface)?;
        log::info!("the config file is updated");
    } else {
        log::info!("exiting without updating the listen port.");
    }

    Ok(listen_port.flatten())
}

fn override_endpoint(
    interface: &InterfaceName,
    opts: &Opts,
    sub_opts: OverrideEndpointOpts,
) -> Result<(), Error> {
    let config = InterfaceConfig::from_interface(&opts.config_dir, interface)?;
    // TODO(mbernat): Refactor command handling so that we can gather the server info in `run()`.
    let info = get_server_info(&config)?;

    let endpoint_contents = if sub_opts.unset {
        prompt_unset_override_endpoint(&sub_opts)?.then_some(EndpointContents::Unset)
    } else {
        let port = match config.interface.listen_port {
            Some(port) => port,
            None => bail!("you need to set a listen port with set-listen-port before overriding the endpoint (otherwise port randomization on the interface would make it useless).")
        };
        let endpoint = prompt_override_endpoint(&info, &sub_opts, port)?;
        endpoint.map(EndpointContents::Set)
    };

    if let Some(contents) = endpoint_contents {
        log::info!("requesting endpoint update...");
        Api::new(&config.server).http_form::<_, ()>("PUT", "/user/endpoint", contents)?;
        log::info!(
            "endpoint override {}",
            if sub_opts.unset { "unset" } else { "set" }
        );
    } else {
        log::info!("exiting without overriding endpoint");
    }

    Ok(())
}

fn prompt_override_endpoint(
    info: &ApparentServerInfo,
    args: &OverrideEndpointOpts,
    listen_port: u16,
) -> Result<Option<Endpoint>, Error> {
    let endpoint = match &args.endpoint {
        Some(endpoint) => endpoint.clone(),
        None => {
            let external_ip = if info.supports_unspecified_ip_resolution() {
                prompts::unspecified_ip_and_auto_detection_flow()?
            } else {
                prompts::ip_auto_detection_flow()?
            };

            prompts::input_external_endpoint(external_ip, listen_port)?
        },
    };
    if args.yes || prompts::confirm(&format!("Set external endpoint to {endpoint}?"))? {
        Ok(Some(endpoint))
    } else {
        Ok(None)
    }
}

fn prompt_unset_override_endpoint(args: &OverrideEndpointOpts) -> Result<bool, Error> {
    Ok(args.yes
        || prompts::confirm("Unset external endpoint to enable automatic endpoint discovery?")?)
}

fn fetch_server_info(config: &InterfaceConfig) -> Result<ApparentServerInfo, Error> {
    let api = Api::new(&config.server);
    let maybe_info: Result<Info, ureq::Error> = api.http("GET", "/user/info");
    match maybe_info {
        Ok(info) => Ok(ApparentServerInfo::Present(info)),
        Err(ureq::Error::Status(404, _)) => Ok(ApparentServerInfo::Missing),
        Err(e) => {
            bail!(e)
        },
    }
}

fn get_server_info(config: &InterfaceConfig) -> Result<ApparentServerInfo, Error> {
    log::debug!("querying innernet server info");
    match fetch_server_info(config)? {
        ApparentServerInfo::Present(info) => {
            let server_version = &info.version;
            let client_version = &Version::parse(VERSION)?;

            if server_version < client_version {
                log::warn!(
                    "innernet server version {server_version} is older than the client version \
                    {VERSION}; the server might not support all the client features"
                )
            } else {
                log::debug!("innerner server version is {server_version}");
            }

            Ok(ApparentServerInfo::Present(info))
        },
        ApparentServerInfo::Missing => {
            log::warn!(
                "could not determine the innernet server version, assuming it is older than the \
                 client version {VERSION}; the server might not support all the client features"
            );
            Ok(ApparentServerInfo::Missing)
        },
    }
}

fn show(opts: &Opts, short: bool, tree: bool, interface: Option<Interface>) -> Result<(), Error> {
    let interfaces = interface.map_or_else(
        || Device::list(opts.network.backend),
        |interface| Ok(vec![*interface]),
    )?;

    let devices = interfaces
        .into_iter()
        .filter_map(|name| {
            match DataStore::open(&opts.data_dir, &name) {
                Ok(store) => {
                    let device =
                        Device::get(&name, opts.network.backend).with_str(name.as_str_lossy());
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
        let public_key = match &device_info.public_key {
            Some(key) => key.to_base64(),
            None => {
                log::warn!(
                    "network {} is missing public key.",
                    device_info.name.to_string().yellow()
                );
                continue;
            },
        };

        let peers = store.peers();
        let cidrs = store.cidrs();
        let me = peers
            .iter()
            .find(|p| p.public_key == public_key)
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
            .map(|p| format!("(:{p}) "))
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
        let connected = info
            .map(|info| info.is_recently_connected())
            .unwrap_or_default();

        let is_you = info.is_none();

        println_pad!(
            pad,
            "| {} {}: {} ({}{}…)",
            if connected || is_you {
                "◉".bold()
            } else {
                "◯".dimmed()
            },
            peer.ip.to_string().yellow().bold(),
            peer.name.yellow(),
            if is_you { "you, " } else { "" },
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
        if let Some(info) = info {
            if let Some(endpoint) = info.config.endpoint {
                println_pad!(pad, "  {}: {}", "endpoint".bold(), endpoint);
            }
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
    let opts = Opts::parse();
    util::init_logger(opts.verbose);

    if let Err(e) = run(&opts) {
        println!();
        log::error!("{}\n", e);
        if let Some(e) = e.downcast_ref::<WrappedIoError>() {
            util::permissions_helptext(&opts.config_dir, &opts.data_dir, e);
        }
        if let Some(e) = e.downcast_ref::<io::Error>() {
            util::permissions_helptext(&opts.config_dir, &opts.data_dir, e);
        }
        std::process::exit(1);
    }
}

fn run(opts: &Opts) -> Result<(), Error> {
    let command = opts.command.clone().unwrap_or(Command::Show {
        short: false,
        tree: false,
        interface: None,
    });

    match command {
        Command::Install {
            invite,
            hosts,
            install_opts,
            nat,
        } => install(opts, &invite, hosts.into(), install_opts, &nat)?,
        Command::Show {
            short,
            tree,
            interface,
        } => show(opts, short, tree, interface)?,
        Command::Fetch {
            interface,
            hosts,
            nat,
        } => fetch(&interface, opts, false, hosts.into(), &nat)?,
        Command::Up {
            interface,
            daemon,
            hosts,
            nat,
            interval,
        } => up(
            interface,
            opts,
            daemon.then(|| Duration::from_secs(interval)),
            hosts.into(),
            &nat,
        )?,
        Command::Down { interface } => wg::down(&interface, opts.network.backend)?,
        Command::Uninstall { interface, yes } => uninstall(&interface, opts, yes)?,
        Command::AddPeer {
            interface,
            sub_opts,
        } => add_peer(&interface, opts, sub_opts)?,
        Command::RenamePeer {
            interface,
            sub_opts,
        } => rename_peer(&interface, opts, sub_opts)?,
        Command::AddCidr {
            interface,
            sub_opts,
        } => add_cidr(&interface, opts, sub_opts)?,
        Command::RenameCidr {
            interface,
            sub_opts,
        } => rename_cidr(&interface, opts, sub_opts)?,
        Command::DeleteCidr {
            interface,
            sub_opts,
        } => delete_cidr(&interface, opts, sub_opts)?,
        Command::ListCidrs { interface, tree } => list_cidrs(&interface, opts, tree)?,
        Command::DisablePeer {
            interface,
            sub_opts,
        } => enable_or_disable_peer(&interface, opts, sub_opts, false)?,
        Command::EnablePeer {
            interface,
            sub_opts,
        } => enable_or_disable_peer(&interface, opts, sub_opts, true)?,
        Command::AddAssociation {
            interface,
            sub_opts,
        } => add_association(&interface, opts, sub_opts)?,
        Command::DeleteAssociation {
            interface,
            sub_opts,
        } => delete_association(&interface, opts, sub_opts)?,
        Command::ListAssociations { interface } => list_associations(&interface, opts)?,
        Command::SetListenPort {
            interface,
            sub_opts,
        } => {
            set_listen_port(&interface, opts, sub_opts)?;
        },
        Command::OverrideEndpoint {
            interface,
            sub_opts,
        } => {
            override_endpoint(&interface, opts, sub_opts)?;
        },
        Command::Completions { shell } => {
            use clap::CommandFactory;
            let mut app = Opts::command();
            let app_name = app.get_name().to_string();
            clap_complete::generate(shell, &mut app, app_name, &mut std::io::stdout());
            std::process::exit(0);
        },
    }

    Ok(())
}
