use colored::*;
use dialoguer::{Confirm, Input};
use hostsfile::HostsBuilder;
use indoc::printdoc;
use shared::{
    interface_config::InterfaceConfig, prompts, AddAssociationOpts, AddCidrOpts, AddPeerOpts,
    Association, AssociationContents, Cidr, CidrTree, EndpointContents, InstallOpts, Interface,
    IoErrorContext, Peer, RedeemContents, State, CLIENT_CONFIG_PATH, REDEEM_TRANSITION_WAIT,
};
use std::{
    fmt,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};
use structopt::StructOpt;
use wgctrl::{DeviceConfigBuilder, DeviceInfo, InterfaceName, PeerConfigBuilder, PeerInfo};

mod data_store;
mod util;

use data_store::DataStore;
use shared::{wg, Error};
use util::{human_duration, human_size, Api};

#[derive(Debug, StructOpt)]
#[structopt(name = "innernet", about)]
struct Opts {
    #[structopt(subcommand)]
    command: Option<Command>,
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

    /// Add a new CIDR.
    AddCidr {
        interface: Interface,

        #[structopt(flatten)]
        opts: AddCidrOpts,
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
) -> Result<(), Error> {
    println!(
        "{} updating {} with the latest peers.",
        "[*]".dimmed(),
        "/etc/hosts".yellow()
    );

    let mut hosts_builder = HostsBuilder::new(format!("innernet {}", interface));
    for peer in peers {
        hosts_builder.add_hostname(
            peer.contents.ip,
            &format!("{}.{}.wg", peer.contents.name, interface),
        );
    }
    hosts_builder.write_to(hosts_path)?;

    Ok(())
}

fn install(invite: &Path, hosts_file: Option<PathBuf>, opts: InstallOpts) -> Result<(), Error> {
    shared::ensure_dirs_exist(&[*CLIENT_CONFIG_PATH])?;
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

    let target_conf = CLIENT_CONFIG_PATH.join(&iface).with_extension("conf");
    if target_conf.exists() {
        return Err("An interface with this name already exists in innernet.".into());
    }

    let iface = iface.parse()?;
    redeem_invite(&iface, config, target_conf).map_err(|e| {
        println!("{} bringing down the interface.", "[*]".dimmed());
        if let Err(e) = wg::down(&iface) {
            println!("{} failed to bring down interface: {}.", "[*]".yellow(), e.to_string());
        };
        println!("{} Failed to redeem invite. Now's a good time to make sure the server is started and accessible!", "[!]".red());
        e
    })?;

    let mut fetch_success = false;
    for _ in 0..3 {
        if fetch(&iface, false, hosts_file.clone()).is_ok() {
            fetch_success = true;
            break;
        }
    }
    if !fetch_success {
        println!(
            "{} Failed to fetch peers from server, you will need to manually run the 'up' command.",
            "[!]".red()
        );
    }

    if opts.delete_invite
        || Confirm::with_theme(&*prompts::THEME)
            .with_prompt(&format!(
                "Delete invitation file \"{}\" now? (It's no longer needed)",
                invite.to_string_lossy().yellow()
            ))
            .default(true)
            .interact()?
    {
        std::fs::remove_file(invite).with_path(invite)?;
    }

    printdoc!(
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
) -> Result<(), Error> {
    println!("{} bringing up the interface.", "[*]".dimmed());
    let resolved_endpoint = config.server.external_endpoint.resolve()?;
    wg::up(
        &iface,
        &config.interface.private_key,
        config.interface.address,
        None,
        Some((
            &config.server.public_key,
            config.server.internal_endpoint.ip(),
            resolved_endpoint,
        )),
    )?;

    println!("{} Generating new keypair.", "[*]".dimmed());
    let keypair = wgctrl::KeyPair::generate();

    println!(
        "{} Registering keypair with server (at {}).",
        "[*]".dimmed(),
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
    println!(
        "{} New keypair registered. Copied config to {}.\n",
        "[*]".dimmed(),
        target_conf.to_string_lossy().yellow()
    );

    println!(
        "{} Changing keys and waiting for server's WireGuard interface to transition.",
        "[*]".dimmed(),
    );
    DeviceConfigBuilder::new()
        .set_private_key(keypair.private)
        .apply(&iface)?;
    thread::sleep(*REDEEM_TRANSITION_WAIT);

    Ok(())
}

fn up(
    interface: &InterfaceName,
    loop_interval: Option<Duration>,
    hosts_path: Option<PathBuf>,
) -> Result<(), Error> {
    loop {
        fetch(interface, true, hosts_path.clone())?;
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
) -> Result<(), Error> {
    let config = InterfaceConfig::from_interface(interface)?;
    let interface_up = if let Ok(interfaces) = DeviceInfo::enumerate() {
        interfaces.iter().any(|name| name == interface)
    } else {
        false
    };

    if !interface_up {
        if !bring_up_interface {
            return Err(format!(
                "Interface is not up. Use 'innernet up {}' instead",
                interface
            )
            .into());
        }

        println!("{} bringing up the interface.", "[*]".dimmed());
        let resolved_endpoint = config.server.external_endpoint.resolve()?;
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
        )?
    }

    println!("{} fetching state from server.", "[*]".dimmed());
    let mut store = DataStore::open_or_create(&interface)?;
    let State { peers, cidrs } = Api::new(&config.server).http("GET", "/user/state")?;

    let device_info = DeviceInfo::get_by_name(&interface)?;
    let interface_public_key = device_info
        .public_key
        .as_ref()
        .map(|k| k.to_base64())
        .unwrap_or_default();
    let existing_peers = &device_info.peers;

    let peer_configs_diff = peers
        .iter()
        .filter(|peer| !peer.is_disabled && peer.public_key != interface_public_key)
        .filter_map(|peer| {
            let existing_peer = existing_peers
                .iter()
                .find(|p| p.config.public_key.to_base64() == peer.public_key);

            let change = match existing_peer {
                Some(existing_peer) => peer
                    .diff(&existing_peer.config)
                    .map(|diff| (PeerConfigBuilder::from(&diff), peer, "modified".normal())),
                None => Some((PeerConfigBuilder::from(peer), peer, "added".green())),
            };

            change.map(|(builder, peer, text)| {
                println!(
                    "    peer {} ({}...) was {}.",
                    peer.name.yellow(),
                    &peer.public_key[..10].dimmed(),
                    text
                );
                builder
            })
        })
        .collect::<Vec<PeerConfigBuilder>>();

    let mut device_config_builder = DeviceConfigBuilder::new();
    let mut device_config_changed = false;

    if !peer_configs_diff.is_empty() {
        device_config_builder = device_config_builder.add_peers(&peer_configs_diff);
        device_config_changed = true;
    }

    for peer in existing_peers {
        let public_key = peer.config.public_key.to_base64();
        if !peers.iter().any(|p| p.public_key == public_key) {
            println!(
                "    peer ({}...) was {}.",
                &public_key[..10].yellow(),
                "removed".red()
            );

            device_config_builder =
                device_config_builder.remove_peer_by_key(&peer.config.public_key);
            device_config_changed = true;
        }
    }

    if device_config_changed {
        device_config_builder.apply(&interface)?;

        if let Some(path) = hosts_path {
            update_hosts_file(interface, path, &peers)?;
        }

        println!(
            "\n{} updated interface {}\n",
            "[*]".dimmed(),
            interface.as_str_lossy().yellow()
        );
    } else {
        println!("{}", "    peers are already up to date.".green());
    }
    store.set_cidrs(cidrs);
    store.add_peers(peers)?;
    store.write()?;

    Ok(())
}

fn uninstall(interface: &InterfaceName) -> Result<(), Error> {
    if Confirm::with_theme(&*prompts::THEME)
        .with_prompt(&format!(
            "Permanently delete network \"{}\"?",
            interface.as_str_lossy().yellow()
        ))
        .default(false)
        .interact()?
    {
        println!("{} bringing down interface (if up).", "[*]".dimmed());
        wg::down(interface).ok();
        let config = InterfaceConfig::get_path(interface);
        let data = DataStore::get_path(interface);
        std::fs::remove_file(&config)
            .with_path(&config)
            .map_err(|e| println!("[!] {}", e.to_string().yellow()))
            .ok();
        std::fs::remove_file(&data)
            .with_path(&data)
            .map_err(|e| println!("[!] {}", e.to_string().yellow()))
            .ok();
        println!(
            "{} network {} is uninstalled.",
            "[*]".dimmed(),
            interface.as_str_lossy().yellow()
        );
    }
    Ok(())
}

fn add_cidr(interface: &InterfaceName, opts: AddCidrOpts) -> Result<(), Error> {
    let InterfaceConfig { server, .. } = InterfaceConfig::from_interface(interface)?;
    println!("Fetching CIDRs");
    let api = Api::new(&server);
    let cidrs: Vec<Cidr> = api.http("GET", "/admin/cidrs")?;

    let cidr_request = prompts::add_cidr(&cidrs, &opts)?;

    println!("Creating CIDR...");
    let cidr: Cidr = api.http_form("POST", "/admin/cidrs", cidr_request)?;

    printdoc!(
        "
        CIDR \"{cidr_name}\" added.

        Right now, peers within {cidr_name} can only see peers in the same CIDR
        , and in the special \"infra\" CIDR that includes the innernet server peer.

        You'll need to add more associations for peers in diffent CIDRs to communicate.
        ",
        cidr_name = cidr.name.bold()
    );

    Ok(())
}

fn add_peer(interface: &InterfaceName, opts: AddPeerOpts) -> Result<(), Error> {
    let InterfaceConfig { server, .. } = InterfaceConfig::from_interface(interface)?;
    let api = Api::new(&server);

    println!("Fetching CIDRs");
    let cidrs: Vec<Cidr> = api.http("GET", "/admin/cidrs")?;
    println!("Fetching peers");
    let peers: Vec<Peer> = api.http("GET", "/admin/peers")?;
    let cidr_tree = CidrTree::new(&cidrs[..]);

    if let Some((peer_request, keypair)) = prompts::add_peer(&peers, &cidr_tree, &opts)? {
        println!("Creating peer...");
        let peer: Peer = api.http_form("POST", "/admin/peers", peer_request)?;
        let server_peer = peers.iter().find(|p| p.id == 1).unwrap();
        prompts::save_peer_invitation(
            interface,
            &peer,
            server_peer,
            &cidr_tree,
            keypair,
            &server.internal_endpoint,
            &opts.save_config,
        )?;
    } else {
        println!("exited without creating peer.");
    }

    Ok(())
}

fn enable_or_disable_peer(interface: &InterfaceName, enable: bool) -> Result<(), Error> {
    let InterfaceConfig { server, .. } = InterfaceConfig::from_interface(interface)?;
    let api = Api::new(&server);

    println!("Fetching peers.");
    let peers: Vec<Peer> = api.http("GET", "/admin/peers")?;

    if let Some(peer) = prompts::enable_or_disable_peer(&peers[..], enable)? {
        let Peer { id, mut contents } = peer;
        contents.is_disabled = !enable;
        api.http_form("PUT", &format!("/admin/peers/{}", id), contents)?;
    } else {
        println!("exited without disabling peer.");
    }

    Ok(())
}

fn add_association(interface: &InterfaceName, opts: AddAssociationOpts) -> Result<(), Error> {
    let InterfaceConfig { server, .. } = InterfaceConfig::from_interface(interface)?;
    let api = Api::new(&server);

    println!("Fetching CIDRs");
    let cidrs: Vec<Cidr> = api.http("GET", "/admin/cidrs")?;

    let association = if let (Some(ref cidr1), Some(ref cidr2)) = (opts.cidr1, opts.cidr2) {
        let cidr1 = cidrs
            .iter()
            .find(|c| &c.name == cidr1)
            .ok_or(format!("can't find cidr '{}'", cidr1))?;
        let cidr2 = cidrs
            .iter()
            .find(|c| &c.name == cidr2)
            .ok_or(format!("can't find cidr '{}'", cidr2))?;
        (cidr1, cidr2)
    } else if let Some((cidr1, cidr2)) = prompts::add_association(&cidrs[..])? {
        (cidr1, cidr2)
    } else {
        println!("exited without adding association.");
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

    println!("Fetching CIDRs");
    let cidrs: Vec<Cidr> = api.http("GET", "/admin/cidrs")?;
    println!("Fetching associations");
    let associations: Vec<Association> = api.http("GET", "/admin/associations")?;

    if let Some(association) = prompts::delete_association(&associations[..], &cidrs[..])? {
        api.http("DELETE", &format!("/admin/associations/{}", association.id))?;
    } else {
        println!("exited without adding association.");
    }

    Ok(())
}

fn list_associations(interface: &InterfaceName) -> Result<(), Error> {
    let InterfaceConfig { server, .. } = InterfaceConfig::from_interface(interface)?;
    let api = Api::new(&server);

    println!("Fetching CIDRs");
    let cidrs: Vec<Cidr> = api.http("GET", "/admin/cidrs")?;
    println!("Fetching associations");
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

fn set_listen_port(interface: &InterfaceName, unset: bool) -> Result<(), Error> {
    let mut config = InterfaceConfig::from_interface(interface)?;

    if let Some(listen_port) = prompts::set_listen_port(&config.interface, unset)? {
        wg::set_listen_port(interface, listen_port)?;
        println!("{} the interface is updated", "[*]".dimmed(),);

        config.interface.listen_port = listen_port;
        config.write_to_interface(interface)?;
        println!("{} the config file is updated", "[*]".dimmed(),);
    } else {
        println!("exited without updating listen port.");
    }

    Ok(())
}

fn override_endpoint(interface: &InterfaceName, unset: bool) -> Result<(), Error> {
    let config = InterfaceConfig::from_interface(interface)?;
    if !unset && config.interface.listen_port.is_none() {
        println!(
            "{}: you need to set a listen port for your interface first.",
            "note".bold().yellow()
        );
        set_listen_port(interface, unset)?;
    }

    if let Some(endpoint) = prompts::override_endpoint(unset)? {
        println!("Updating endpoint.");
        Api::new(&config.server).http_form(
            "PUT",
            "/user/endpoint",
            EndpointContents::from(endpoint),
        )?;
    } else {
        println!("exited without overriding endpoint.");
    }

    Ok(())
}

fn show(short: bool, tree: bool, interface: Option<Interface>) -> Result<(), Error> {
    let interfaces =
        interface.map_or_else(DeviceInfo::enumerate, |interface| Ok(vec![*interface]))?;

    let devices = interfaces.into_iter().filter_map(|name| {
        DataStore::open(&name)
            .and_then(|store| Ok((DeviceInfo::get_by_name(&name)?, store)))
            .ok()
    });
    for (mut device_info, store) in devices {
        let peers = store.peers();
        let cidrs = store.cidrs();
        let me = peers
            .iter()
            .find(|p| p.public_key == device_info.public_key.as_ref().unwrap().to_base64())
            .ok_or("missing peer info")?;

        print_interface(&device_info, me, short)?;
        // Sort the peers by last handshake time (descending),
        // then by IP address (ascending)
        device_info.peers.sort_by_key(|peer| {
            let our_peer = peers
                .iter()
                .find(|p| p.public_key == peer.config.public_key.to_base64())
                .ok_or("missing peer info")
                .unwrap();

            (
                std::cmp::Reverse(peer.stats.last_handshake_time),
                our_peer.ip,
            )
        });

        if tree {
            let cidr_tree = CidrTree::new(cidrs);
            print_tree(&cidr_tree, &peers, 1);
        } else {
            for peer in device_info.peers {
                let our_peer = peers
                    .iter()
                    .find(|p| p.public_key == peer.config.public_key.to_base64())
                    .ok_or("missing peer info")?;
                print_peer(our_peer, &peer, short)?;
            }
        }
    }
    Ok(())
}

fn print_tree(cidr: &CidrTree, peers: &[Peer], level: usize) {
    println!(
        "{:pad$}{} {}",
        "",
        cidr.cidr.to_string().bold().blue(),
        cidr.name.blue(),
        pad = level * 2
    );

    let mut children: Vec<_> = cidr.children().collect();
    children.sort();
    children
        .iter()
        .for_each(|child| print_tree(&child, peers, level + 1));

    for peer in peers.iter().filter(|p| p.cidr_id == cidr.id) {
        println!(
            "{:pad$}| {} {}",
            "",
            peer.ip.to_string().yellow().bold(),
            peer.name.yellow(),
            pad = level * 2
        );
    }
}

fn print_interface(device_info: &DeviceInfo, me: &Peer, short: bool) -> Result<(), Error> {
    let public_key = device_info
        .public_key
        .as_ref()
        .ok_or("interface has no private key set.")?
        .to_base64();

    if short {
        println!("{}", device_info.name.to_string().green().bold());
        println!(
            "  {} {}: {} ({}...)",
            "(you)".bold(),
            me.ip.to_string().yellow().bold(),
            me.name.yellow(),
            public_key[..10].dimmed()
        );
    } else {
        println!(
            "{}: {} ({}...)",
            "interface".green().bold(),
            device_info.name.to_string().green(),
            public_key[..10].yellow()
        );
        if !short {
            if let Some(listen_port) = device_info.listen_port {
                println!("  {}: {}", "listening_port".bold(), listen_port);
            }
            println!("  {}: {}", "ip".bold(), me.ip);
        }
    }
    Ok(())
}

fn print_peer(our_peer: &Peer, peer: &PeerInfo, short: bool) -> Result<(), Error> {
    if short {
        println!(
            "  {}: {} ({}...)",
            peer.config.allowed_ips[0]
                .address
                .to_string()
                .yellow()
                .bold(),
            our_peer.name.yellow(),
            &our_peer.public_key[..10].dimmed()
        );
    } else {
        println!(
            "{}: {} ({}...)",
            "peer".yellow().bold(),
            our_peer.name.yellow(),
            &our_peer.public_key[..10].yellow()
        );
        println!("  {}: {}", "ip".bold(), our_peer.ip);
        if let Some(ref endpoint) = our_peer.endpoint {
            println!("  {}: {}", "endpoint".bold(), endpoint);
        }
        if let Some(last_handshake) = peer.stats.last_handshake_time {
            let duration = last_handshake.elapsed()?;
            println!(
                "  {}: {}",
                "last handshake".bold(),
                human_duration(duration),
            );
        }
        if peer.stats.tx_bytes > 0 || peer.stats.rx_bytes > 0 {
            println!(
                "  {}: {} received, {} sent",
                "transfer".bold(),
                human_size(peer.stats.rx_bytes),
                human_size(peer.stats.tx_bytes),
            );
        }
    }

    Ok(())
}

fn main() {
    let opt = Opts::from_args();

    if let Err(e) = run(opt) {
        eprintln!("\n{} {}\n", "[ERROR]".red(), e);
        std::process::exit(1);
    }
}

fn run(opt: Opts) -> Result<(), Error> {
    if unsafe { libc::getuid() } != 0 {
        return Err("innernet must run as root.".into());
    }

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
        } => install(&invite, hosts.into(), opts)?,
        Command::Show {
            short,
            tree,
            interface,
        } => show(short, tree, interface)?,
        Command::Fetch { interface, hosts } => fetch(&interface, false, hosts.into())?,
        Command::Up {
            interface,
            daemon,
            hosts,
            interval,
        } => up(
            &interface,
            daemon.then(|| Duration::from_secs(interval)),
            hosts.into(),
        )?,
        Command::Down { interface } => wg::down(&interface)?,
        Command::Uninstall { interface } => uninstall(&interface)?,
        Command::AddPeer { interface, opts } => add_peer(&interface, opts)?,
        Command::AddCidr { interface, opts } => add_cidr(&interface, opts)?,
        Command::DisablePeer { interface } => enable_or_disable_peer(&interface, false)?,
        Command::EnablePeer { interface } => enable_or_disable_peer(&interface, true)?,
        Command::AddAssociation { interface, opts } => add_association(&interface, opts)?,
        Command::DeleteAssociation { interface } => delete_association(&interface)?,
        Command::ListAssociations { interface } => list_associations(&interface)?,
        Command::SetListenPort { interface, unset } => set_listen_port(&interface, unset)?,
        Command::OverrideEndpoint { interface, unset } => override_endpoint(&interface, unset)?,
    }

    Ok(())
}
