use anyhow::{anyhow, bail};
use clap::{AppSettings, Args, IntoApp, Parser, Subcommand};
use colored::*;
use dialoguer::{Confirm, Input};
use hostsfile::HostsBuilder;
use indoc::eprintdoc;
use shared::{
    get_local_addrs, interface_config::InterfaceConfig, print_interface, print_peer, print_tree,
    prompts, wg::DeviceExt, Association, AssociationContents, Cidr, CidrTree, CommonCommand,
    Endpoint, EndpointContents, InstallOpts, Interface, InterfaceApi, IoErrorContext,
    ListenPortOpts, NatOpts, NetworkOpts, OverrideEndpointOpts, Peer, PeerState, RedeemContents,
    State, WrappedIoError, REDEEM_TRANSITION_WAIT,
};
use std::{
    fmt, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};
use wireguard_control::{Device, DeviceUpdate, InterfaceName, PeerConfigBuilder};

mod data_store;
mod nat;
mod util;

use data_store::DataStore;
use nat::NatTraverse;
use shared::{wg, Error};
use util::Api;

use crate::util::all_installed;

#[derive(Clone, Debug, Parser)]
#[clap(name = "innernet", author, version, about)]
#[clap(global_setting(AppSettings::DeriveDisplayOrder))]
struct Opts {
    #[clap(subcommand)]
    command: Option<Command>,

    /// Verbose output, use -vv for even higher verbositude
    #[clap(short, long, parse(from_occurrences))]
    verbose: u64,

    #[clap(short, long, default_value = "/etc/innernet")]
    config_dir: PathBuf,

    #[clap(short, long, default_value = "/var/lib/innernet")]
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
    #[clap(long = "no-write-hosts", conflicts_with = "hosts-path")]
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
        #[clap(arg_enum)]
        shell: clap_complete::Shell,
    },

    #[clap(flatten)]
    Common(CommonCommand),
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

    let mut hosts_builder = HostsBuilder::new(format!("innernet {interface}"));
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
            .with_prompt(&format!(
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
    let port = match config.interface.listen_port {
        Some(port) => port,
        None => bail!("you need to set a listen port with set-listen-port before overriding the endpoint (otherwise port randomization on the interface would make it useless).")
    };

    let endpoint_contents = if sub_opts.unset {
        prompts::unset_override_endpoint(&sub_opts)?.then_some(EndpointContents::Unset)
    } else {
        let endpoint = prompts::override_endpoint(&sub_opts, port)?;
        endpoint.map(EndpointContents::Set)
    };

    if let Some(contents) = endpoint_contents {
        log::info!("requesting endpoint update...");
        Api::new(&config.server).http_form("PUT", "/user/endpoint", contents)?;
        log::info!(
            "endpoint override {}",
            if sub_opts.unset { "unset" } else { "set" }
        );
    } else {
        log::info!("exiting without overriding endpoint");
    }

    Ok(())
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

fn main() {
    let opts = Opts::parse();
    util::init_logger(opts.verbose);

    let argv0 = std::env::args().next().unwrap();
    let executable = Path::new(&argv0).file_name().unwrap().to_str().unwrap();
    if executable == "inn" {
        log::warn!("");
        log::warn!("  {}: the {} shortcut will be removed from OS packages soon in favor of users creating a shell alias.", "WARNING".bold(), "inn".yellow());
        log::warn!("");
        log::warn!("  See https://github.com/tonarino/innernet/issues/176 for instructions to continue using it.");
        log::warn!("");
    }

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
            let mut app = Opts::command();
            let app_name = app.get_name().to_string();
            clap_complete::generate(shell, &mut app, app_name, &mut std::io::stdout());
            std::process::exit(0);
        },
        Command::Common(common_command) => {
            let InterfaceConfig { server, .. } =
                InterfaceConfig::from_interface(&opts.config_dir, common_command.interface())?;
            let mut db = ClientInterfaceApi {
                api: Api::new(&server),
                interface: common_command.interface().clone(),
                server_endpoint: server.internal_endpoint,
            };
            common_command.execute(&mut db)?;
        },
    }

    Ok(())
}

struct ClientInterfaceApi<'a> {
    api: Api<'a>,
    interface: Interface,
    server_endpoint: SocketAddr,
}

impl<'a> InterfaceApi for ClientInterfaceApi<'a> {
    fn cidrs(&mut self) -> anyhow::Result<Vec<Cidr>> {
        self.api.http("GET", "/admin/cidrs").map_err(Into::into)
    }

    fn peers(&mut self) -> anyhow::Result<Vec<Peer>> {
        self.api.http("GET", "/admin/peers").map_err(Into::into)
    }

    fn associations(&mut self) -> anyhow::Result<Vec<Association>> {
        self.api
            .http("GET", "/admin/associations")
            .map_err(Into::into)
    }

    fn add_cidr(&mut self, cidr_request: shared::CidrContents) -> anyhow::Result<Cidr> {
        self.api
            .http_form("POST", "/admin/cidrs", cidr_request)
            .map_err(Into::into)
    }

    fn delete_cidr(&mut self, cidr_id: i64) -> anyhow::Result<()> {
        self.api
            .http("DELETE", &format!("/admin/cidrs/{cidr_id}"))
            .map_err(Into::into)
    }

    fn add_peer(&mut self, peer_request: shared::PeerContents) -> anyhow::Result<Peer> {
        self.api
            .http_form("POST", "/admin/peers", peer_request)
            .map_err(Into::into)
    }

    fn rename_peer(
        &mut self,
        peer_request: shared::PeerContents,
        old_name: shared::Hostname,
    ) -> anyhow::Result<()> {
        // TODO optimize this: list of peers may have already been fetched in
        // shared::cli::rename_peer
        let peers = self.peers()?;

        let id = peers
            .iter()
            .filter(|p| p.name == old_name)
            .map(|p| p.id)
            .next()
            .ok_or_else(|| anyhow!("Peer not found."))?;

        self.api
            .http_form("PUT", &format!("/admin/peers/{id}"), peer_request)
            .map_err(Into::into)
    }

    fn enable_or_disable_peer(&mut self, peer: Peer, enable: bool) -> anyhow::Result<()> {
        let Peer { id, mut contents } = peer;
        contents.is_disabled = !enable;
        self.api
            .http_form("PUT", &format!("/admin/peers/{id}"), contents)
            .map_err(Into::into)
    }

    fn add_association(&mut self, association_request: AssociationContents) -> anyhow::Result<()> {
        self.api
            .http_form("POST", "/admin/associations", association_request)
            .map_err(Into::into)
    }

    fn delete_association(&mut self, association: &Association) -> anyhow::Result<()> {
        self.api
            .http("DELETE", &format!("/admin/associations/{}", association.id))
            .map_err(Into::into)
    }

    fn interface(&self) -> &Interface {
        &self.interface
    }

    fn server_endpoint(&self) -> SocketAddr {
        self.server_endpoint
    }
}
