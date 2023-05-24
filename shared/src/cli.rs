use anyhow::anyhow;
use clap::{Args, Subcommand};
use colored::Colorize;
use indoc::eprintdoc;
use ipnet::IpNet;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
    vec,
};
use wireguard_control::{Backend, Device, PeerInfo};

use crate::{
    prompts, wg::PeerInfoExt, Association, AssociationContents, Cidr, CidrContents, CidrTree,
    Endpoint, Hostname, Interface, Peer, PeerContents, Timestring,
};

/// Commands that are implemented by both the server and the client CLIs.
///
/// Note: Some of these are administration/management commands, which require
/// admin privileges in order to run as a client.
#[derive(Clone, Debug, Subcommand)]
pub enum CommonCommand {
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
    DisablePeer { interface: Interface },

    /// Enable a disabled peer
    EnablePeer { interface: Interface },

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
}

impl CommonCommand {
    pub fn interface(&self) -> &Interface {
        match self {
            Self::AddPeer { interface, .. }
            | Self::RenamePeer { interface, .. }
            | Self::AddCidr { interface, .. }
            | Self::DeleteCidr { interface, .. }
            | Self::ListCidrs { interface, .. }
            | Self::DisablePeer { interface, .. }
            | Self::EnablePeer { interface, .. }
            | Self::AddAssociation { interface, .. }
            | Self::DeleteAssociation { interface, .. }
            | Self::ListAssociations { interface, .. } => interface,
        }
    }
    pub fn execute<Api: InterfaceApi>(self, api: &mut Api) -> anyhow::Result<()> {
        match self {
            Self::AddPeer { sub_opts, .. } => add_peer(api, sub_opts),
            Self::RenamePeer { sub_opts, .. } => rename_peer(api, sub_opts),
            Self::AddCidr { sub_opts, .. } => add_cidr(api, sub_opts),
            Self::DeleteCidr { sub_opts, .. } => delete_cidr(api, sub_opts),
            Self::ListCidrs { tree, .. } => list_cidrs(api, tree),
            Self::DisablePeer { .. } => enable_or_disable_peer(api, false),
            Self::EnablePeer { .. } => enable_or_disable_peer(api, true),
            Self::AddAssociation { sub_opts, .. } => add_association(api, sub_opts),
            Self::DeleteAssociation { sub_opts, .. } => delete_association(api, sub_opts),
            Self::ListAssociations { .. } => list_associations(api),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct InstallOpts {
    /// Set a specific interface name
    #[clap(long, conflicts_with = "default-name")]
    pub name: Option<String>,

    /// Use the network name inside the invitation as the interface name
    #[clap(long = "default-name")]
    pub default_name: bool,

    /// Delete the invitation after a successful install
    #[clap(short, long)]
    pub delete_invite: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct AddPeerOpts {
    /// Name of new peer
    #[clap(long)]
    pub name: Option<Hostname>,

    /// Specify desired IP of new peer (within parent CIDR)
    #[clap(long, conflicts_with = "auto-ip")]
    pub ip: Option<IpAddr>,

    /// Auto-assign the peer the first available IP within the CIDR
    #[clap(long = "auto-ip")]
    pub auto_ip: bool,

    /// Name of CIDR to add new peer under
    #[clap(long)]
    pub cidr: Option<String>,

    /// Make new peer an admin?
    #[clap(long)]
    pub admin: Option<bool>,

    /// Bypass confirmation
    #[clap(long)]
    pub yes: bool,

    /// Save the config to the given location
    #[clap(long)]
    pub save_config: Option<String>,

    /// Invite expiration period (eg. '30d', '7w', '2h', '60m', '1000s')
    #[clap(long)]
    pub invite_expires: Option<Timestring>,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct RenamePeerOpts {
    /// Name of peer to rename
    #[clap(long)]
    pub name: Option<Hostname>,

    /// The new name of the peer
    #[clap(long)]
    pub new_name: Option<Hostname>,

    /// Bypass confirmation
    #[clap(long)]
    pub yes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct AddCidrOpts {
    /// The CIDR name (eg. 'engineers')
    #[clap(long)]
    pub name: Option<Hostname>,

    /// The CIDR network (eg. '10.42.5.0/24')
    #[clap(long)]
    pub cidr: Option<IpNet>,

    /// The CIDR parent name
    #[clap(long)]
    pub parent: Option<String>,

    /// Bypass confirmation
    #[clap(long)]
    pub yes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct DeleteCidrOpts {
    /// The CIDR name (eg. 'engineers')
    #[clap(long)]
    pub name: Option<String>,

    /// Bypass confirmation
    #[clap(long)]
    pub yes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct AddDeleteAssociationOpts {
    /// The first cidr to associate
    pub cidr1: Option<String>,

    /// The second cidr to associate
    pub cidr2: Option<String>,

    /// Bypass confirmation
    #[clap(long)]
    pub yes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct ListenPortOpts {
    /// The listen port you'd like to set for the interface
    #[clap(short, long)]
    pub listen_port: Option<u16>,

    /// Unset the local listen port to use a randomized port
    #[clap(short, long, conflicts_with = "listen-port")]
    pub unset: bool,

    /// Bypass confirmation
    #[clap(long)]
    pub yes: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub struct OverrideEndpointOpts {
    /// The listen port you'd like to set for the interface
    #[clap(short, long)]
    pub endpoint: Option<Endpoint>,

    /// Unset an existing override to use the automatic endpoint discovery
    #[clap(short, long, conflicts_with = "endpoint")]
    pub unset: bool,

    /// Bypass confirmation
    #[clap(long)]
    pub yes: bool,
}

#[derive(Debug, Clone, Args)]
pub struct NatOpts {
    #[clap(long)]
    /// Don't attempt NAT traversal. Note that this still will report candidates
    /// unless you also specify to exclude all NAT candidates.
    pub no_nat_traversal: bool,

    #[clap(long)]
    /// Exclude one or more CIDRs from NAT candidate reporting.
    /// ex. --exclude-nat-candidates '0.0.0.0/0' would report no candidates.
    pub exclude_nat_candidates: Vec<IpNet>,

    #[clap(long, conflicts_with = "exclude-nat-candidates")]
    /// Don't report any candidates to coordinating server.
    /// Shorthand for --exclude-nat-candidates '0.0.0.0/0'.
    pub no_nat_candidates: bool,
}

impl NatOpts {
    pub fn all_disabled() -> Self {
        Self {
            no_nat_traversal: true,
            exclude_nat_candidates: vec![],
            no_nat_candidates: true,
        }
    }

    /// Check if an IP is allowed to be reported as a candidate.
    pub fn is_excluded(&self, ip: IpAddr) -> bool {
        self.no_nat_candidates
            || self
                .exclude_nat_candidates
                .iter()
                .any(|network| network.contains(&ip))
    }
}

#[derive(Debug, Clone, Copy, Args)]
pub struct NetworkOpts {
    #[clap(long)]
    /// Whether the routing should be done by innernet or is done by an
    /// external tool like e.g. babeld.
    pub no_routing: bool,

    #[clap(long, default_value_t, possible_values = Backend::variants())]
    /// Specify a WireGuard backend to use.
    /// If not set, innernet will auto-select based on availability.
    pub backend: Backend,

    #[clap(long)]
    /// Specify the desired MTU for your interface (default: 1280).
    pub mtu: Option<u32>,
}

pub trait InterfaceApi {
    fn cidrs(&mut self) -> anyhow::Result<Vec<Cidr>>;
    fn peers(&mut self) -> anyhow::Result<Vec<Peer>>;
    fn associations(&mut self) -> anyhow::Result<Vec<Association>>;
    fn add_cidr(&mut self, cidr_request: CidrContents) -> anyhow::Result<Cidr>;
    fn delete_cidr(&mut self, cidr_id: i64) -> anyhow::Result<()>;
    fn add_peer(&mut self, peer_request: PeerContents) -> anyhow::Result<Peer>;
    fn rename_peer(&mut self, peer_request: PeerContents, old_name: Hostname)
        -> anyhow::Result<()>;
    fn enable_or_disable_peer(&mut self, peer: Peer, enable: bool) -> anyhow::Result<()>;
    fn add_association(&mut self, association_request: AssociationContents) -> anyhow::Result<()>;
    fn delete_association(&mut self, association: &Association) -> anyhow::Result<()>;
    fn interface(&self) -> &Interface;
    fn server_endpoint(&self) -> SocketAddr;
}

fn add_cidr<Api: InterfaceApi>(api: &mut Api, sub_opts: AddCidrOpts) -> anyhow::Result<()> {
    let cidrs: Vec<Cidr> = api.cidrs()?;

    if let Some(cidr_request) = prompts::add_cidr(&cidrs, &sub_opts)? {
        log::info!("Creating CIDR...");
        let cidr: Cidr = api.add_cidr(cidr_request)?;

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

fn delete_cidr<Api: InterfaceApi>(api: &mut Api, sub_opts: DeleteCidrOpts) -> anyhow::Result<()> {
    println!("Fetching eligible CIDRs");
    let cidrs: Vec<Cidr> = api.cidrs()?;
    let peers: Vec<Peer> = api.peers()?;

    let cidr_id = prompts::delete_cidr(&cidrs, &peers, &sub_opts)?;

    println!("Deleting CIDR...");
    api.delete_cidr(cidr_id)?;

    println!("CIDR deleted.");

    Ok(())
}

fn list_cidrs<Api: InterfaceApi>(api: &mut Api, tree: bool) -> anyhow::Result<()> {
    let cidrs = api.cidrs()?;
    if tree {
        // let cidr_tree = CidrTree::new(&cidrs);
        // colored::control::set_override(false);
        // print_tree(&cidr_tree, &[], 0);
        // colored::control::unset_override();
        todo!()
    } else {
        for cidr in cidrs {
            println!("{} {}", cidr.cidr, cidr.name);
        }
    }
    Ok(())
}

fn add_peer<Api: InterfaceApi>(api: &mut Api, sub_opts: AddPeerOpts) -> anyhow::Result<()> {
    log::info!("Fetching CIDRs");
    let cidrs: Vec<Cidr> = api.cidrs()?;
    log::info!("Fetching peers");
    let peers: Vec<Peer> = api.peers()?;
    let cidr_tree = CidrTree::new(&cidrs[..]);

    if let Some(result) = prompts::add_peer(&peers, &cidr_tree, &sub_opts)? {
        let (peer_request, keypair, target_path, mut target_file) = result;
        log::info!("Creating peer...");
        let peer: Peer = api.add_peer(peer_request)?;
        let server_peer = peers.iter().find(|p| p.id == 1).unwrap();
        prompts::write_peer_invitation(
            (&mut target_file, &target_path),
            api.interface(),
            &peer,
            server_peer,
            &cidr_tree,
            keypair,
            &api.server_endpoint(),
        )?;
    } else {
        log::info!("Exited without creating peer.");
    }

    Ok(())
}

fn rename_peer<Api: InterfaceApi>(api: &mut Api, sub_opts: RenamePeerOpts) -> anyhow::Result<()> {
    log::info!("Fetching peers");
    let peers: Vec<Peer> = api.peers()?;

    if let Some((peer_request, old_name)) = prompts::rename_peer(&peers, &sub_opts)? {
        log::info!("Renaming peer...");

        api.rename_peer(peer_request, old_name)?;
        log::info!("Peer renamed.");
    } else {
        log::info!("exited without renaming peer.");
    }

    Ok(())
}

fn enable_or_disable_peer<Api: InterfaceApi>(api: &mut Api, enable: bool) -> anyhow::Result<()> {
    log::info!("Fetching peers.");
    let peers: Vec<Peer> = api.peers()?;

    if let Some(peer) = prompts::enable_or_disable_peer(&peers[..], enable)? {
        api.enable_or_disable_peer(peer, enable)?;
    } else {
        log::info!("exiting without enabling or disabling peer.");
    }

    Ok(())
}

fn add_association<Api: InterfaceApi>(
    api: &mut Api,
    sub_opts: AddDeleteAssociationOpts,
) -> anyhow::Result<()> {
    log::info!("Fetching CIDRs");
    let cidrs: Vec<Cidr> = api.cidrs()?;

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

    api.add_association(AssociationContents {
        cidr_id_1: association.0.id,
        cidr_id_2: association.1.id,
    })?;

    Ok(())
}

fn delete_association<Api: InterfaceApi>(
    api: &mut Api,
    sub_opts: AddDeleteAssociationOpts,
) -> anyhow::Result<()> {
    log::info!("Fetching CIDRs");
    let cidrs: Vec<Cidr> = api.cidrs()?;
    log::info!("Fetching associations");
    let associations: Vec<Association> = api.associations()?;

    if let Some(association) =
        prompts::delete_association(&associations[..], &cidrs[..], &sub_opts)?
    {
        api.delete_association(association)?;
    } else {
        log::info!("exiting without adding association.");
    }

    Ok(())
}

fn list_associations<Api: InterfaceApi>(api: &mut Api) -> anyhow::Result<()> {
    log::info!("Fetching CIDRs");
    let cidrs: Vec<Cidr> = api.cidrs()?;
    log::info!("Fetching associations");
    let associations: Vec<Association> = api.associations()?;

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

pub struct PeerState<'a> {
    pub peer: &'a Peer,
    pub info: Option<&'a PeerInfo>,
}

macro_rules! println_pad {
    ($pad:expr, $($arg:tt)*) => {
        print!("{:pad$}", "", pad = $pad);
        println!($($arg)*);
    }
}

pub fn print_tree(cidr: &CidrTree, peers: &[PeerState], level: usize) {
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

pub fn print_interface(device_info: &Device, short: bool) -> anyhow::Result<()> {
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

pub fn print_peer(peer: &PeerState, short: bool, level: usize) {
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

pub fn human_duration(duration: Duration) -> String {
    match duration.as_secs() {
        n if n < 1 => "just now".cyan().to_string(),
        n if n < 60 => format!("{} {} ago", n, "seconds".cyan()),
        n if n < 60 * 60 => {
            let mins = n / 60;
            let secs = n % 60;
            format!(
                "{} {}, {} {} ago",
                mins,
                if mins == 1 { "minute" } else { "minutes" }.cyan(),
                secs,
                if secs == 1 { "second" } else { "seconds" }.cyan(),
            )
        },
        n => {
            let hours = n / (60 * 60);
            let mins = (n / 60) % 60;
            format!(
                "{} {}, {} {} ago",
                hours,
                if hours == 1 { "hour" } else { "hours" }.cyan(),
                mins,
                if mins == 1 { "minute" } else { "minutes" }.cyan(),
            )
        },
    }
}

pub fn human_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    const TB: u64 = 1024 * GB;
    match bytes {
        n if n < 2 * KB => format!("{} {}", n, "B".cyan()),
        n if n < 2 * MB => format!("{:.2} {}", n as f64 / KB as f64, "KiB".cyan()),
        n if n < 2 * GB => format!("{:.2} {}", n as f64 / MB as f64, "MiB".cyan()),
        n if n < 2 * TB => format!("{:.2} {}", n as f64 / GB as f64, "GiB".cyan()),
        n => format!("{:.2} {}", n as f64 / TB as f64, "TiB".cyan()),
    }
}
