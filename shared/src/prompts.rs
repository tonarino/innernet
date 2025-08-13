use crate::{
    interface_config::{InterfaceConfig, InterfaceInfo, ServerInfo},
    AddCidrOpts, AddDeleteAssociationOpts, AddPeerOpts, Association, Cidr, CidrContents, CidrTree,
    DeleteCidrOpts, EnableDisablePeerOpts, Endpoint, Error, Hostname, IpNetExt, ListenPortOpts,
    Peer, PeerContents, RenameCidrOpts, RenamePeerOpts, PERSISTENT_KEEPALIVE_INTERVAL_SECS,
};
use anyhow::anyhow;
use colored::*;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use innernet_publicip::Preference;
use ipnet::IpNet;
use once_cell::sync::Lazy;
use std::{
    fmt::{Debug, Display},
    fs::{File, OpenOptions},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    time::SystemTime,
};
use wireguard_control::{InterfaceName, KeyPair};

pub static THEME: Lazy<ColorfulTheme> = Lazy::new(ColorfulTheme::default);

pub fn ensure_interactive(prompt: &str) -> Result<(), io::Error> {
    if atty::is(atty::Stream::Stdin) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            format!("Prompt \"{prompt}\" failed because TTY isn't connected."),
        ))
    }
}

pub fn confirm(prompt: &str) -> Result<bool, dialoguer::Error> {
    ensure_interactive(prompt)?;
    Confirm::with_theme(&*THEME)
        .wait_for_newline(true)
        .with_prompt(prompt)
        .default(false)
        .interact()
}

pub fn select<'a, T: ToString>(
    prompt: &str,
    items: &'a [T],
) -> Result<(usize, &'a T), dialoguer::Error> {
    ensure_interactive(prompt)?;
    let choice = Select::with_theme(&*THEME)
        .with_prompt(prompt)
        .items(items)
        .interact()?;
    Ok((choice, &items[choice]))
}

pub enum Prefill<T> {
    Default(T),
    Editable(String),
    None,
}

pub fn input<T>(prompt: &str, prefill: Prefill<T>) -> Result<T, dialoguer::Error>
where
    T: Clone + FromStr + Display,
    T::Err: Display + Debug,
{
    ensure_interactive(prompt)?;
    let input = Input::with_theme(&*THEME);
    match prefill {
        Prefill::Default(value) => input.default(value),
        Prefill::Editable(value) => input.with_initial_text(value),
        _ => input,
    }
    .with_prompt(prompt)
    .interact()
}

/// Bring up a prompt to create a new CIDR. Returns the peer request.
pub fn add_cidr(cidrs: &[Cidr], request: &AddCidrOpts) -> Result<Option<CidrContents>, Error> {
    let parent_cidr = if let Some(ref parent_name) = request.parent {
        cidrs
            .iter()
            .find(|cidr| &cidr.name == parent_name)
            .ok_or_else(|| anyhow!("No parent CIDR with that name exists."))?
    } else {
        choose_cidr(cidrs, "Parent CIDR")?
    };

    let name = if let Some(ref name) = request.name {
        name.clone()
    } else {
        input("Name", Prefill::None)?
    };

    let cidr = if let Some(cidr) = request.cidr {
        cidr
    } else {
        input("CIDR", Prefill::None)?
    };

    let cidr_request = CidrContents {
        name: name.to_string(),
        cidr,
        parent: Some(parent_cidr.id),
    };

    Ok(
        if request.yes || confirm(&format!("Create CIDR \"{}\"?", cidr_request.name))? {
            Some(cidr_request)
        } else {
            None
        },
    )
}

/// Bring up a prompt to rename an existing CIDR. Returns the CIDR request.
pub fn rename_cidr(
    cidrs: &[Cidr],
    args: &RenameCidrOpts,
) -> Result<Option<(CidrContents, String)>, Error> {
    let old_cidr = if let Some(ref name) = args.name {
        cidrs
            .iter()
            .find(|c| &c.name == name)
            .ok_or_else(|| anyhow!("CIDR '{}' does not exist", name))?
            .clone()
    } else {
        let (cidr_index, _) = select(
            "CIDR to rename",
            &cidrs.iter().map(|ep| ep.name.clone()).collect::<Vec<_>>(),
        )?;
        cidrs[cidr_index].clone()
    };
    let old_name = old_cidr.name.clone();
    let new_name = if let Some(ref name) = args.new_name {
        name.clone()
    } else {
        input("New Name", Prefill::None)?
    };

    let mut new_cidr = old_cidr;
    new_cidr.contents.name.clone_from(&new_name);

    Ok(
        if args.yes
            || confirm(&format!(
                "Rename CIDR {} to {}?",
                old_name.yellow(),
                new_name.yellow()
            ))?
        {
            Some((new_cidr.contents, old_name))
        } else {
            None
        },
    )
}

/// Bring up a prompt to delete a CIDR. Returns the peer request.
pub fn delete_cidr(cidrs: &[Cidr], peers: &[Peer], request: &DeleteCidrOpts) -> Result<i64, Error> {
    let eligible_cidrs: Vec<_> = cidrs
        .iter()
        .filter(|cidr| {
            !peers.iter().any(|peer| peer.contents.cidr_id == cidr.id) &&
            !cidrs.iter().any(
                |cidr2| matches!(cidr2.contents.parent, Some(parent_id) if parent_id == cidr.id)
            )
        })
        .collect();
    let cidr = if let Some(ref name) = request.name {
        cidrs
            .iter()
            .find(|cidr| &cidr.name == name)
            .ok_or_else(|| anyhow!("CIDR {} doesn't exist or isn't eligible for deletion", name))?
    } else {
        select("Delete CIDR", &eligible_cidrs)?.1
    };

    if request.yes || confirm(&format!("Delete CIDR \"{}\"?", cidr.name))? {
        Ok(cidr.id)
    } else {
        Err(anyhow!("Canceled"))
    }
}

pub fn choose_cidr<'a>(cidrs: &'a [Cidr], text: &'static str) -> Result<&'a Cidr, Error> {
    let eligible_cidrs: Vec<_> = cidrs
        .iter()
        .filter(|cidr| cidr.name != "innernet-server")
        .collect();
    Ok(select(text, &eligible_cidrs)?.1)
}

pub fn choose_association<'a>(
    associations: &'a [Association],
    cidrs: &'a [Cidr],
    args: &AddDeleteAssociationOpts,
) -> Result<&'a Association, Error> {
    match (&args.cidr1, &args.cidr2) {
        (Some(cidr1_name), Some(cidr2_name)) => {
            let cidr1 = find_cidr(cidrs, cidr1_name)?;
            let cidr2 = find_cidr(cidrs, cidr2_name)?;
            associations
                .iter()
                .find(|association| {
                    (association.cidr_id_1 == cidr1.id && association.cidr_id_2 == cidr2.id)
                        || (association.cidr_id_1 == cidr2.id && association.cidr_id_2 == cidr1.id)
                })
                .ok_or_else(|| anyhow!("CIDR association does not exist"))
        },
        _ => {
            let names: Vec<_> = associations
                .iter()
                .map(|association| {
                    format!(
                        "{}: {} <=> {}",
                        association.id,
                        &cidrs
                            .iter()
                            .find(|c| c.id == association.cidr_id_1)
                            .unwrap()
                            .name,
                        &cidrs
                            .iter()
                            .find(|c| c.id == association.cidr_id_2)
                            .unwrap()
                            .name
                    )
                })
                .collect();
            let (index, _) = select("Association", &names)?;

            Ok(&associations[index])
        },
    }
}

fn find_cidr<'a>(cidrs: &'a [Cidr], name: &str) -> Result<&'a Cidr, Error> {
    cidrs
        .iter()
        .find(|c| c.name == name)
        .ok_or_else(|| anyhow!("can't find cidr '{}'", name))
}

fn find_or_prompt_cidr<'a>(
    cidrs: &'a [Cidr],
    sub_opt: &Option<String>,
    prompt: &'static str,
) -> Result<&'a Cidr, Error> {
    if let Some(name) = sub_opt {
        find_cidr(cidrs, name)
    } else {
        choose_cidr(cidrs, prompt)
    }
}

pub fn add_association<'a>(
    cidrs: &'a [Cidr],
    args: &AddDeleteAssociationOpts,
) -> Result<Option<(&'a Cidr, &'a Cidr)>, Error> {
    let cidr1 = find_or_prompt_cidr(cidrs, &args.cidr1, "First CIDR")?;
    let cidr2 = find_or_prompt_cidr(cidrs, &args.cidr2, "Second CIDR")?;

    Ok(
        if args.yes
            || confirm(&format!(
                "Add association: {} <=> {}?",
                cidr1.name.yellow().bold(),
                cidr2.name.yellow().bold()
            ))?
        {
            Some((cidr1, cidr2))
        } else {
            None
        },
    )
}

pub fn delete_association<'a>(
    associations: &'a [Association],
    cidrs: &'a [Cidr],
    args: &AddDeleteAssociationOpts,
) -> Result<Option<&'a Association>, Error> {
    let association = choose_association(associations, cidrs, args)?;

    Ok(
        if args.yes || confirm(&format!("Delete association #{}?", association.id))? {
            Some(association)
        } else {
            None
        },
    )
}

/// Bring up a prompt to create a new peer. Returns the peer request.
pub fn add_peer(
    peers: &[Peer],
    cidr_tree: &CidrTree,
    args: &AddPeerOpts,
) -> Result<Option<(PeerContents, KeyPair, String, File)>, Error> {
    let leaves = cidr_tree.leaves();

    let cidr = if let Some(ref parent_name) = args.cidr {
        leaves
            .iter()
            .find(|cidr| &cidr.name == parent_name)
            .ok_or_else(|| anyhow!("No eligible CIDR with that name exists."))?
    } else {
        choose_cidr(&leaves[..], "Eligible CIDRs for peer")?
    };

    let mut available_ip = None;
    let candidate_ips = cidr.hosts().filter(|ip| cidr.is_assignable(ip));
    for ip in candidate_ips {
        if !peers.iter().any(|peer| peer.ip == ip) {
            available_ip = Some(ip);
            break;
        }
    }

    let available_ip = available_ip.expect("No IPs in this CIDR are avavilable");

    let ip = if let Some(ip) = args.ip {
        ip
    } else if args.auto_ip {
        available_ip
    } else {
        input("IP", Prefill::Default(available_ip))?
    };

    let name = if let Some(ref name) = args.name {
        name.clone()
    } else {
        input("Name", Prefill::None)?
    };

    let is_admin = if let Some(is_admin) = args.admin {
        is_admin
    } else {
        confirm(&format!("Make {name} an admin?"))?
    };

    let invite_expires = if let Some(ref invite_expires) = args.invite_expires {
        invite_expires.clone()
    } else {
        input(
            "Invite expires after",
            Prefill::Default("14d".parse().map_err(|s: &str| anyhow!(s))?),
        )?
    };

    let invite_save_path = if let Some(ref location) = args.save_config {
        location.clone()
    } else {
        input(
            "Save peer invitation file to",
            Prefill::Default(format!("{name}.toml")),
        )?
    };

    let default_keypair = KeyPair::generate();
    let peer_request = PeerContents {
        name,
        ip,
        cidr_id: cidr.id,
        public_key: default_keypair.public.to_base64(),
        endpoint: None,
        is_admin,
        is_disabled: false,
        is_redeemed: false,
        persistent_keepalive_interval: Some(PERSISTENT_KEEPALIVE_INTERVAL_SECS),
        invite_expires: Some(SystemTime::now() + invite_expires.into()),
        candidates: vec![],
    };

    Ok(
        if args.yes || confirm(&format!("Create peer {}?", peer_request.name.yellow()))? {
            let invite_file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&invite_save_path)?;
            Some((peer_request, default_keypair, invite_save_path, invite_file))
        } else {
            None
        },
    )
}

/// Bring up a prompt to rename an existing peer. Returns the peer request.
pub fn rename_peer(
    peers: &[Peer],
    args: &RenamePeerOpts,
) -> Result<Option<(PeerContents, Hostname)>, Error> {
    let eligible_peers = peers
        .iter()
        .filter(|p| &*p.name != "innernet-server")
        .collect::<Vec<_>>();
    let old_peer = if let Some(ref name) = args.name {
        eligible_peers
            .into_iter()
            .find(|p| &p.name == name)
            .ok_or_else(|| anyhow!("Peer '{}' does not exist", name))?
            .clone()
    } else {
        let (peer_index, _) = select(
            "Peer to rename",
            &eligible_peers
                .iter()
                .map(|ep| ep.name.clone())
                .collect::<Vec<_>>(),
        )?;
        eligible_peers[peer_index].clone()
    };
    let old_name = old_peer.name.clone();
    let new_name = if let Some(ref name) = args.new_name {
        name.clone()
    } else {
        input("New Name", Prefill::None)?
    };

    let mut new_peer = old_peer;
    new_peer.contents.name = new_name.clone();

    Ok(
        if args.yes
            || confirm(&format!(
                "Rename peer {} to {}?",
                old_name.yellow(),
                new_name.yellow()
            ))?
        {
            Some((new_peer.contents, old_name))
        } else {
            None
        },
    )
}

/// Presents a selection and confirmation of eligible peers for either disabling or enabling,
/// and returns back the ID of the selected peer.
pub fn enable_or_disable_peer(
    peers: &[Peer],
    args: &EnableDisablePeerOpts,
    enable: bool,
) -> Result<Option<Peer>, Error> {
    let enabled_peers: Vec<_> = peers
        .iter()
        .filter(|peer| enable && peer.is_disabled || !enable && !peer.is_disabled)
        .collect();

    let peer = if let Some(ref name) = args.name {
        enabled_peers
            .into_iter()
            .find(|p| &p.name == name)
            .ok_or_else(|| anyhow!("Peer '{}' does not exist", name))?
    } else {
        let peer_selection: Vec<_> = enabled_peers
            .iter()
            .map(|peer| format!("{} ({})", &peer.name, &peer.ip))
            .collect();
        let (index, _) = select(
            &format!("Peer to {}able", if enable { "en" } else { "dis" }),
            &peer_selection,
        )?;
        enabled_peers[index]
    };

    Ok(
        if args.yes
            || confirm(&format!(
                "{}able peer {}?",
                if enable { "En" } else { "Dis" },
                peer.name.yellow()
            ))?
        {
            Some(peer.clone())
        } else {
            None
        },
    )
}

/// Confirm and write a innernet invitation file after a peer has been created.
pub fn write_peer_invitation(
    target_file: (&mut File, &str),
    network_name: &InterfaceName,
    peer: &Peer,
    server_peer: &Peer,
    root_cidr: &Cidr,
    keypair: KeyPair,
    server_api_addr: &SocketAddr,
) -> Result<(), Error> {
    let peer_invitation = InterfaceConfig {
        interface: InterfaceInfo {
            network_name: network_name.to_string(),
            private_key: keypair.private.to_base64(),
            address: IpNet::new(peer.ip, root_cidr.prefix_len())?,
            listen_port: None,
        },
        server: ServerInfo {
            external_endpoint: server_peer
                .endpoint
                .clone()
                .expect("The innernet server should have a WireGuard endpoint"),
            internal_endpoint: *server_api_addr,
            public_key: server_peer.public_key.clone(),
        },
    };

    peer_invitation.write_to(target_file.0, true, None)?;

    println!(
        "\nPeer \"{}\" added\n\
         Peer invitation file written to {}\n\
         Please send it to them securely (eg. via magic-wormhole) \
         to bootstrap them onto the network.",
        peer.name.bold(),
        target_file.1.bold()
    );

    Ok(())
}

pub fn set_listen_port(
    interface: &InterfaceInfo,
    args: ListenPortOpts,
) -> Result<Option<Option<u16>>, Error> {
    let listen_port = if let Some(listen_port) = args.listen_port {
        Some(listen_port)
    } else if !args.unset {
        Some(input(
            "Listen port",
            Prefill::Default(interface.listen_port.unwrap_or(51820)),
        )?)
    } else {
        None
    };

    let confirmation = Confirm::with_theme(&*THEME)
        .wait_for_newline(true)
        .with_prompt(
            &(if let Some(port) = &listen_port {
                format!("Set listen port to {port}?")
            } else {
                "Unset and randomize listen port?".to_string()
            }),
        )
        .default(false);

    if listen_port == interface.listen_port {
        println!("No change necessary - interface already has this setting.");
        Ok(None)
    } else if args.yes || confirmation.interact()? {
        Ok(Some(listen_port))
    } else {
        Ok(None)
    }
}

pub fn unspecified_ip_and_auto_detection_flow() -> Result<Option<IpAddr>, Error> {
    if confirm_unspecified_ip_usage()? {
        Ok(Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)))
    } else {
        ip_auto_detection_flow()
    }
}

pub fn ip_auto_detection_flow() -> Result<Option<IpAddr>, Error> {
    let ip_addr = if confirm_ip_auto_detection()? {
        innernet_publicip::get_any(Preference::Ipv4)
    } else {
        None
    };

    Ok(ip_addr)
}

fn confirm_ip_auto_detection() -> Result<bool, Error> {
    let answer = Confirm::with_theme(&*THEME)
        .wait_for_newline(true)
        .with_prompt("Auto-detect external endpoint IP address (via DNS query to 9.9.9.9)?")
        .interact()?;

    Ok(answer)
}

fn confirm_unspecified_ip_usage() -> Result<bool, Error> {
    log::info!(
        "Note: use unspecified IP address (all zeros) if you do not have a fixed global IP but the \
         port is forwarded." 
    );
    let answer = Confirm::with_theme(&*THEME)
        .wait_for_newline(true)
        .with_prompt("Use an unspecified IP address and override just the port?")
        .interact()?;

    Ok(answer)
}

pub fn input_external_endpoint(
    external_ip: Option<IpAddr>,
    listen_port: u16,
) -> Result<Endpoint, Error> {
    let endpoint = input(
        "External endpoint",
        match external_ip {
            Some(ip) => Prefill::Editable(SocketAddr::new(ip, listen_port).to_string()),
            None => Prefill::None,
        },
    )?;

    Ok(endpoint)
}
