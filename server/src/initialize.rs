use crate::{
    db::{self, DatabaseCidr, DatabasePeer},
    ConfigFile, Interface, Path, ServerConfig,
};
use anyhow::{anyhow, Error};
use clap::Parser;
use colored::Colorize;
use dialoguer::{theme::ColorfulTheme, Input};
use indoc::printdoc;
use innernet_shared::{
    prompts, CidrContents, Endpoint, IpNetExt, PeerContents, PERSISTENT_KEEPALIVE_INTERVAL_SECS,
};
use ipnet::IpNet;
use rusqlite::{params, Connection};
use std::net::{IpAddr, SocketAddr};
use wireguard_control::KeyPair;

fn create_database<P: AsRef<Path>>(
    database_path: P,
) -> Result<Connection, Box<dyn std::error::Error>> {
    let conn = Connection::open(&database_path)?;
    conn.pragma_update(None, "foreign_keys", 1)?;
    // TODO(strohel): set stricter permissions on the db file?
    conn.execute(db::peer::CREATE_TABLE_SQL, params![])?;
    conn.execute(db::association::CREATE_TABLE_SQL, params![])?;
    conn.execute(db::cidr::CREATE_TABLE_SQL, params![])?;
    conn.pragma_update(None, "user_version", db::CURRENT_VERSION)?;
    log::debug!("set database version to db::CURRENT_VERSION");

    Ok(conn)
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Parser)]
pub struct InitializeOpts {
    /// The network name (ex: evilcorp)
    #[clap(long)]
    pub network_name: Option<Interface>,

    /// The network CIDR (ex: 10.42.0.0/16)
    #[clap(long)]
    pub network_cidr: Option<IpNet>,

    /// This server's external endpoint (ex: 100.100.100.100:51820)
    #[clap(long, conflicts_with = "auto_external_endpoint")]
    pub external_endpoint: Option<Endpoint>,

    /// This server's IPv6 external endpoint, used by clients that cannot reach the
    /// external endpoint (ex: [2001:db8::1]:51820)
    #[clap(long, conflicts_with = "auto_external_endpoint", value_parser = Endpoint::parse_ipv6)]
    pub external_endpoint_v6: Option<Endpoint>,

    /// Auto-resolve external endpoints
    #[clap(long = "auto-external-endpoint")]
    pub auto_external_endpoint: bool,

    /// Port to listen on (for the WireGuard interface)
    #[clap(long)]
    pub listen_port: Option<u16>,
}

struct DbInitData {
    network_name: String,
    network_cidr: IpNet,
    server_cidr: IpNet,
    our_ip: IpAddr,
    public_key_base64: String,
    endpoint: Endpoint,
    endpoint_v6: Option<Endpoint>,
}

fn populate_database(conn: &Connection, db_init_data: DbInitData) -> Result<(), Error> {
    const SERVER_NAME: &str = "innernet-server";

    let root_cidr = DatabaseCidr::create(
        conn,
        CidrContents {
            name: db_init_data.network_name.clone(),
            cidr: db_init_data.network_cidr,
            parent: None,
        },
    )
    .map_err(|_| anyhow!("failed to create root CIDR"))?;

    let server_cidr = DatabaseCidr::create(
        conn,
        CidrContents {
            name: SERVER_NAME.into(),
            cidr: db_init_data.server_cidr,
            parent: Some(root_cidr.id),
        },
    )
    .map_err(|_| anyhow!("failed to create innernet-server CIDR"))?;

    let _me = DatabasePeer::create(
        conn,
        PeerContents {
            name: SERVER_NAME.parse().map_err(|e: &str| anyhow!(e))?,
            ip: db_init_data.our_ip,
            cidr_id: server_cidr.id,
            public_key: db_init_data.public_key_base64,
            endpoint: Some(db_init_data.endpoint),
            is_admin: true,
            is_disabled: false,
            is_redeemed: true,
            persistent_keepalive_interval: Some(PERSISTENT_KEEPALIVE_INTERVAL_SECS),
            invite_expires: None,
            candidates: db_init_data.endpoint_v6.into_iter().collect(),
        },
    )
    .map_err(|_| anyhow!("failed to create innernet peer."))?;

    Ok(())
}

pub fn init_wizard(conf: &ServerConfig, opts: InitializeOpts) -> Result<(), Error> {
    let theme = ColorfulTheme::default();

    innernet_shared::ensure_dirs_exist(&[conf.config_dir(), conf.database_dir()]).map_err(
        |_| {
            anyhow!(
                "Failed to create config and database directories {}",
                "(are you not running as root?)".bold()
            )
        },
    )?;
    printdoc!(
        "\nTime to setup your innernet network.

        Your network name can be any hostname-valid string, i.e. \"evilcorp\", and
        your network CIDR should be in the RFC1918 IPv4 (10/8, 172.16/12, or 192.168/16), 
        or RFC4193 IPv6 (fd00::/8) ranges.

        The external endpoint specified is a <host>:<port> string that is the address clients
        will connect to. An optional IPv6 external endpoint is used by clients that cannot
        reach the external endpoint. It's up to you to forward/open ports in your
        routers/firewalls as needed.

        For more usage instructions, see https://github.com/tonarino/innernet#usage
        \n"
    );

    let name: Interface = if let Some(name) = opts.network_name {
        name
    } else {
        Input::with_theme(&theme)
            .with_prompt("Network name")
            .interact()?
    };

    let root_cidr: IpNet = if let Some(cidr) = opts.network_cidr {
        cidr
    } else {
        Input::with_theme(&theme)
            .with_prompt("Network CIDR")
            .with_initial_text("10.42.0.0/16")
            // TODO(mbernat): workaround for https://github.com/console-rs/dialoguer/issues/330
            .interact_text()?
    };

    let listen_port: u16 = if let Some(listen_port) = opts.listen_port {
        listen_port
    } else {
        Input::with_theme(&theme)
            .with_prompt("Listen port")
            .default(51820)
            .interact()
            .map_err(|_| anyhow!("failed to get listen port."))?
    };

    log::info!("listen port: {}", listen_port);

    // IPv4 is the primary endpoint; IPv6 is primary only when no IPv4 address is found.
    let to_endpoint = |ip: IpAddr| -> Endpoint { SocketAddr::new(ip, listen_port).into() };
    let detect_endpoints = || match innernet_publicip::get_both() {
        (Some(v4), v6) => (
            Some(to_endpoint(v4.into())),
            v6.map(|ip| to_endpoint(ip.into())),
        ),
        (None, v6) => (v6.map(|ip| to_endpoint(ip.into())), None),
    };
    let (endpoint, endpoint_v6) = if opts.auto_external_endpoint {
        let (endpoint, endpoint_v6) = detect_endpoints();
        (
            endpoint.ok_or_else(|| anyhow!("couldn't get external IP"))?,
            endpoint_v6,
        )
    } else if let Some(endpoint) = opts.external_endpoint {
        (endpoint, opts.external_endpoint_v6)
    } else {
        let (detected, detected_v6) = if prompts::confirm_ip_auto_detection()? {
            detect_endpoints()
        } else {
            (None, None)
        };
        let endpoint = prompts::input_external_endpoint(detected)?;
        let endpoint_v6 = match opts.external_endpoint_v6 {
            Some(endpoint_v6) => Some(endpoint_v6),
            None => prompts::input_external_endpoint_v6(detected_v6)?,
        };
        (endpoint, endpoint_v6)
    };

    let our_ip = root_cidr
        .hosts()
        .find(|ip| root_cidr.is_assignable(ip))
        .unwrap();
    let config_path = conf.config_path(&name);
    let our_keypair = KeyPair::generate();

    let config = ConfigFile {
        private_key: our_keypair.private.to_base64(),
        listen_port,
        address: our_ip,
        network_cidr_prefix: root_cidr.prefix_len(),
    };
    config.write_to_path(config_path)?;

    let db_init_data = DbInitData {
        network_name: name.to_string(),
        network_cidr: root_cidr,
        server_cidr: IpNet::new(our_ip, root_cidr.max_prefix_len())?,
        our_ip,
        public_key_base64: our_keypair.public.to_base64(),
        endpoint,
        endpoint_v6,
    };

    // TODO(bschwind) - Clean up the config file and database
    //                  if any errors occur in these init calls.

    let database_path = conf.database_path(&name);
    let conn = create_database(&database_path).map_err(|_| {
        anyhow!(
            "failed to create database {}",
            "(are you not running as root?)".bold()
        )
    })?;
    populate_database(&conn, db_init_data)?;

    println!(
        "{} Created database at {}\n",
        "[*]".dimmed(),
        database_path.to_string_lossy().bold()
    );
    printdoc!(
        "
        {star} Setup finished.

            Network {interface} has been {created}, but it's not started yet!

            Your new network starts with only one peer: this innernet server. Next,
            you'll want to create additional CIDRs and peers using the commands:

                {wg_manage_server} {add_cidr} {interface}, and
                {wg_manage_server} {add_peer} {interface}
            
            See https://github.com/tonarino/innernet for more detailed instruction
            on designing your network.
        
            When you're ready to start the network, you can auto-start the server:
            
                {systemctl_enable}{interface}

    ",
        star = "[*]".dimmed(),
        interface = name.to_string().yellow(),
        created = "created".green(),
        wg_manage_server = "innernet-server".yellow(),
        add_cidr = "add-cidr".yellow(),
        add_peer = "add-peer".yellow(),
        systemctl_enable = "systemctl enable --now innernet-server@".yellow(),
    );

    Ok(())
}
