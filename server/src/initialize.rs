use crate::*;
use db::DatabaseCidr;
use dialoguer::{theme::ColorfulTheme, Input};
use indoc::printdoc;
use rusqlite::{params, Connection};
use shared::{
    prompts::{self, hostname_validator},
    CidrContents, Endpoint, PeerContents, PERSISTENT_KEEPALIVE_INTERVAL_SECS,
};
use wgctrl::KeyPair;

fn create_database<P: AsRef<Path>>(
    database_path: P,
) -> Result<Connection, Box<dyn std::error::Error>> {
    let conn = Connection::open(&database_path)?;
    conn.pragma_update(None, "foreign_keys", &1)?;
    conn.execute(db::peer::CREATE_TABLE_SQL, params![])?;
    conn.execute(db::association::CREATE_TABLE_SQL, params![])?;
    conn.execute(db::cidr::CREATE_TABLE_SQL, params![])?;
    Ok(conn)
}

#[derive(Debug, Default, Clone, PartialEq, StructOpt)]
pub struct InitializeOpts {
    /// The network name (ex: evilcorp)
    #[structopt(long)]
    pub network_name: Option<String>,

    /// The network CIDR (ex: 10.42.0.0/16)
    #[structopt(long)]
    pub network_cidr: Option<IpNetwork>,

    /// This server's external endpoint (ex: 100.100.100.100:51820)
    #[structopt(long, conflicts_with = "auto-external-endpoint")]
    pub external_endpoint: Option<Endpoint>,

    /// Auto-resolve external endpoint
    #[structopt(long = "auto-external-endpoint")]
    pub auto_external_endpoint: bool,

    /// Port to listen on (for the WireGuard interface)
    #[structopt(long)]
    pub listen_port: Option<u16>,
}

struct DbInitData {
    network_name: String,
    network_cidr: IpNetwork,
    server_cidr: IpNetwork,
    our_ip: IpAddr,
    public_key_base64: String,
    endpoint: Endpoint,
}

fn populate_database(conn: &Connection, db_init_data: DbInitData) -> Result<(), Error> {
    const SERVER_NAME: &str = "innernet-server";

    let root_cidr = DatabaseCidr::create(
        &conn,
        CidrContents {
            name: db_init_data.network_name.clone(),
            cidr: db_init_data.network_cidr,
            parent: None,
        },
    )
    .map_err(|_| "failed to create root CIDR".to_string())?;

    let server_cidr = DatabaseCidr::create(
        &conn,
        CidrContents {
            name: SERVER_NAME.into(),
            cidr: db_init_data.server_cidr,
            parent: Some(root_cidr.id),
        },
    )
    .map_err(|_| "failed to create innernet-server CIDR".to_string())?;

    let _me = DatabasePeer::create(
        &conn,
        PeerContents {
            name: SERVER_NAME.into(),
            ip: db_init_data.our_ip,
            cidr_id: server_cidr.id,
            public_key: db_init_data.public_key_base64,
            endpoint: Some(db_init_data.endpoint),
            is_admin: true,
            is_disabled: false,
            is_redeemed: true,
            persistent_keepalive_interval: Some(PERSISTENT_KEEPALIVE_INTERVAL_SECS),
            invite_expires: None,
        },
    )
    .map_err(|_| "failed to create innernet peer.".to_string())?;

    Ok(())
}

pub fn init_wizard(conf: &ServerConfig, opts: InitializeOpts) -> Result<(), Error> {
    let theme = ColorfulTheme::default();

    shared::ensure_dirs_exist(&[conf.config_dir(), conf.database_dir()]).map_err(|_| {
        format!(
            "Failed to create config and database directories {}",
            "(are you not running as root?)".bold()
        )
    })?;

    let name: String = if let Some(name) = opts.network_name {
        name
    } else {
        println!("Here you'll specify the network CIDR, which will encompass the entire network.");
        Input::with_theme(&theme)
            .with_prompt("Network name")
            .validate_with(hostname_validator)
            .interact()?
    };

    let root_cidr: IpNetwork = if let Some(cidr) = opts.network_cidr {
        cidr
    } else {
        Input::with_theme(&theme)
            .with_prompt("Network CIDR")
            .with_initial_text("10.42.0.0/16")
            .interact()?
    };

    // This probably won't error because of the `hostname_validator` regex.
    let name = name.parse()?;

    let endpoint: Endpoint = if let Some(endpoint) = opts.external_endpoint {
        endpoint
    } else {
        let external_ip: Option<IpAddr> = ureq::get("http://4.icanhazip.com")
            .call()
            .ok()
            .map(|res| res.into_string().ok())
            .flatten()
            .map(|body| body.trim().to_string())
            .and_then(|body| body.parse().ok());

        if opts.auto_external_endpoint {
            let ip = external_ip.ok_or("couldn't get external IP")?;
            SocketAddr::new(ip, 51820).into()
        } else {
            prompts::ask_endpoint(external_ip)?
        }
    };

    let listen_port: u16 = if let Some(listen_port) = opts.listen_port {
        listen_port
    } else {
        Input::with_theme(&theme)
            .with_prompt("Listen port")
            .default(51820)
            .interact()
            .map_err(|_| "failed to get listen port.")?
    };

    let our_ip = root_cidr
        .iter()
        .find(|ip| root_cidr.is_assignable(*ip))
        .unwrap();
    let server_cidr = IpNetwork::new(our_ip, root_cidr.max_prefix())?;
    let config_path = conf.config_path(&name);
    let our_keypair = KeyPair::generate();

    let config = ConfigFile {
        private_key: our_keypair.private.to_base64(),
        listen_port,
        address: our_ip,
        network_cidr_prefix: root_cidr.prefix(),
    };
    config.write_to_path(&config_path)?;

    let db_init_data = DbInitData {
        network_name: name.to_string(),
        network_cidr: root_cidr,
        server_cidr,
        our_ip,
        public_key_base64: our_keypair.public.to_base64(),
        endpoint,
    };

    // TODO(bschwind) - Clean up the config file and database
    //                  if any errors occur in these init calls.

    let database_path = conf.database_path(&name);
    let conn = create_database(&database_path).map_err(|_| {
        format!(
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

            Network {interface} has been {created}!

            Your new network starts with only one peer: this innernet server. Next,
            you'll want to create additional CIDRs and peers using the commands:

                {wg_manage_server} {add_cidr} {interface}, and
                {wg_manage_server} {add_peer} {interface}
            
            See the documentation for more detailed instruction on designing your network.
        
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
