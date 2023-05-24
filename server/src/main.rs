use anyhow::{anyhow, bail};
use clap::{AppSettings, IntoApp, Parser, Subcommand};
use colored::*;
use dialoguer::Confirm;
use hyper::{http, server::conn::AddrStream, Body, Request, Response};
use ipnet::IpNet;
use parking_lot::{Mutex, RwLock};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use shared::{
    get_local_addrs, Cidr, CommonCommand, Endpoint, InterfaceApi, IoErrorContext, NetworkOpts,
    Peer, PeerContents, INNERNET_PUBKEY_HEADER,
};
use std::{
    collections::{HashMap, VecDeque},
    convert::TryInto,
    env,
    fs::File,
    io::prelude::*,
    net::{IpAddr, SocketAddr, TcpListener},
    ops::Deref,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use subtle::ConstantTimeEq;
use wireguard_control::{Backend, Device, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder};

pub mod api;
pub mod db;
pub mod error;
#[cfg(test)]
mod test;
pub mod util;

mod initialize;

use db::{DatabaseAssociation, DatabaseCidr, DatabasePeer};
pub use error::ServerError;
use initialize::InitializeOpts;
use shared::{prompts, wg, Error, Interface};
pub use shared::{Association, AssociationContents};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Parser)]
#[clap(name = "innernet-server", author, version, about)]
#[clap(global_setting(AppSettings::DeriveDisplayOrder))]
struct Opts {
    #[clap(subcommand)]
    command: Command,

    #[clap(short, long, default_value = "/etc/innernet-server")]
    config_dir: PathBuf,

    #[clap(short, long, default_value = "/var/lib/innernet-server")]
    data_dir: PathBuf,

    #[clap(flatten)]
    network: NetworkOpts,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new network.
    #[clap(alias = "init")]
    New {
        #[clap(flatten)]
        opts: InitializeOpts,
    },

    /// Permanently uninstall a created network, rendering it unusable. Use with care.
    Uninstall {
        interface: Interface,

        /// Bypass confirmation
        #[clap(long)]
        yes: bool,
    },

    /// Serve the coordinating server for an existing network.
    Serve {
        interface: Interface,

        #[clap(flatten)]
        network: NetworkOpts,
    },

    /// Generate shell completion scripts
    Completions {
        #[clap(arg_enum)]
        shell: clap_complete::Shell,
    },

    #[clap(flatten)]
    Common(CommonCommand),
}

pub type Db = Arc<Mutex<Connection>>;
pub type Endpoints = Arc<RwLock<HashMap<String, SocketAddr>>>;

#[derive(Clone)]
pub struct Context {
    pub db: Db,
    pub endpoints: Arc<RwLock<HashMap<String, SocketAddr>>>,
    pub interface: InterfaceName,
    pub backend: Backend,
    pub public_key: Key,
}

pub struct Session {
    pub context: Context,
    pub peer: DatabasePeer,
}

impl Session {
    pub fn admin_capable(&self) -> bool {
        self.peer.is_admin && self.user_capable()
    }

    pub fn user_capable(&self) -> bool {
        !self.peer.is_disabled && self.peer.is_redeemed
    }

    pub fn redeemable(&self) -> bool {
        !self.peer.is_disabled && !self.peer.is_redeemed
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct ConfigFile {
    /// The server's WireGuard key
    pub private_key: String,

    /// The listen port of the server
    pub listen_port: u16,

    /// The internal WireGuard IP address assigned to the server
    pub address: IpAddr,

    /// The CIDR prefix of the WireGuard network
    pub network_cidr_prefix: u8,
}

impl ConfigFile {
    pub fn write_to_path<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let mut invitation_file = File::create(&path).with_path(&path)?;
        shared::chmod(&invitation_file, 0o600)?;
        invitation_file
            .write_all(toml::to_string(self).unwrap().as_bytes())
            .with_path(path)?;
        Ok(())
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let path = path.as_ref();
        let file = File::open(path).with_path(path)?;
        if shared::chmod(&file, 0o600)? {
            println!(
                "{} updated permissions for {} to 0600.",
                "[!]".yellow(),
                path.display()
            );
        }
        Ok(toml::from_slice(&std::fs::read(path).with_path(path)?)?)
    }
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
}

impl ServerConfig {
    pub fn new(config_dir: PathBuf, data_dir: PathBuf) -> Self {
        Self {
            config_dir,
            data_dir,
        }
    }

    fn database_dir(&self) -> &Path {
        &self.data_dir
    }

    fn database_path(&self, interface: &InterfaceName) -> PathBuf {
        PathBuf::new()
            .join(self.database_dir())
            .join(interface.to_string())
            .with_extension("db")
    }

    fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    fn config_path(&self, interface: &InterfaceName) -> PathBuf {
        PathBuf::new()
            .join(self.config_dir())
            .join(interface.to_string())
            .with_extension("conf")
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::var_os("RUST_LOG").is_none() {
        // Set some default log settings.
        env::set_var("RUST_LOG", "warn,warp=info,wg_manage_server=info");
    }

    pretty_env_logger::init();
    let opts = Opts::parse();

    if unsafe { libc::getuid() } != 0 && !matches!(opts.command, Command::Completions { .. }) {
        return Err("innernet-server must run as root.".into());
    }

    let conf = ServerConfig::new(opts.config_dir, opts.data_dir);

    match opts.command {
        Command::New { opts } => {
            if let Err(e) = initialize::init_wizard(&conf, opts) {
                eprintln!("{}: {}.", "creation failed".red(), e);
                std::process::exit(1);
            }
        },
        Command::Uninstall { interface, yes } => uninstall(&interface, &conf, opts.network, yes)?,
        Command::Serve {
            interface,
            network: routing,
        } => serve(*interface, &conf, routing).await?,
        Command::Completions { shell } => {
            let mut app = Opts::command();
            let app_name = app.get_name().to_string();
            clap_complete::generate(shell, &mut app, app_name, &mut std::io::stdout());
            std::process::exit(0);
        },
        Command::Common(common_command) => {
            let interface = common_command.interface();
            let config = ConfigFile::from_file(conf.config_path(&interface))?;
            let mut db = ServerInterfaceApi {
                conn: open_database_connection(interface, &conf)?,
                interface: interface.clone(),
                server_endpoint: SocketAddr::new(config.address, config.listen_port),
                network: &opts.network,
            };
            common_command.execute(&mut db)?;
        },
    }

    Ok(())
}

fn open_database_connection(
    interface: &InterfaceName,
    conf: &ServerConfig,
) -> Result<rusqlite::Connection, Error> {
    let database_path = conf.database_path(interface);
    if !Path::new(&database_path).exists() {
        bail!(
            "no database file found at {}",
            database_path.to_string_lossy()
        );
    }

    let conn = Connection::open(&database_path)?;
    // Foreign key constraints aren't on in SQLite by default. Enable.
    conn.pragma_update(None, "foreign_keys", 1)?;
    db::auto_migrate(&conn)?;
    Ok(conn)
}

struct ServerInterfaceApi<'a> {
    conn: rusqlite::Connection,
    interface: Interface,
    server_endpoint: SocketAddr,
    network: &'a NetworkOpts,
}

impl<'a> InterfaceApi for ServerInterfaceApi<'a> {
    fn peers(&mut self) -> anyhow::Result<Vec<Peer>> {
        let rows = DatabasePeer::list(&self.conn)?;
        Ok(rows.into_iter().map(|dp| dp.inner).collect())
    }

    fn cidrs(&mut self) -> anyhow::Result<Vec<Cidr>> {
        DatabaseCidr::list(&self.conn).map_err(Into::into)
    }

    fn add_peer(&mut self, peer_request: PeerContents) -> anyhow::Result<Peer> {
        let peer = DatabasePeer::create(&self.conn, peer_request)?;
        if cfg!(not(test)) && Device::get(&self.interface, self.network.backend).is_ok() {
            // Update the current WireGuard interface with the new peers.
            DeviceUpdate::new()
                .add_peer(PeerConfigBuilder::from(&*peer))
                .apply(&self.interface, self.network.backend)
                .map_err(|_| ServerError::WireGuard)?;

            println!("adding to WireGuard interface: {}", &*peer);
        }

        Ok(peer.inner)
    }

    fn rename_peer(
        &mut self,
        peer_request: PeerContents,
        old_name: shared::Hostname,
    ) -> anyhow::Result<()> {
        let mut db_peer = DatabasePeer::list(&self.conn)?
            .into_iter()
            .find(|p| p.name == old_name)
            .ok_or_else(|| anyhow!("Peer not found."))?;
        db_peer.update(&self.conn, peer_request)?;
        Ok(())
    }

    fn enable_or_disable_peer(&mut self, peer: Peer, enable: bool) -> anyhow::Result<()> {
        let mut db_peer = DatabasePeer::get(&self.conn, peer.id)?;
        db_peer.update(
            &self.conn,
            PeerContents {
                is_disabled: !enable,
                ..peer.contents.clone()
            },
        )?;

        if enable {
            DeviceUpdate::new()
                .add_peer(db_peer.deref().into())
                .apply(&self.interface, self.network.backend)
                .map_err(|_| ServerError::WireGuard)?;
        } else {
            let public_key =
                Key::from_base64(&peer.public_key).map_err(|_| ServerError::WireGuard)?;

            DeviceUpdate::new()
                .remove_peer_by_key(&public_key)
                .apply(&self.interface, self.network.backend)
                .map_err(|_| ServerError::WireGuard)?;
        }

        Ok(())
    }

    fn add_cidr(&mut self, cidr_request: shared::CidrContents) -> anyhow::Result<Cidr> {
        DatabaseCidr::create(&self.conn, cidr_request).map_err(Into::into)
    }

    fn delete_cidr(&mut self, cidr_id: i64) -> anyhow::Result<()> {
        DatabaseCidr::delete(&self.conn, cidr_id).map_err(Into::into)
    }

    fn associations(&mut self) -> anyhow::Result<Vec<Association>> {
        DatabaseAssociation::list(&self.conn).map_err(Into::into)
    }

    fn add_association(&mut self, association_request: AssociationContents) -> anyhow::Result<()> {
        DatabaseAssociation::create(&self.conn, association_request)?;
        Ok(())
    }

    fn delete_association(&mut self, association: &Association) -> anyhow::Result<()> {
        DatabaseAssociation::delete(&self.conn, association.id).map_err(Into::into)
    }

    fn interface(&self) -> &Interface {
        &self.interface
    }

    fn server_endpoint(&self) -> SocketAddr {
        self.server_endpoint
    }
}

fn uninstall(
    interface: &InterfaceName,
    conf: &ServerConfig,
    network: NetworkOpts,
    yes: bool,
) -> Result<(), Error> {
    if yes
        || Confirm::with_theme(&*prompts::THEME)
            .with_prompt(&format!(
                "Permanently delete network \"{}\"?",
                interface.as_str_lossy().yellow()
            ))
            .default(false)
            .interact()?
    {
        println!("{} bringing down interface (if up).", "[*]".dimmed());
        wg::down(interface, network.backend).ok();
        let config = conf.config_path(interface);
        let data = conf.database_path(interface);
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

fn spawn_endpoint_refresher(interface: InterfaceName, network: NetworkOpts) -> Endpoints {
    let endpoints = Arc::new(RwLock::new(HashMap::new()));
    tokio::task::spawn({
        let endpoints = endpoints.clone();
        async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                if let Ok(info) = Device::get(&interface, network.backend) {
                    for peer in info.peers {
                        if let Some(endpoint) = peer.config.endpoint {
                            endpoints
                                .write()
                                .insert(peer.config.public_key.to_base64(), endpoint);
                        }
                    }
                }
            }
        }
    });
    endpoints
}

fn spawn_expired_invite_sweeper(db: Db) {
    tokio::task::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            match DatabasePeer::delete_expired_invites(&db.lock()) {
                Ok(deleted) if deleted > 0 => {
                    log::info!("Deleted {} expired peer invitations.", deleted)
                },
                Err(e) => log::error!("Failed to delete expired peer invitations: {}", e),
                _ => {},
            }
        }
    });
}

async fn serve(
    interface: InterfaceName,
    conf: &ServerConfig,
    network: NetworkOpts,
) -> Result<(), Error> {
    let config = ConfigFile::from_file(conf.config_path(&interface))?;
    log::debug!("opening database connection...");
    let conn = open_database_connection(&interface, conf)?;

    let mut peers = DatabasePeer::list(&conn)?;
    log::debug!("peers listed...");
    let peer_configs = peers
        .iter()
        .map(|peer| peer.deref().into())
        .collect::<Vec<PeerConfigBuilder>>();

    log::info!("bringing up interface.");
    wg::up(
        &interface,
        &config.private_key,
        IpNet::new(config.address, config.network_cidr_prefix)?,
        Some(config.listen_port),
        None,
        network,
    )?;

    DeviceUpdate::new()
        .add_peers(&peer_configs)
        .apply(&interface, network.backend)?;

    log::info!("{} peers added to wireguard interface.", peers.len());

    let candidates: Vec<Endpoint> = get_local_addrs()?
        .map(|addr| SocketAddr::from((addr, config.listen_port)).into())
        .collect();
    let num_candidates = candidates.len();
    let myself = peers
        .iter_mut()
        .find(|peer| peer.ip == config.address)
        .expect("Couldn't find server peer in peer list.");
    myself.update(
        &conn,
        PeerContents {
            candidates,
            ..myself.contents.clone()
        },
    )?;

    log::info!(
        "{} local candidates added to server peer config.",
        num_candidates
    );

    let public_key = wireguard_control::Key::from_base64(&config.private_key)?.get_public();
    let db = Arc::new(Mutex::new(conn));
    let endpoints = spawn_endpoint_refresher(interface, network);
    spawn_expired_invite_sweeper(db.clone());

    let context = Context {
        db,
        endpoints,
        interface,
        public_key,
        backend: network.backend,
    };

    log::info!("innernet-server {} starting.", VERSION);

    let listener = get_listener((config.address, config.listen_port).into(), &interface)?;

    let make_svc = hyper::service::make_service_fn(move |socket: &AddrStream| {
        let remote_addr = socket.remote_addr();
        let context = context.clone();
        async move {
            Ok::<_, http::Error>(hyper::service::service_fn(move |req: Request<Body>| {
                log::debug!("{} - {} {}", &remote_addr, req.method(), req.uri());
                hyper_service(req, context.clone(), remote_addr)
            }))
        }
    });

    let server = hyper::Server::from_tcp(listener)?.serve(make_svc);

    server.await?;

    Ok(())
}

/// This function differs per OS, because different operating systems have
/// opposing characteristics when binding to a specific IP address.
/// On Linux, binding to a specific local IP address does *not* bind it to
/// that IP's interface, allowing for spoofing attacks.
///
/// See https://github.com/tonarino/innernet/issues/26 for more details.
#[cfg(target_os = "linux")]
fn get_listener(addr: SocketAddr, interface: &InterfaceName) -> Result<TcpListener, Error> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let sock = socket2::Socket::from(listener);
    sock.bind_device(Some(interface.as_str_lossy().as_bytes()))?;
    Ok(sock.into())
}

/// BSD-likes do seem to bind to an interface when binding to an IP,
/// according to the internet, but we may want to explicitly use
/// IP_BOUND_IF in the future regardless. This isn't currently in
/// the socket2 crate however, so we aren't currently using it.
///
/// See https://github.com/tonarino/innernet/issues/26 for more details.
#[cfg(not(target_os = "linux"))]
fn get_listener(addr: SocketAddr, _interface: &InterfaceName) -> Result<TcpListener, Error> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

pub(crate) async fn hyper_service(
    req: Request<Body>,
    context: Context,
    remote_addr: SocketAddr,
) -> Result<Response<Body>, http::Error> {
    // Break the path into components.
    let components: VecDeque<_> = req
        .uri()
        .path()
        .trim_start_matches('/')
        .split('/')
        .map(String::from)
        .collect();

    routes(req, context, remote_addr, components)
        .await
        .or_else(TryInto::try_into)
}

async fn routes(
    req: Request<Body>,
    context: Context,
    remote_addr: SocketAddr,
    mut components: VecDeque<String>,
) -> Result<Response<Body>, ServerError> {
    // Must be "/v1/[something]"
    if components.pop_front().as_deref() != Some("v1") {
        Err(ServerError::NotFound)
    } else {
        let session = get_session(&req, context, remote_addr.ip())?;
        let component = components.pop_front();
        match component.as_deref() {
            Some("user") => api::user::routes(req, components, session).await,
            Some("admin") => api::admin::routes(req, components, session).await,
            _ => Err(ServerError::NotFound),
        }
    }
}

fn get_session(
    req: &Request<Body>,
    context: Context,
    addr: IpAddr,
) -> Result<Session, ServerError> {
    let pubkey = req
        .headers()
        .get(INNERNET_PUBKEY_HEADER)
        .ok_or(ServerError::Unauthorized)?;
    let pubkey = pubkey.to_str().map_err(|_| ServerError::Unauthorized)?;
    let pubkey = Key::from_base64(pubkey).map_err(|_| ServerError::Unauthorized)?;
    if pubkey
        .as_bytes()
        .ct_eq(context.public_key.as_bytes())
        .into()
    {
        let peer = DatabasePeer::get_from_ip(&context.db.lock(), addr).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => ServerError::Unauthorized,
            e => ServerError::Database(e),
        })?;

        if !peer.is_disabled {
            return Ok(Session { context, peer });
        }
    }

    Err(ServerError::Unauthorized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test;
    use anyhow::Result;
    use hyper::StatusCode;
    use std::path::Path;

    #[test]
    fn test_init_wizard() -> Result<(), Error> {
        // This runs init_wizard().
        let server = test::Server::new()?;

        assert!(Path::new(&server.wg_conf_path()).exists());

        Ok(())
    }

    #[tokio::test]
    async fn test_with_session_disguised_with_headers() -> Result<(), Error> {
        let server = test::Server::new()?;

        let path = if cfg!(feature = "v6-test") {
            format!("http://[{}]/v1/admin/peers", test::WG_MANAGE_PEER_IP)
        } else {
            format!("http://{}/v1/admin/peers", test::WG_MANAGE_PEER_IP)
        };
        let req = Request::builder()
            .uri(path)
            .header("Forwarded", format!("for={}", test::ADMIN_PEER_IP))
            .header("X-Forwarded-For", test::ADMIN_PEER_IP)
            .header("X-Real-IP", test::ADMIN_PEER_IP)
            .body(Body::empty())
            .unwrap();

        // Request from an unknown IP, trying to disguise as an admin using HTTP headers.
        let res = if cfg!(feature = "v6-test") {
            server.raw_request("fd00:1337::1337", req).await
        } else {
            server.raw_request("10.80.80.80", req).await
        };

        // addr::remote() filter only look at remote_addr from TCP socket.
        // HTTP headers are not considered. This also means that innernet
        // server would not function behind an HTTP proxy.
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[tokio::test]
    async fn test_incorrect_public_key() -> Result<(), Error> {
        let server = test::Server::new()?;

        let key = Key::generate_private().get_public();

        let path = if cfg!(feature = "v6-test") {
            format!("http://[{}]/v1/admin/peers", test::WG_MANAGE_PEER_IP)
        } else {
            format!("http://{}/v1/admin/peers", test::WG_MANAGE_PEER_IP)
        };
        // Request from an unknown IP, trying to disguise as an admin using HTTP headers.
        let req = Request::builder()
            .uri(path)
            .header(shared::INNERNET_PUBKEY_HEADER, key.to_base64())
            .body(Body::empty())
            .unwrap();
        let res = if cfg!(feature = "v6-test") {
            server.raw_request("fd00:1337::1337", req).await
        } else {
            server.raw_request("10.80.80.80", req).await
        };

        // addr::remote() filter only look at remote_addr from TCP socket.
        // HTTP headers are not considered. This also means that innernet
        // server would not function behind an HTTP proxy.
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[tokio::test]
    async fn test_unparseable_public_key() -> Result<(), Error> {
        let server = test::Server::new()?;

        let path = if cfg!(feature = "v6-test") {
            format!("http://[{}]/v1/admin/peers", test::WG_MANAGE_PEER_IP)
        } else {
            format!("http://{}/v1/admin/peers", test::WG_MANAGE_PEER_IP)
        };
        let req = Request::builder()
            .uri(path)
            .header(shared::INNERNET_PUBKEY_HEADER, "!!!")
            .body(Body::empty())
            .unwrap();
        let res = if cfg!(feature = "v6-test") {
            server.raw_request("fd00:1337::1337", req).await
        } else {
            server.raw_request("10.80.80.80", req).await
        };

        // addr::remote() filter only look at remote_addr from TCP socket.
        // HTTP headers are not considered. This also means that innernet
        // server would not function behind an HTTP proxy.
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }
}
