use colored::*;
use error::handle_rejection;
use hyper::{server::conn::AddrStream, Body, Request};
use indoc::printdoc;
use ipnetwork::IpNetwork;
use parking_lot::Mutex;
use rusqlite::Connection;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use shared::{IoErrorContext, INNERNET_PUBKEY_HEADER};
use std::{
    convert::Infallible,
    env,
    fs::File,
    io::prelude::*,
    net::{IpAddr, SocketAddr, TcpListener},
    ops::Deref,
    path::{Path, PathBuf},
    sync::Arc,
};
use structopt::StructOpt;
use subtle::ConstantTimeEq;
use warp::{filters, Filter};
use wgctrl::{DeviceConfigBuilder, DeviceInfo, InterfaceName, Key, PeerConfigBuilder};

pub mod api;
pub mod db;
pub mod endpoints;
pub mod error;
#[cfg(test)]
mod test;

mod initialize;

use db::{DatabaseCidr, DatabasePeer};
pub use endpoints::Endpoints;
pub use error::ServerError;
use shared::{prompts, wg, CidrTree, Error, Interface, SERVER_CONFIG_DIR, SERVER_DATABASE_DIR};
pub use shared::{Association, AssociationContents};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, StructOpt)]
#[structopt(name = "innernet-server", about)]
struct Opt {
    #[structopt(subcommand)]
    command: Command,
}

#[derive(Debug, StructOpt)]
enum Command {
    /// Create a new network.
    #[structopt(alias = "init")]
    New,

    /// Serve the coordinating server for an existing network.
    Serve { interface: Interface },

    /// Add a peer to an existing network.
    AddPeer { interface: Interface },

    /// Add a new CIDR to an existing network.
    AddCidr { interface: Interface },
}

pub type Db = Arc<Mutex<Connection>>;

#[derive(Clone)]
pub struct Context {
    pub db: Db,
    pub endpoints: Arc<Endpoints>,
    pub interface: InterfaceName,
    pub public_key: Key,
}

pub struct Session {
    pub context: Context,
    pub peer: DatabasePeer,
}

pub struct AdminSession(Session);
impl Deref for AdminSession {
    type Target = Session;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct UnredeemedSession(Session);
impl Deref for UnredeemedSession {
    type Target = Session;

    fn deref(&self) -> &Self::Target {
        &self.0
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
        invitation_file
            .write_all(toml::to_string(self).unwrap().as_bytes())
            .with_path(path)?;
        Ok(())
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        Ok(toml::from_slice(&std::fs::read(&path).with_path(path)?)?)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ServerConfig {
    wg_manage_dir_override: Option<PathBuf>,
    wg_dir_override: Option<PathBuf>,
    root_cidr: Option<(String, IpNetwork)>,
    endpoint: Option<SocketAddr>,
    listen_port: Option<u16>,
    noninteractive: bool,
}

impl ServerConfig {
    fn database_dir(&self) -> &Path {
        self.wg_manage_dir_override
            .as_deref()
            .unwrap_or(*SERVER_DATABASE_DIR)
    }

    fn database_path(&self, interface: &InterfaceName) -> PathBuf {
        PathBuf::new()
            .join(self.database_dir())
            .join(interface.to_string())
            .with_extension("db")
    }

    fn config_dir(&self) -> &Path {
        self.wg_dir_override
            .as_deref()
            .unwrap_or(*SERVER_CONFIG_DIR)
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
    let opt = Opt::from_args();

    if unsafe { libc::getuid() } != 0 {
        return Err("innernet-server must run as root.".into());
    }

    let conf = ServerConfig::default();

    match opt.command {
        Command::New => {
            if let Err(e) = initialize::init_wizard(&conf) {
                println!("{}: {}.", "creation failed".red(), e);
            }
        },
        Command::Serve { interface } => serve(&interface, &conf).await?,
        Command::AddPeer { interface } => add_peer(&interface, &conf)?,
        Command::AddCidr { interface } => add_cidr(&interface, &conf)?,
    }

    Ok(())
}

fn open_database_connection(
    interface: &InterfaceName,
    conf: &ServerConfig,
) -> Result<rusqlite::Connection, Box<dyn std::error::Error>> {
    let database_path = conf.database_path(&interface);
    if !Path::new(&database_path).exists() {
        return Err(format!(
            "no database file found at {}",
            database_path.to_string_lossy()
        )
        .into());
    }

    Ok(Connection::open(&database_path)?)
}

fn add_peer(interface: &InterfaceName, conf: &ServerConfig) -> Result<(), Error> {
    let config = ConfigFile::from_file(conf.config_path(interface))?;
    let conn = open_database_connection(interface, conf)?;
    let peers = DatabasePeer::list(&conn)?
        .into_iter()
        .map(|dp| dp.inner)
        .collect::<Vec<_>>();
    let cidrs = DatabaseCidr::list(&conn)?;
    let cidr_tree = CidrTree::new(&cidrs[..]);

    if let Some((peer_request, keypair)) = shared::prompts::add_peer(&peers, &cidr_tree)? {
        let peer = DatabasePeer::create(&conn, peer_request)?;
        if cfg!(not(test)) && DeviceInfo::get_by_name(interface).is_ok() {
            // Update the current WireGuard interface with the new peers.
            DeviceConfigBuilder::new()
                .add_peer((&*peer).into())
                .apply(interface)
                .map_err(|_| ServerError::WireGuard)?;

            println!("adding to WireGuard interface: {}", &*peer);
        }

        let server_peer = DatabasePeer::get(&conn, 1)?;
        prompts::save_peer_invitation(
            interface,
            &peer,
            &*server_peer,
            &cidr_tree,
            keypair,
            &SocketAddr::new(config.address, config.listen_port),
        )?;
    } else {
        println!("exited without creating peer.");
    }

    Ok(())
}

fn add_cidr(interface: &InterfaceName, conf: &ServerConfig) -> Result<(), Error> {
    let conn = open_database_connection(interface, conf)?;
    let cidrs = DatabaseCidr::list(&conn)?;
    if let Some(cidr_request) = shared::prompts::add_cidr(&cidrs)? {
        let cidr = DatabaseCidr::create(&conn, cidr_request)?;
        printdoc!(
            "
            CIDR \"{cidr_name}\" added.

            Right now, peers within {cidr_name} can only see peers in the same CIDR, and in
            the special \"innernet-server\" CIDR that includes the innernet server peer.

            You'll need to add more associations for peers in diffent CIDRs to communicate.
            ",
            cidr_name = cidr.name.bold()
        );
    } else {
        println!("exited without creating CIDR.");
    }

    Ok(())
}

async fn serve(interface: &InterfaceName, conf: &ServerConfig) -> Result<(), Error> {
    let config = ConfigFile::from_file(conf.config_path(interface))?;
    let conn = open_database_connection(interface, conf)?;
    // Foreign key constraints aren't on in SQLite by default. Enable.
    conn.pragma_update(None, "foreign_keys", &1)?;

    let peers = DatabasePeer::list(&conn)?;
    let peer_configs = peers
        .iter()
        .map(|peer| peer.deref().into())
        .collect::<Vec<PeerConfigBuilder>>();

    log::info!("bringing up interface.");
    wg::up(
        interface,
        &config.private_key,
        IpNetwork::new(config.address, config.network_cidr_prefix)?,
        Some(config.listen_port),
        None,
    )?;

    DeviceConfigBuilder::new()
        .add_peers(&peer_configs)
        .apply(&interface)?;

    let endpoints = Arc::new(Endpoints::new(&interface)?);

    log::info!("{} peers added to wireguard interface.", peers.len());

    let public_key = wgctrl::Key::from_base64(&config.private_key)?.generate_public();
    let db = Arc::new(Mutex::new(conn));
    let context = Context {
        db,
        interface: *interface,
        endpoints,
        public_key,
    };

    log::info!("innernet-server {} starting.", VERSION);
    let routes = routes(context.clone()).with(warp::log("warp")).boxed();

    let listener = get_listener((config.address, config.listen_port).into(), interface)?;

    let warp_svc = warp::service(routes);
    let make_svc = hyper::service::make_service_fn(move |socket: &AddrStream| {
        let remote_addr = socket.remote_addr();
        let warp_svc = warp_svc.clone();
        async move {
            let svc = hyper::service::service_fn(move |req: Request<Body>| {
                let warp_svc = warp_svc.clone();
                async move { warp_svc.call_with_addr(req, Some(remote_addr)).await }
            });
            Ok::<_, Infallible>(svc)
        }
    });

    hyper::Server::from_tcp(listener)?.serve(make_svc).await?;

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
    let listener = TcpListener::bind(&addr)?;
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
    let listener = TcpListener::bind(&addr)?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

pub fn routes(
    context: Context,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    warp::path("v1")
        .and(api::admin::routes(context.clone()).or(api::user::routes(context)))
        .recover(handle_rejection)
}

pub fn form_body<T>() -> impl Filter<Extract = (T,), Error = warp::Rejection> + Clone
where
    T: DeserializeOwned + Send,
{
    warp::body::content_length_limit(1024 * 16).and(warp::body::json())
}

pub fn with_unredeemed_session(
    context: Context,
) -> impl Filter<Extract = (UnredeemedSession,), Error = warp::Rejection> + Clone {
    filters::addr::remote()
        .and(filters::header::header(INNERNET_PUBKEY_HEADER))
        .and_then(move |addr: Option<SocketAddr>, pubkey: String| {
            get_session(
                context.clone(),
                addr.map(|addr| addr.ip()),
                pubkey,
                false,
                false,
            )
        })
        .map(|session| UnredeemedSession(session))
}

pub fn with_session(
    context: Context,
) -> impl Filter<Extract = (Session,), Error = warp::Rejection> + Clone {
    filters::addr::remote()
        .and(filters::header::header(INNERNET_PUBKEY_HEADER))
        .and_then(move |addr: Option<SocketAddr>, pubkey: String| {
            get_session(
                context.clone(),
                addr.map(|addr| addr.ip()),
                pubkey,
                false,
                true,
            )
        })
}

pub fn with_admin_session(
    context: Context,
) -> impl Filter<Extract = (AdminSession,), Error = warp::Rejection> + Clone {
    filters::addr::remote()
        .and(filters::header::header(INNERNET_PUBKEY_HEADER))
        .and_then(move |addr: Option<SocketAddr>, pubkey: String| {
            get_session(
                context.clone(),
                addr.map(|addr| addr.ip()),
                pubkey,
                true,
                true,
            )
        })
        .map(|session| AdminSession(session))
}

async fn get_session(
    context: Context,
    addr: Option<IpAddr>,
    pubkey: String,
    admin_only: bool,
    redeemed_only: bool,
) -> Result<Session, warp::Rejection> {
    _get_session(context, addr, pubkey, admin_only, redeemed_only)
        .map_err(|_| warp::reject::custom(ServerError::Unauthorized))
}

fn _get_session(
    context: Context,
    addr: Option<IpAddr>,
    pubkey: String,
    admin_only: bool,
    redeemed_only: bool,
) -> Result<Session, Error> {
    let pubkey = Key::from_base64(&pubkey)?;
    if pubkey.0.ct_eq(&context.public_key.0).into() {
        let addr = addr.ok_or(ServerError::NotFound)?;
        let peer = DatabasePeer::get_from_ip(&context.db.lock(), addr)?;

        if !peer.is_disabled
            && (!admin_only || peer.is_admin)
            && (!redeemed_only || peer.is_redeemed)
        {
            return Ok(Session { context, peer });
        }
    }

    Err(ServerError::Unauthorized.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test;
    use anyhow::Result;
    use std::path::Path;
    use warp::http::StatusCode;

    #[test]
    fn test_init_wizard() -> Result<()> {
        // This runs init_wizard().
        let server = test::Server::new()?;

        assert!(Path::new(&server.wg_conf_path()).exists());

        Ok(())
    }

    #[tokio::test]
    async fn test_with_session_disguised_with_headers() -> Result<()> {
        let server = test::Server::new()?;
        let filter = routes(server.context());

        // Request from an unknown IP, trying to disguise as an admin using HTTP headers.
        let res = server
            .request_from_ip("10.80.80.80")
            .path("/v1/admin/peers")
            .header("Forwarded", format!("for={}", test::ADMIN_PEER_IP))
            .header("X-Forwarded-For", test::ADMIN_PEER_IP)
            .header("X-Real-IP", test::ADMIN_PEER_IP)
            .reply(&filter)
            .await;

        // addr::remote() filter only look at remote_addr from TCP socket.
        // HTTP headers are not considered. This also means that innernet
        // server would not function behind an HTTP proxy.
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[tokio::test]
    async fn test_incorrect_public_key() -> Result<()> {
        let server = test::Server::new()?;
        let filter = routes(server.context());

        let key = Key::generate_private().generate_public();

        // Request from an unknown IP, trying to disguise as an admin using HTTP headers.
        let res = server
            .request_from_ip("10.80.80.80")
            .path("/v1/admin/peers")
            .header(shared::INNERNET_PUBKEY_HEADER, key.to_base64())
            .reply(&filter)
            .await;

        // addr::remote() filter only look at remote_addr from TCP socket.
        // HTTP headers are not considered. This also means that innernet
        // server would not function behind an HTTP proxy.
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[tokio::test]
    async fn test_unparseable_public_key() -> Result<()> {
        let server = test::Server::new()?;
        let filter = routes(server.context());

        // Request from an unknown IP, trying to disguise as an admin using HTTP headers.
        let res = server
            .request_from_ip("10.80.80.80")
            .path("/v1/admin/peers")
            .header(shared::INNERNET_PUBKEY_HEADER, "")
            .reply(&filter)
            .await;

        // addr::remote() filter only look at remote_addr from TCP socket.
        // HTTP headers are not considered. This also means that innernet
        // server would not function behind an HTTP proxy.
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }
}
