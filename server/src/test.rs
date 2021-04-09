#![allow(dead_code)]
use crate::{
    db::{DatabaseCidr, DatabasePeer},
    endpoints::Endpoints,
    initialize::init_wizard,
    Context, ServerConfig,
};
use anyhow::{anyhow, Result};
use parking_lot::Mutex;
use rusqlite::Connection;
use shared::{Cidr, CidrContents, PeerContents};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tempfile::TempDir;
use warp::test::RequestBuilder;
use wgctrl::{InterfaceName, Key, KeyPair};

pub const ROOT_CIDR: &str = "10.80.0.0/15";
pub const SERVER_CIDR: &str = "10.80.0.1/32";
pub const ADMIN_CIDR: &str = "10.80.1.0/24";
pub const DEVELOPER_CIDR: &str = "10.80.64.0/24";
pub const USER_CIDR: &str = "10.80.128.0/17";
pub const EXPERIMENTAL_CIDR: &str = "10.81.0.0/16";
pub const EXPERIMENTAL_SUBCIDR: &str = "10.81.0.0/17";

pub const ADMIN_PEER_IP: &str = "10.80.1.1";
pub const WG_MANAGE_PEER_IP: &str = "10.80.1.1";
pub const DEVELOPER1_PEER_IP: &str = "10.80.64.2";
pub const DEVELOPER2_PEER_IP: &str = "10.80.64.3";
pub const USER1_PEER_IP: &str = "10.80.128.2";
pub const USER2_PEER_IP: &str = "10.80.129.2";
pub const EXPERIMENT_SUBCIDR_PEER_IP: &str = "10.81.0.1";

pub const ROOT_CIDR_ID: i64 = 1;
pub const INFRA_CIDR_ID: i64 = 2;
pub const ADMIN_CIDR_ID: i64 = 3;
pub const DEVELOPER_CIDR_ID: i64 = 4;
pub const USER_CIDR_ID: i64 = 5;

pub const ADMIN_PEER_ID: i64 = 2;
pub const DEVELOPER1_PEER_ID: i64 = 3;
pub const DEVELOPER2_PEER_ID: i64 = 4;
pub const USER1_PEER_ID: i64 = 5;
pub const USER2_PEER_ID: i64 = 6;

pub struct Server {
    pub db: Arc<Mutex<Connection>>,
    endpoints: Arc<Endpoints>,
    interface: InterfaceName,
    conf: ServerConfig,
    public_key: Key,
    // The directory will be removed during destruction.
    _test_dir: TempDir,
}

impl Server {
    pub fn new() -> Result<Self> {
        let test_dir = tempfile::tempdir()?;
        let test_dir_path = test_dir.path();

        let public_key = Key::generate_private().generate_public();
        // Run the init wizard to initialize the database and create basic
        // cidrs and peers.
        let interface = "test".to_string();
        let conf = ServerConfig {
            wg_manage_dir_override: Some(test_dir_path.to_path_buf()),
            wg_dir_override: Some(test_dir_path.to_path_buf()),
            root_cidr: Some((interface.clone(), ROOT_CIDR.parse()?)),
            endpoint: Some("155.155.155.155:54321".parse()?),
            listen_port: Some(54321),
            noninteractive: true,
        };
        init_wizard(&conf).map_err(|_| anyhow!("init_wizard failed"))?;

        let interface = interface.parse().unwrap();
        // Add developer CIDR and user CIDR and some peers for testing.
        let db = Connection::open(&conf.database_path(&interface))?;
        db.pragma_update(None, "foreign_keys", &1)?;
        assert_eq!(ADMIN_CIDR_ID, create_cidr(&db, "admin", ADMIN_CIDR)?.id);
        assert_eq!(
            ADMIN_PEER_ID,
            DatabasePeer::create(&db, admin_peer_contents("admin", ADMIN_PEER_IP)?)?.id
        );
        assert_eq!(
            DEVELOPER_CIDR_ID,
            create_cidr(&db, "developer", DEVELOPER_CIDR)?.id
        );
        assert_eq!(
            DEVELOPER1_PEER_ID,
            DatabasePeer::create(
                &db,
                developer_peer_contents("developer1", DEVELOPER1_PEER_IP)?
            )?
            .id
        );
        assert_eq!(
            DEVELOPER2_PEER_ID,
            DatabasePeer::create(
                &db,
                developer_peer_contents("developer2", DEVELOPER2_PEER_IP)?
            )?
            .id
        );
        assert_eq!(USER_CIDR_ID, create_cidr(&db, "user", USER_CIDR)?.id);
        assert_eq!(
            USER1_PEER_ID,
            DatabasePeer::create(&db, user_peer_contents("user1", USER1_PEER_IP)?)?.id
        );
        assert_eq!(
            USER2_PEER_ID,
            DatabasePeer::create(&db, user_peer_contents("user2", USER2_PEER_IP)?)?.id
        );

        let db = Arc::new(Mutex::new(db));
        let endpoints = Arc::new(Endpoints::new(&interface)?);

        Ok(Self {
            conf,
            db,
            endpoints,
            interface,
            public_key,
            _test_dir: test_dir,
        })
    }

    pub fn db(&self) -> Arc<Mutex<Connection>> {
        self.db.clone()
    }

    pub fn context(&self) -> Context {
        Context {
            db: self.db.clone(),
            interface: self.interface.clone(),
            endpoints: self.endpoints.clone(),
            public_key: self.public_key.clone(),
        }
    }

    pub fn wg_conf_path(&self) -> PathBuf {
        self.conf.config_path(&self.interface)
    }

    pub fn request_from_ip(&self, ip_str: &str) -> RequestBuilder {
        let port = 54321u16;
        warp::test::request()
            .remote_addr(SocketAddr::new(ip_str.parse().unwrap(), port))
            .header(shared::INNERNET_PUBKEY_HEADER, self.public_key.to_base64())
    }

    pub fn post_request_from_ip(&self, ip_str: &str) -> RequestBuilder {
        self.request_from_ip(ip_str)
            .method("POST")
            .header("Content-Type", "application/json")
    }

    pub fn put_request_from_ip(&self, ip_str: &str) -> RequestBuilder {
        self.request_from_ip(ip_str)
            .method("PUT")
            .header("Content-Type", "application/json")
    }
}

pub fn create_cidr(db: &Connection, name: &str, cidr_str: &str) -> Result<Cidr> {
    let cidr = DatabaseCidr::create(
        db,
        CidrContents {
            name: name.to_string(),
            cidr: cidr_str.parse()?,
            parent: Some(ROOT_CIDR_ID),
        },
    )?;

    Ok(cidr)
}

//
// Below are helper functions for writing tests.
//

pub fn peer_contents(
    name: &str,
    ip_str: &str,
    cidr_id: i64,
    is_admin: bool,
) -> Result<PeerContents> {
    let public_key = KeyPair::generate().public;

    Ok(PeerContents {
        name: name.to_string(),
        ip: ip_str.parse()?,
        cidr_id,
        public_key: public_key.to_base64(),
        is_admin,
        endpoint: None,
        persistent_keepalive_interval: None,
        is_disabled: false,
        is_redeemed: true,
    })
}

pub fn admin_peer_contents(name: &str, ip_str: &str) -> Result<PeerContents> {
    peer_contents(name, ip_str, ADMIN_CIDR_ID, true)
}

pub fn infra_peer_contents(name: &str, ip_str: &str) -> Result<PeerContents> {
    peer_contents(name, ip_str, INFRA_CIDR_ID, false)
}

pub fn developer_peer_contents(name: &str, ip_str: &str) -> Result<PeerContents> {
    peer_contents(name, ip_str, DEVELOPER_CIDR_ID, false)
}

pub fn user_peer_contents(name: &str, ip_str: &str) -> Result<PeerContents> {
    peer_contents(name, ip_str, USER_CIDR_ID, false)
}
