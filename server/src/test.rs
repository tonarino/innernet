#![allow(dead_code)]
use crate::{
    db::{DatabaseCidr, DatabasePeer},
    initialize::{init_wizard, InitializeOpts},
    Context, Db, Endpoints, ServerConfig,
};
use anyhow::anyhow;
use hyper::{header::HeaderValue, http, Body, Request, Response};
use parking_lot::{Mutex, RwLock};
use rusqlite::Connection;
use serde::Serialize;
use shared::{Cidr, CidrContents, Error, PeerContents};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tempfile::TempDir;
use wireguard_control::{Backend, InterfaceName, Key, KeyPair};

#[cfg(not(feature = "v6-test"))]
mod v4 {
    pub const ROOT_CIDR: &str = "10.80.0.0/15";
    pub const SERVER_CIDR: &str = "10.80.0.1/32";
    pub const ADMIN_CIDR: &str = "10.80.1.0/24";
    pub const DEVELOPER_CIDR: &str = "10.80.64.0/24";
    pub const USER_CIDR: &str = "10.80.128.0/17";
    pub const EXPERIMENTAL_CIDR: &str = "10.81.0.0/16";
    pub const EXPERIMENTAL_SUBCIDR: &str = "10.81.0.0/17";

    pub const ADMIN_PEER_IP: &str = "10.80.1.1";
    pub const WG_MANAGE_PEER_IP: &str = ADMIN_PEER_IP;
    pub const DEVELOPER1_PEER_IP: &str = "10.80.64.2";
    pub const DEVELOPER1_PEER_ENDPOINT: &str = "169.10.26.8:14720";
    pub const DEVELOPER2_PEER_IP: &str = "10.80.64.3";
    pub const DEVELOPER2_PEER_ENDPOINT: &str = "169.55.140.9:5833";
    pub const USER1_PEER_IP: &str = "10.80.128.2";
    pub const USER2_PEER_IP: &str = "10.80.129.2";
    pub const EXPERIMENT_SUBCIDR_PEER_IP: &str = "10.81.0.1";
}
#[cfg(not(feature = "v6-test"))]
pub use v4::*;

#[cfg(feature = "v6-test")]
mod v6 {
    pub const ROOT_CIDR: &str = "fd00:1337::/64";
    pub const SERVER_CIDR: &str = "fd00:1337::1/128";
    pub const ADMIN_CIDR: &str = "fd00:1337::1:0:0:0/80";
    pub const DEVELOPER_CIDR: &str = "fd00:1337::2:0:0:0/80";
    pub const USER_CIDR: &str = "fd00:1337::3:0:0:0/80";
    pub const EXPERIMENTAL_CIDR: &str = "fd00:1337::4:0:0:0/80";
    pub const EXPERIMENTAL_SUBCIDR: &str = "fd00:1337::4:0:0:0/81";

    pub const ADMIN_PEER_IP: &str = "fd00:1337::1:0:0:1";
    pub const WG_MANAGE_PEER_IP: &str = ADMIN_PEER_IP;
    pub const DEVELOPER1_PEER_IP: &str = "fd00:1337::2:0:0:1";
    pub const DEVELOPER1_PEER_ENDPOINT: &str = "[1001:db8::1]:14720";
    pub const DEVELOPER2_PEER_IP: &str = "fd00:1337::2:0:0:2";
    pub const DEVELOPER2_PEER_ENDPOINT: &str = "[2001:db8::1]:5833";
    pub const USER1_PEER_IP: &str = "fd00:1337::3:0:0:1";
    pub const USER2_PEER_IP: &str = "fd00:1337::3:0:0:2";
    pub const EXPERIMENT_SUBCIDR_PEER_IP: &str = "fd00:1337::4:0:0:1";
}
#[cfg(feature = "v6-test")]
pub use v6::*;

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
    pub db: Db,
    endpoints: Endpoints,
    interface: InterfaceName,
    conf: ServerConfig,
    public_key: Key,
    // The directory will be removed during destruction.
    _test_dir: TempDir,
}

impl Server {
    pub fn new() -> Result<Self, Error> {
        let test_dir = tempfile::tempdir()?;
        let test_dir_path = test_dir.path();

        let public_key = Key::generate_private().get_public();
        // Run the init wizard to initialize the database and create basic
        // cidrs and peers.
        let interface = "test".to_string();
        let conf = ServerConfig {
            config_dir: test_dir_path.to_path_buf(),
            data_dir: test_dir_path.to_path_buf(),
        };

        let opts = InitializeOpts {
            network_name: Some(interface.parse()?),
            network_cidr: Some(ROOT_CIDR.parse()?),
            external_endpoint: Some("155.155.155.155:54321".parse().unwrap()),
            listen_port: Some(54321),
            auto_external_endpoint: false,
        };
        init_wizard(&conf, opts).map_err(|_| anyhow!("init_wizard failed"))?;

        let interface = interface.parse().unwrap();
        // Add developer CIDR and user CIDR and some peers for testing.
        let db = Connection::open(conf.database_path(&interface))?;
        db.pragma_update(None, "foreign_keys", 1)?;
        assert_eq!(ADMIN_CIDR_ID, create_cidr(&db, "admin", ADMIN_CIDR)?.id);
        assert_eq!(
            ADMIN_PEER_ID,
            DatabasePeer::create(&db, admin_peer_contents("admin", ADMIN_PEER_IP)?)?.id
        );
        assert_eq!(
            DEVELOPER_CIDR_ID,
            create_cidr(&db, "developer", DEVELOPER_CIDR)?.id
        );

        let developer_1 = developer_peer_contents("developer1", DEVELOPER1_PEER_IP)?;
        let developer_1_public_key = developer_1.public_key.clone();
        assert_eq!(
            DEVELOPER1_PEER_ID,
            DatabasePeer::create(&db, developer_1,)?.id
        );

        let developer_2 = developer_peer_contents("developer2", DEVELOPER2_PEER_IP)?;
        let developer_2_public_key = developer_2.public_key.clone();
        assert_eq!(
            DEVELOPER2_PEER_ID,
            DatabasePeer::create(&db, developer_2)?.id
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

        let endpoints = [
            (
                developer_1_public_key,
                DEVELOPER1_PEER_ENDPOINT.parse().unwrap(),
            ),
            (
                developer_2_public_key,
                DEVELOPER2_PEER_ENDPOINT.parse().unwrap(),
            ),
        ];
        let endpoints = Arc::new(RwLock::new(endpoints.into()));

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
            interface: self.interface,
            endpoints: self.endpoints.clone(),
            public_key: self.public_key.clone(),
            #[cfg(target_os = "linux")]
            backend: Backend::Kernel,
            #[cfg(not(target_os = "linux"))]
            backend: Backend::Userspace,
        }
    }

    pub fn wg_conf_path(&self) -> PathBuf {
        self.conf.config_path(&self.interface)
    }

    pub async fn raw_request(&self, ip_str: &str, req: Request<Body>) -> Response<Body> {
        let port = 54321u16;
        crate::hyper_service(
            req,
            self.context(),
            SocketAddr::new(ip_str.parse().unwrap(), port),
        )
        .await
        .unwrap()
    }

    fn base_request_builder(&self, verb: &str, path: &str) -> http::request::Builder {
        let path = if cfg!(feature = "v6-test") {
            format!("http://[{WG_MANAGE_PEER_IP}]{path}")
        } else {
            format!("http://{WG_MANAGE_PEER_IP}{path}")
        };
        Request::builder().uri(path).method(verb).header(
            shared::INNERNET_PUBKEY_HEADER,
            HeaderValue::from_str(&self.public_key.to_base64()).unwrap(),
        )
    }

    pub async fn request(&self, ip_str: &str, verb: &str, path: &str) -> Response<Body> {
        let req = self
            .base_request_builder(verb, path)
            .body(Body::empty())
            .unwrap();
        self.raw_request(ip_str, req).await
    }

    pub async fn form_request<F: Serialize>(
        &self,
        ip_str: &str,
        verb: &str,
        path: &str,
        form: F,
    ) -> Response<Body> {
        let json = serde_json::to_string(&form).unwrap();
        let req = self
            .base_request_builder(verb, path)
            .header("Content-Type", "application/json")
            .header("Content-Length", json.len().to_string())
            .body(Body::from(json))
            .unwrap();
        self.raw_request(ip_str, req).await
    }
}

pub fn create_cidr(db: &Connection, name: &str, cidr_str: &str) -> Result<Cidr, Error> {
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
) -> Result<PeerContents, Error> {
    let public_key = KeyPair::generate().public;

    Ok(PeerContents {
        name: name.parse().map_err(|e: &str| anyhow!(e))?,
        ip: ip_str.parse()?,
        cidr_id,
        public_key: public_key.to_base64(),
        is_admin,
        endpoint: None,
        persistent_keepalive_interval: None,
        is_disabled: false,
        is_redeemed: true,
        invite_expires: None,
        candidates: vec![],
    })
}

pub fn admin_peer_contents(name: &str, ip_str: &str) -> Result<PeerContents, Error> {
    peer_contents(name, ip_str, ADMIN_CIDR_ID, true)
}

pub fn infra_peer_contents(name: &str, ip_str: &str) -> Result<PeerContents, Error> {
    peer_contents(name, ip_str, INFRA_CIDR_ID, false)
}

pub fn developer_peer_contents(name: &str, ip_str: &str) -> Result<PeerContents, Error> {
    peer_contents(name, ip_str, DEVELOPER_CIDR_ID, false)
}

pub fn user_peer_contents(name: &str, ip_str: &str) -> Result<PeerContents, Error> {
    peer_contents(name, ip_str, USER_CIDR_ID, false)
}
