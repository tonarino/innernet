use std::{net::SocketAddr, path::PathBuf, str::FromStr, time::SystemTime};
use axum::{http::StatusCode, Json};
use ipnet::IpNet;
use shared::{interface_config::{InterfaceConfig, InterfaceInfo}, IpNetExt, Timestring, PERSISTENT_KEEPALIVE_INTERVAL_SECS};
use shared::{interface_config::ServerInfo, Cidr, CidrTree, Hostname, Peer, PeerContents};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, sync::broadcast::Receiver};
use wireguard_control::{InterfaceName, KeyPair};
use client::util::Api;
use innernet_server::{
    ConfigFile,
    ServerConfig,
    open_database_connection, 
    DatabasePeer,
    DatabaseCidr,
};

use conductor::{
    HEADER_SIZE,
    TOPIC_SIZE_OFFSET,
    util::{
        try_get_topic_len, try_get_message_len, parse_next_message
    },
    subscriber::SubStream,
    publisher::PubStream
};
use form_types::{GenericPublisher, VmmEvent, VmmTopic, FormnetMessage};
use tokio::net::TcpStream;
use serde::{Serialize, Deserialize};

pub const CONFIG_DIR: &'static str = "/etc/innernet";
pub const SERVER_CONFIG_DIR: &'static str = "/etc/innernet-server";
pub const SERVER_DATA_DIR: &'static str = "/var/lib/innernet-server";

pub async fn add_peer<'a>(
    peers: &[Peer],
    cidr_tree: &CidrTree<'a>,
    peer_type: &PeerType,
    peer_id: &str
) -> Result<(PeerContents, KeyPair), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let leaves = cidr_tree.leaves();
    let cidr = match peer_type {
        PeerType::User => {
            leaves.iter().filter(|cidr| cidr.name == "operators").collect::<Vec<_>>().first().cloned()
        }
        PeerType::Operator => {
            leaves.iter().filter(|cidr| cidr.name == "operators").collect::<Vec<_>>().first().cloned()
        }
        PeerType::Instance => {
            leaves.iter().filter(|cidr| cidr.name == "vm-subnet").collect::<Vec<_>>().first().cloned()
        }
    }.ok_or(
        Box::new(
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "CIDRs are not properly set up"
            )
        )
    )?;

    log::info!("Choose CIDR: {cidr:?}");

    let mut available_ip = None;
    let candidate_ips = cidr.hosts().filter(|ip| cidr.is_assignable(ip));
    for ip in candidate_ips {
        if !peers.iter().any(|peer| peer.ip == ip) {
            available_ip = Some(ip);
            break;
        }
    }
    let ip = available_ip.ok_or(
        Box::new(
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "No IPs in this CIDR are available"
            )
        )
    )?;
    log::info!("Choose IP: {ip:?}");

    let default_keypair = KeyPair::generate();

    log::info!("Generated Keypair");

    let invite_expires: Timestring = "1d".parse().map_err(|e| {
        Box::new(
            std::io::Error::new(
                std::io::ErrorKind::Other,
                e
            )
        )
    })?; 
    log::info!("Generated expiration");

    let name = Hostname::from_str(peer_id)?;
    log::info!("Generated Hostname");

    let peer_request = PeerContents {
        name,
        ip,
        cidr_id: cidr.id,
        public_key: default_keypair.public.to_base64(),
        endpoint: None,
        is_admin: match peer_type {
            PeerType::Operator => true,
            _ => false
        },
        is_disabled: false,
        is_redeemed: false,
        persistent_keepalive_interval: Some(PERSISTENT_KEEPALIVE_INTERVAL_SECS),
        invite_expires: Some(SystemTime::now() + invite_expires.into()),
        candidates: vec![],
    };

    Ok((peer_request, default_keypair))
}

pub async fn server_add_peer(
    inet: &InterfaceName, 
    conf: &ServerConfig,
    peer_type: &PeerType,
    peer_id: &str,
) -> Result<InterfaceConfig, Box<dyn std::error::Error + Send + Sync + 'static>> {
    log::info!("Reading config file into ConfigFile...");
    let config = ConfigFile::from_file(conf.config_path(inet))?;
    log::info!("Opening database connection...");
    let conn = open_database_connection(inet, conf)?;
    log::info!("Collecting peers...");
    let peers = DatabasePeer::list(&conn)?
        .into_iter().map(|dp| dp.inner)
        .collect::<Vec<_>>();

    log::info!("Collecting CIDRs...");
    let cidrs = DatabaseCidr::list(&conn)?;
    let cidr_tree = CidrTree::new(&cidrs[..]);

    log::info!("calling add peer to get key pair and contents...");
    let (contents, keypair) = add_peer(&peers, &cidr_tree, peer_type, peer_id).await?;

    log::info!("Getting Server Peer...");
    let server_peer = DatabasePeer::get(&conn, 1)?;

    log::info!("Creating peer...");
    let peer = DatabasePeer::create(&conn, contents)?;

    log::info!("building invitation...");
    let peer_invitation = InterfaceConfig {
        interface: InterfaceInfo {
            network_name: inet.to_string(),
            private_key: keypair.private.to_base64(),
            address: IpNet::new(peer.ip, cidr_tree.prefix_len())?,
            listen_port: None,
        },
        server: ServerInfo {
            external_endpoint: server_peer
                .endpoint
                .clone()
                .expect("The innernet server should have a WireGuard endpoint"),
            internal_endpoint: SocketAddr::new(config.address, config.listen_port),
            public_key: server_peer.public_key.clone(),
        },
    };

    log::info!("returning invitation...");
    Ok(peer_invitation)
}

pub async fn respond_with_peer_invitation<'a>(
    peer: &Peer,
    server: ServerInfo,
    root_cidr: &CidrTree<'a>,
    keypair: KeyPair,
) -> Result<(), Box<dyn std::error::Error>> {
    let invite = InterfaceConfig {
        interface: InterfaceInfo {
            network_name: "formnet".to_string(),
            private_key: keypair.private.to_base64(),
            address: IpNet::new(peer.ip, root_cidr.prefix_len())?,
            listen_port: None,
        },
        server
    };

    // Write to the MessageBroker under `VmmTopic` as this
    // should represent a request for a new Instance to be added to the 
    // network
    let mut publisher = GenericPublisher::new("127.0.0.1:5555").await?; 
    publisher.publish(
        Box::new(VmmTopic),
        Box::new(VmmEvent::NetworkSetupComplete { 
            invite: serde_json::to_string(&invite)? 
        })
    ).await?;

    Ok(())
}

pub async fn server_respond_with_peer_invitation(invitation: InterfaceConfig) -> Result<(), Box<dyn std::error::Error>> {
    // Write to the MessageBroker under `VmmTopic` as this
    // should represent a request for a new Instance to be added to the 
    // network
    let mut publisher = GenericPublisher::new("127.0.0.1:5555").await?; 
    publisher.publish(
        Box::new(VmmTopic),
        Box::new(VmmEvent::NetworkSetupComplete { 
            invite: serde_json::to_string(&invitation)? 
        })
    ).await?;

    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FormnetEvent {
    AddPeer {
        peer_type: PeerType,
        peer_id: String,
        callback: SocketAddr
    },
    DisablePeer,
    EnablePeer,
    SetListenPort,
    OverrideEndpoint,
}

impl FormnetEvent {
    #[cfg(not(any(feature = "integration", test)))]
    pub const INTERFACE_NAME: &'static str = "formnet";
    #[cfg(any(feature = "integration", test))]
    pub const INTERFACE_NAME: &'static str = "test-net";
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PeerType {
    Operator,
    User,
    Instance,
}

impl From<form_types::PeerType> for PeerType {
    fn from(value: form_types::PeerType) -> Self {
        match value {
            form_types::PeerType::User => PeerType::User,
            form_types::PeerType::Operator => PeerType::Operator,
            form_types::PeerType::Instance => PeerType::Instance,
        }
    }
}

impl From<&form_types::PeerType> for PeerType {
    fn from(value: &form_types::PeerType) -> Self {
        match value {
            form_types::PeerType::User => PeerType::User,
            form_types::PeerType::Operator => PeerType::Operator,
            form_types::PeerType::Instance => PeerType::Instance,
        }
    }
}

impl From<PeerType> for form_types::PeerType {
    fn from(value: PeerType) -> Self {
        match value {
            PeerType::User => form_types::PeerType::User, 
            PeerType::Operator => form_types::PeerType::Operator,
            PeerType::Instance => form_types::PeerType::Instance ,
        }
    }
}

impl From<&PeerType> for form_types::PeerType {
    fn from(value: &PeerType) -> Self {
        match value {
            PeerType::User => form_types::PeerType::User, 
            PeerType::Operator => form_types::PeerType::Operator,
            PeerType::Instance => form_types::PeerType::Instance ,
        }
    }
}

pub struct FormnetSubscriber {
    stream: TcpStream
}

impl FormnetSubscriber {
    pub async fn new(uri: &str, topics: Vec<String>) -> std::io::Result<Self> {
        let mut stream = TcpStream::connect(uri).await?;
        let topic_str = topics.join(",");
        stream.write_all(topic_str.as_bytes()).await?;
        Ok(Self { stream })
    }
}

#[async_trait::async_trait]
impl SubStream for FormnetSubscriber {
    type Message = Vec<FormnetMessage>;

    async fn receive(&mut self) -> std::io::Result<Self::Message> {
        let mut buffer = Vec::new();
        loop {
            let mut read_buffer = [0; 4096];
            match self.stream.read(&mut read_buffer).await {
                Err(e) => log::error!("Error reading stream to buffer: {e}..."),
                Ok(n) => {
                    if n == 0 {
                        break;
                    }

                    buffer.extend_from_slice(&read_buffer[..n]);
                    let results = Self::parse_messages(&mut buffer).await?;
                    if !results.is_empty() {
                        return Ok(results);
                    }
                }
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "No complete messages received",
        ))
    }

    async fn parse_messages(msg: &mut Vec<u8>) -> std::io::Result<Self::Message> {
        let mut results = Vec::new();
        while msg.len() >= HEADER_SIZE {
            let total_len = try_get_message_len(msg)?;
            if msg.len() >= total_len {
                let topic_len = try_get_topic_len(msg)?;
                let (_, message) = parse_next_message(total_len, topic_len, msg).await;
                let message_offset = TOPIC_SIZE_OFFSET + topic_len;
                let msg = &message[message_offset..message_offset + total_len];
                results.push(msg.to_vec());
            }
        }

        let msg_results = results
            .iter()
            .filter_map(|m| serde_json::from_slice(&m).ok())
            .collect();

        Ok(msg_results)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserJoinRequest {
    user_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UserJoinResponse {
    Success {
        #[serde(flatten)]
        invitation: InterfaceConfig,
    },
    Error(String) 
}

pub fn create_router() -> axum::Router {
    axum::Router::new().route("/join", axum::routing::post(handle_join_request))
}

pub fn is_server() -> bool {
    PathBuf::from(SERVER_CONFIG_DIR).join(
        format!("{}.conf", FormnetMessage::INTERFACE_NAME)
    ).exists()
}

async fn handle_join_request_from_server(
    join_request: UserJoinRequest,
    inet: InterfaceName
) -> (StatusCode, axum::Json<UserJoinResponse>) {
    match server_add_peer(
        &inet,
        &ServerConfig { config_dir: SERVER_CONFIG_DIR.into(), data_dir: SERVER_DATA_DIR.into() },
        &PeerType::User,
        &join_request.user_id
    ).await {
        Ok(invitation) => {
            let resp = UserJoinResponse::Success { invitation };
            return (
                StatusCode::OK,
                Json(resp)
            )
        },
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(UserJoinResponse::Error(e.to_string()))
            )
        }
    }
}

async fn handle_join_request_from_admin_client(
    join_request: UserJoinRequest,
    inet: InterfaceName
) -> (StatusCode, axum::Json<UserJoinResponse>) {
    let InterfaceConfig { server, ..} = {
        match InterfaceConfig::from_interface(
            &PathBuf::from(CONFIG_DIR).as_path(),
            &inet
        ) {
            Ok(config) => config,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(UserJoinResponse::Error(format!("Failed to acquire config for innernet server: {}", e)))
                )
            }
        }
    };

    let api = Api::new(&server);

    log::info!("Fetching CIDRs...");
    let cidrs: Vec<Cidr> = match api.http("GET", "/admin/cidrs") {
        Ok(cidr_list) => cidr_list,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(UserJoinResponse::Error(format!("Failed to acquire CIDR list for innernet network: {e}")))
            )
        }
    };
    log::info!("Fetching Peers...");
    let peers: Vec<Peer> = match api.http("GET", "/admin/peers") {
        Ok(peer_list) => peer_list,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(UserJoinResponse::Error(format!("Failed to acquire Peer list for innernet network: {e}")))
            )
        }
    };
    log::info!("Creating CIDR Tree...");
    let cidr_tree = CidrTree::new(&cidrs[..]);

    match add_peer(
        &peers, &cidr_tree, &PeerType::User, &join_request.user_id 
    ).await {
        Ok((content, keypair)) => {
            log::info!("Creating peer...");
            let peer: Peer = match api.http_form("POST", "/admin/peers", content) {
                Ok(peer) => peer,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(UserJoinResponse::Error(format!("Failed to create peer: {e}")))
                    )
                }
            };

            match api_respond_with_peer_invitation(&peer, server, &cidr_tree, keypair).await {
                Ok(resp) => {
                    return (
                        StatusCode::OK,
                        Json(resp)
                    )
                }
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(UserJoinResponse::Error(format!("Unable to build peer invitation: {e}")))
                    )
                }
            }
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(UserJoinResponse::Error(format!("Failed to add peer to innernet: {e}")))
            )
        }
    }
}

pub async fn handle_join_request(axum::Json(join_request): axum::Json<UserJoinRequest>) -> impl axum::response::IntoResponse {
    let inet = match InterfaceName::from_str(
        FormnetMessage::INTERFACE_NAME
    ) {
        Ok(inet) => inet,
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(UserJoinResponse::Error(format!("Failed to convert {} into InterfaceName: {e}", FormnetMessage::INTERFACE_NAME)))
        )
    };

    if is_server() {
        return handle_join_request_from_server(join_request, inet).await;
    } else {
        return handle_join_request_from_admin_client(join_request, inet).await;
    }
}

async fn api_respond_with_peer_invitation<'a>(
    peer: &Peer,
    server: ServerInfo,
    root_cidr: &CidrTree<'a>,
    keypair: KeyPair,
) -> Result<UserJoinResponse, Box<dyn std::error::Error>> {
    Ok(UserJoinResponse::Success {
        invitation: InterfaceConfig {
            interface: InterfaceInfo {
                network_name: "formnet".to_string(),
                private_key: keypair.private.to_base64(),
                address: IpNet::new(peer.ip, root_cidr.prefix_len())?,
                listen_port: None,
            },
            server
        }
    })
}

pub async fn api_shutdown_handler(
    mut rx: Receiver<()>
) {
    loop {
        tokio::select! {
            res = rx.recv() => {
                log::info!("Received shutdown signal for api server: {res:?}");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use tokio::net::TcpListener;
    use reqwest::Client;

    #[tokio::test]
    async fn test_user_join() -> Result<(), Box<dyn std::error::Error>> {
        let (tx, rx) = tokio::sync::broadcast::channel(1);
        let api_shutdown = rx.resubscribe();
        
        let api_handle = tokio::spawn(async move {
            let api = create_router();
            let listener = TcpListener::bind("0.0.0.0:3001").await?;

            let _ = axum::serve(
                listener,
                api
            ).with_graceful_shutdown(
                api_shutdown_handler(api_shutdown)
            ).await;

            Ok::<(), Box<dyn std::error::Error + Send + Sync + 'static>>(())
        });

        tokio::time::sleep(Duration::from_secs(2)).await;

        let user_id = random_word::gen(random_word::Lang::En).to_string();
        let client = Client::new();
        let response = client.post("http://localhost:3001/join")
            .json(&UserJoinRequest {
                user_id
            }).send().await?;

        log::info!("{:?}", response);

        let status = response.status().clone();

        // Let's print out the error response body if we get a non-success status
        if !response.status().is_success() {
            let error_body = response.text().await?.clone();
            log::info!("Error response body: {}", error_body);
            // Now fail the test
            panic!("Request failed with status {} and error: {}", status, error_body);
        }

        assert!(response.status().is_success());

        let join_response = response.json::<UserJoinResponse>().await?;

        log::info!("{}", serde_json::to_string_pretty(&join_response)?);

        let _ = tx.send(());
        let _ = api_handle.await?;

        Ok(())
    }
}
