use std::path::PathBuf;
use std::str::FromStr;
use innernet_server::ServerConfig;
use shared::interface_config::InterfaceConfig;
use shared::{Cidr, CidrTree, Peer};
use tokio::{net::TcpListener, sync::broadcast::Receiver};
use wireguard_control::InterfaceName;
use client::util::Api;
use conductor::subscriber::SubStream;
use form_types::FormnetMessage;
use formnet::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    simple_logger::SimpleLogger::new().init().unwrap();

    // Create innernet from CLI, Config or Wizard 
    // If done via wizard save to file
    // Listen for messages on topic "Network" from broker
    // Handle messages
    //
    // Formnet service can:
    //  1. Add peers
    //  2. Remove peers
    //  3. Add CIDRs
    //  4. Remove CIDRs
    //  5. Rename Peers
    //  6. Rename CIDRs
    //  7. Enable Peers
    //  8. Disable Peers
    //  9. Manage Associations
    //  10. Manage Endpoints
    //
    // When a new peer joins the network, a join token will be sent to them
    // which they will then "install" via their formnet network service.
    //
    // In the formnet there are 3 types of peers:
    //  1. Operators - All operators are admins and can add CIDRs, Peers, Associations, etc.
    //                 All operators run a "server" replica.
    //
    //  2. Users - Users run a simple client, they are added as a peer, and in future version
    //             will have more strictly managed associations to ensure they only have
    //             access to the resources they own. In the first version, they have access
    //             to the entire network, but instances and resources use internal auth mechanisms
    //             such as public/private key auth to provide security.
    //
    //  3. Instances - Instances are user owned resources, such as Virtual Machines, containers,
    //                 etc. Instances are only manageable by their owner. Once they are up and
    //                 running the rest of the network just knows they are there. Operators that
    //                 are responsible for a given instance can be financially penalized for not
    //                 maintaining the instance in the correct state/status.
    // 

    // So what do we need this to do
    // 1. Listen on `topic` for relevant messages from the MessageBroker
    // 2. When a message is received, match that message on an action
    // 3. Handle the action (by using the API).


    let (tx, rx) = tokio::sync::broadcast::channel(3);
    let api_shutdown = tx.subscribe();
    
    let api_handle = tokio::spawn(async move {
        let api = create_router();
        let listener = TcpListener::bind("0.0.0.0:3001").await?;

        let _ = axum::serve(
            listener,
            api
        ).with_graceful_shutdown(
            api_shutdown_handler(api_shutdown)
        );

        Ok::<(), Box<dyn std::error::Error + Send + Sync + 'static>>(())
    });

    let handle = tokio::spawn(async move {
        let sub = FormnetSubscriber::new(
            "127.0.0.1:5556",
            vec![
                "formnet".to_string()
            ]
        ).await?;
        if let Err(e) = run(
            sub,
            rx
        ).await {
            eprintln!("Error running innernet handler: {e}");
        }

        Ok::<(), Box<dyn std::error::Error + Send + Sync + 'static>>(())
    });

    tokio::signal::ctrl_c().await?;

    if let Err(e) = tx.send(()) {
        println!("Error sending shutdown signal: {e}");
    }
    let _ = handle.await?;
    let _ = api_handle.await?;

    Ok(())
}

async fn run(
    mut subscriber: impl SubStream<Message = Vec<FormnetMessage>>,
    mut shutdown: Receiver<()>
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    loop {
        tokio::select! {
            Ok(msg) = subscriber.receive() => {
                for m in msg {
                    if let Err(e) = handle_message(&m).await {
                        eprintln!("Error handling message {m:?}: {e}");
                    }
                }
            }
            _ = shutdown.recv() => {
                eprintln!("Received shutdown signal for Formnet");
                break;
            }
        }
    }

    Ok(())
}

async fn handle_message(
    message: &FormnetMessage
) -> Result<(), Box<dyn std::error::Error>> {
    use form_types::FormnetMessage::*;
    match message {
        AddPeer { peer_type, peer_id, callback } => {
            if is_server() {
                let server_config = ServerConfig { 
                    config_dir: PathBuf::from(SERVER_CONFIG_DIR), 
                    data_dir: PathBuf::from(SERVER_DATA_DIR)
                };
                let inet = InterfaceName::from_str(FormnetMessage::INTERFACE_NAME)?;
                if let Ok(invitation) = server_add_peer(
                    &inet,
                    &server_config,
                    &peer_type.into(),
                    peer_id,
                ).await {
                    return server_respond_with_peer_invitation(invitation).await;
                }
            }

            let InterfaceConfig { server, ..} = InterfaceConfig::from_interface(
                PathBuf::from(CONFIG_DIR).as_path(), 
                &InterfaceName::from_str(
                    FormnetMessage::INTERFACE_NAME
                )?
            )?;
            let api = Api::new(&server);
            println!("Fetching CIDRs...");
            let cidrs: Vec<Cidr> = api.http("GET", "/admin/cidrs")?;
            println!("Fetching Peers...");
            let peers: Vec<Peer> = api.http("GET", "/admin/peers")?;
            println!("Creating CIDR Tree...");
            let cidr_tree = CidrTree::new(&cidrs[..]);

            if let Ok((content, keypair)) = add_peer(
                &peers, &cidr_tree, &peer_type.into(), peer_id
            ).await {
                println!("Creating peer...");
                let peer: Peer = api.http_form("POST", "/admin/peers", content)?;
                respond_with_peer_invitation(&peer, server.clone(), &cidr_tree, keypair).await?;
            }
        },
        DisablePeer => {},
        EnablePeer => {},
        SetListenPort => {},
        OverrideEndpoint => {},
    }
    Ok(())
}
