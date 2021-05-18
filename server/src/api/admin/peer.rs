use std::collections::VecDeque;

use crate::{
    api::inject_endpoints,
    db::DatabasePeer,
    util::{form_body, json_response, json_status_response, status_response},
    ServerError, Session,
};
use hyper::{Body, Method, Request, Response, StatusCode};
use shared::PeerContents;
use wgctrl::DeviceUpdate;

pub async fn routes(
    req: Request<Body>,
    mut components: VecDeque<String>,
    session: Session,
) -> Result<Response<Body>, ServerError> {
    match (req.method(), components.pop_front().as_deref()) {
        (&Method::GET, None) => handlers::list(session).await,
        (&Method::POST, None) => {
            let form = form_body(req).await?;
            handlers::create(form, session).await
        },
        (&Method::PUT, Some(id)) => {
            let id: i64 = id.parse().map_err(|_| ServerError::NotFound)?;
            let form = form_body(req).await?;
            handlers::update(id, form, session).await
        },
        (&Method::DELETE, Some(id)) => {
            let id: i64 = id.parse().map_err(|_| ServerError::NotFound)?;
            handlers::delete(id, session).await
        },
        _ => Err(ServerError::NotFound),
    }
}

mod handlers {

    use super::*;

    pub async fn create(
        form: PeerContents,
        session: Session,
    ) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();

        let peer = DatabasePeer::create(&conn, form)?;
        log::info!("adding peer {}", &*peer);

        if cfg!(not(test)) {
            // Update the current WireGuard interface with the new peers.
            DeviceUpdate::new()
                .add_peer((&*peer).into())
                .apply(&session.context.interface)
                .map_err(|_| ServerError::WireGuard)?;
            log::info!("updated WireGuard interface, adding {}", &*peer);
        }

        json_status_response(&*peer, StatusCode::CREATED)
    }

    pub async fn update(
        id: i64,
        form: PeerContents,
        session: Session,
    ) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();
        let mut peer = DatabasePeer::get(&conn, id)?;
        peer.update(&conn, form)?;

        status_response(StatusCode::NO_CONTENT)
    }

    /// List all peers, including disabled ones. This is an admin-only endpoint.
    pub async fn list(session: Session) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();
        let mut peers = DatabasePeer::list(&conn)?
            .into_iter()
            .map(|peer| peer.inner)
            .collect::<Vec<_>>();
        inject_endpoints(&session, &mut peers);
        json_response(&peers)
    }

    pub async fn delete(id: i64, session: Session) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();
        DatabasePeer::disable(&conn, id)?;

        status_response(StatusCode::NO_CONTENT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test;
    use bytes::Buf;
    use shared::{Error, Peer};

    #[tokio::test]
    async fn test_add_peer() -> Result<(), Error> {
        let server = test::Server::new()?;

        let old_peers = DatabasePeer::list(&server.db().lock())?;

        let peer = test::developer_peer_contents("developer3", "10.80.64.4")?;

        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/peers", &peer)
            .await;

        assert_eq!(res.status(), StatusCode::CREATED);
        // The response contains the new peer information.
        let whole_body = hyper::body::aggregate(res).await?;
        let peer_res: Peer = serde_json::from_reader(whole_body.reader())?;

        assert_eq!(peer, peer_res.contents);

        // The number of peer entries in the database increased by 1.
        let new_peers = DatabasePeer::list(&server.db().lock())?;
        assert_eq!(old_peers.len() + 1, new_peers.len());

        Ok(())
    }

    #[tokio::test]
    async fn test_add_peer_with_invalid_name() -> Result<(), Error> {
        assert!(test::developer_peer_contents("devel oper", "10.80.64.4").is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_add_peer_with_duplicate_name() -> Result<(), Error> {
        let server = test::Server::new()?;

        let old_peers = DatabasePeer::list(&server.db().lock())?;

        // Try to add a peer with a name that is already taken.
        let peer = test::developer_peer_contents("developer2", "10.80.64.4")?;

        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/peers", &peer)
            .await;

        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // The number of peer entries in the database should not change.
        let new_peers = DatabasePeer::list(&server.db().lock())?;
        assert_eq!(old_peers.len(), new_peers.len());

        Ok(())
    }

    #[tokio::test]
    async fn test_add_peer_with_duplicate_ip() -> Result<(), Error> {
        let server = test::Server::new()?;

        let old_peers = DatabasePeer::list(&server.db().lock())?;

        // Try to add a peer with an IP that is already taken.
        let peer = test::developer_peer_contents("developer3", "10.80.64.3")?;

        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/peers", &peer)
            .await;

        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // The number of peer entries in the database should not change.
        let new_peers = DatabasePeer::list(&server.db().lock())?;
        assert_eq!(old_peers.len(), new_peers.len());

        Ok(())
    }

    #[tokio::test]
    async fn test_add_peer_with_outside_cidr_range_ip() -> Result<(), Error> {
        let server = test::Server::new()?;

        let old_peers = DatabasePeer::list(&server.db().lock())?;

        // Try to add IP outside of the CIDR network.
        let peer = test::developer_peer_contents("developer3", "10.80.65.4")?;
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/peers", &peer)
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // Try to use the network address as peer IP.
        let peer = test::developer_peer_contents("developer3", "10.80.64.0")?;
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/peers", &peer)
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // Try to use the broadcast address as peer IP.
        let peer = test::developer_peer_contents("developer3", "10.80.64.255")?;
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/peers", &peer)
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // The number of peer entries in the database should not change.
        let new_peers = DatabasePeer::list(&server.db().lock())?;
        assert_eq!(old_peers.len(), new_peers.len());

        Ok(())
    }

    #[tokio::test]
    async fn test_add_peer_from_non_admin() -> Result<(), Error> {
        let server = test::Server::new()?;

        let peer = test::developer_peer_contents("developer3", "10.80.64.4")?;

        // Try to create a new developer peer from a user peer.
        let res = server
            .form_request(test::USER1_PEER_IP, "POST", "/v1/admin/peers", &peer)
            .await;

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[tokio::test]
    async fn test_update_peer_from_admin() -> Result<(), Error> {
        let server = test::Server::new()?;
        let old_peer = DatabasePeer::get(&server.db.lock(), test::DEVELOPER1_PEER_ID)?;

        let change = PeerContents {
            name: "new-peer-name".parse()?,
            ..old_peer.contents.clone()
        };

        // Try to create a new developer peer from a user peer.
        let res = server
            .form_request(
                test::ADMIN_PEER_IP,
                "PUT",
                &format!("/v1/admin/peers/{}", test::DEVELOPER1_PEER_ID),
                &change,
            )
            .await;

        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let new_peer = DatabasePeer::get(&server.db.lock(), test::DEVELOPER1_PEER_ID)?;
        assert_eq!(&*new_peer.name, "new-peer-name");
        Ok(())
    }

    #[tokio::test]
    async fn test_update_peer_from_non_admin() -> Result<(), Error> {
        let server = test::Server::new()?;

        let peer = test::developer_peer_contents("developer3", "10.80.64.4")?;

        // Try to create a new developer peer from a user peer.
        let res = server
            .form_request(
                test::USER1_PEER_IP,
                "PUT",
                &format!("/v1/admin/peers/{}", test::DEVELOPER1_PEER_ID),
                &peer,
            )
            .await;

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[tokio::test]
    async fn test_list_all_peers_from_admin() -> Result<(), Error> {
        let server = test::Server::new()?;
        let res = server
            .request(test::ADMIN_PEER_IP, "GET", "/v1/admin/peers")
            .await;

        assert_eq!(res.status(), StatusCode::OK);

        let whole_body = hyper::body::aggregate(res).await?;
        let peers: Vec<Peer> = serde_json::from_reader(whole_body.reader())?;
        let peer_names = peers.iter().map(|p| &*p.contents.name).collect::<Vec<_>>();
        // An admin peer should see all the peers.
        assert_eq!(
            &[
                "innernet-server",
                "admin",
                "developer1",
                "developer2",
                "user1",
                "user2"
            ],
            &peer_names[..]
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_list_all_peers_from_non_admin() -> Result<(), Error> {
        let server = test::Server::new()?;
        let res = server
            .request(test::DEVELOPER1_PEER_IP, "GET", "/v1/admin/peers")
            .await;

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[tokio::test]
    async fn test_delete() -> Result<(), Error> {
        let server = test::Server::new()?;
        let old_peers = DatabasePeer::list(&server.db().lock())?;

        let res = server
            .request(
                test::ADMIN_PEER_IP,
                "DELETE",
                &format!("/v1/admin/peers/{}", test::USER1_PEER_ID),
            )
            .await;

        assert!(res.status().is_success());

        // The number of peer entries in the database decreased by 1.
        let all_peers = DatabasePeer::list(&server.db().lock())?;
        let new_peers = all_peers.iter().filter(|p| !p.is_disabled).count();
        assert_eq!(old_peers.len() - 1, new_peers);

        Ok(())
    }

    #[tokio::test]
    async fn test_delete_from_non_admin() -> Result<(), Error> {
        let server = test::Server::new()?;

        let old_peers = DatabasePeer::list(&server.db().lock())?;

        let res = server
            .request(
                test::DEVELOPER1_PEER_IP,
                "DELETE",
                &format!("/v1/admin/peers/{}", test::USER1_PEER_ID),
            )
            .await;

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // The number of peer entries in the database hasn't changed.
        let new_peers = DatabasePeer::list(&server.db().lock())?;
        assert_eq!(old_peers.len(), new_peers.len());

        Ok(())
    }

    #[tokio::test]
    async fn test_delete_unknown_id() -> Result<(), Error> {
        let server = test::Server::new()?;

        let res = server
            .request(
                test::ADMIN_PEER_IP,
                "DELETE",
                &format!("/v1/admin/peers/{}", test::USER1_PEER_ID + 100),
            )
            .await;

        // Trying to delete a peer of non-existing ID will result in error.
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        Ok(())
    }
}
