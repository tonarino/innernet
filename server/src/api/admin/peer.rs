use crate::{
    api::inject_endpoints, db::DatabasePeer, with_admin_session, AdminSession, Context, ServerError,
};
use shared::PeerContents;
use warp::{
    http::{response::Response, StatusCode},
    Filter,
};
use wgctrl::DeviceConfigBuilder;

pub mod routes {
    use crate::form_body;

    use super::*;

    pub fn all(
        context: Context,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path("peers").and(
            list(context.clone())
                .or(list(context.clone()))
                .or(create(context.clone()))
                .or(update(context.clone()))
                .or(delete(context)),
        )
    }

    // POST /v1/admin/peers
    pub fn create(
        context: Context,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path::end()
            .and(warp::post())
            .and(form_body())
            .and(with_admin_session(context))
            .and_then(handlers::create)
    }

    // PUT /v1/admin/peers/:id
    pub fn update(
        context: Context,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path::param()
            .and(warp::path::end())
            .and(warp::put())
            .and(form_body())
            .and(with_admin_session(context))
            .and_then(handlers::update)
    }

    // GET /v1/admin/peers
    pub fn list(
        context: Context,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path::end()
            .and(warp::get())
            .and(with_admin_session(context))
            .and_then(handlers::list)
    }

    // DELETE /v1/admin/peers/:id
    pub fn delete(
        context: Context,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path::param()
            .and(warp::path::end())
            .and(warp::delete())
            .and(with_admin_session(context))
            .and_then(handlers::delete)
    }
}

mod handlers {
    use super::*;

    pub async fn create(
        form: PeerContents,
        session: AdminSession,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let conn = session.context.db.lock();

        let peer = DatabasePeer::create(&conn, form)?;
        log::info!("adding peer {}", &*peer);

        if cfg!(not(test)) {
            // Update the current WireGuard interface with the new peers.
            DeviceConfigBuilder::new()
                .add_peer((&*peer).into())
                .apply(&session.context.interface)
                .map_err(|_| ServerError::WireGuard)?;
            log::info!("updated WireGuard interface, adding {}", &*peer);
        }

        let response = Response::builder()
            .status(StatusCode::CREATED)
            .body(serde_json::to_string(&*peer).unwrap());
        Ok(response)
    }

    pub async fn update(
        id: i64,
        form: PeerContents,
        session: AdminSession,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let conn = session.context.db.lock();
        let mut peer = DatabasePeer::get(&conn, id)?;
        peer.update(&conn, form)?;

        Ok(StatusCode::NO_CONTENT)
    }

    /// List all peers, including disabled ones. This is an admin-only endpoint.
    pub async fn list(session: AdminSession) -> Result<impl warp::Reply, warp::Rejection> {
        let conn = session.context.db.lock();
        let mut peers = DatabasePeer::list(&conn)?
            .into_iter()
            .map(|peer| peer.inner)
            .collect::<Vec<_>>();
        inject_endpoints(&session, &mut peers);
        Ok(warp::reply::json(&peers))
    }

    pub async fn delete(
        id: i64,
        session: AdminSession,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let conn = session.context.db.lock();
        DatabasePeer::disable(&conn, id)?;

        Ok(StatusCode::NO_CONTENT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test;
    use anyhow::Result;
    use shared::Peer;

    #[tokio::test]
    async fn test_add_peer() -> Result<()> {
        let server = test::Server::new()?;

        let old_peers = DatabasePeer::list(&server.db().lock())?;

        let peer = test::developer_peer_contents("developer3", "10.80.64.4")?;

        let filter = crate::routes(server.context());
        let res = server.post_request_from_ip(test::ADMIN_PEER_IP)
            .path("/v1/admin/peers")
            .body(serde_json::to_string(&peer)?)
            .reply(&filter)
            .await;

        assert_eq!(res.status(), StatusCode::CREATED);
        // The response contains the new peer information.
        let peer_res: Peer = serde_json::from_slice(&res.body())?;
        assert_eq!(peer, peer_res.contents);

        // The number of peer entries in the database increased by 1.
        let new_peers = DatabasePeer::list(&server.db().lock())?;
        assert_eq!(old_peers.len() + 1, new_peers.len());

        Ok(())
    }

    #[tokio::test]
    async fn test_add_peer_with_invalid_name() -> Result<()> {
        let server = test::Server::new()?;

        let peer = test::developer_peer_contents("devel oper", "10.80.64.4")?;

        let filter = crate::routes(server.context());
        let res = server.post_request_from_ip(test::ADMIN_PEER_IP)
            .path("/v1/admin/peers")
            .body(serde_json::to_string(&peer)?)
            .reply(&filter)
            .await;

        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn test_add_peer_with_duplicate_name() -> Result<()> {
        let server = test::Server::new()?;

        let old_peers = DatabasePeer::list(&server.db().lock())?;

        // Try to add a peer with a name that is already taken.
        let peer = test::developer_peer_contents("developer2", "10.80.64.4")?;

        let filter = crate::routes(server.context());
        let res = server.post_request_from_ip(test::ADMIN_PEER_IP)
            .path("/v1/admin/peers")
            .body(serde_json::to_string(&peer)?)
            .reply(&filter)
            .await;

        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // The number of peer entries in the database should not change.
        let new_peers = DatabasePeer::list(&server.db().lock())?;
        assert_eq!(old_peers.len(), new_peers.len());

        Ok(())
    }

    #[tokio::test]
    async fn test_add_peer_with_duplicate_ip() -> Result<()> {
        let server = test::Server::new()?;

        let old_peers = DatabasePeer::list(&server.db().lock())?;

        // Try to add a peer with an IP that is already taken.
        let peer = test::developer_peer_contents("developer3", "10.80.64.3")?;

        let filter = crate::routes(server.context());
        let res = server.post_request_from_ip(test::ADMIN_PEER_IP)
            .path("/v1/admin/peers")
            .body(serde_json::to_string(&peer)?)
            .reply(&filter)
            .await;

        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // The number of peer entries in the database should not change.
        let new_peers = DatabasePeer::list(&server.db().lock())?;
        assert_eq!(old_peers.len(), new_peers.len());

        Ok(())
    }

    #[tokio::test]
    async fn test_add_peer_with_outside_cidr_range_ip() -> Result<()> {
        let server = test::Server::new()?;
        let filter = crate::routes(server.context());

        let old_peers = DatabasePeer::list(&server.db().lock())?;

        // Try to add IP outside of the CIDR network.
        let peer = test::developer_peer_contents("developer3", "10.80.65.4")?;
        let res = server.post_request_from_ip(test::ADMIN_PEER_IP)
            .path("/v1/admin/peers")
            .body(serde_json::to_string(&peer)?)
            .reply(&filter)
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // Try to use the network address as peer IP.
        let peer = test::developer_peer_contents("developer3", "10.80.64.0")?;
        let res = server.post_request_from_ip(test::ADMIN_PEER_IP)
            .path("/v1/admin/peers")
            .body(serde_json::to_string(&peer)?)
            .reply(&filter)
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // Try to use the broadcast address as peer IP.
        let peer = test::developer_peer_contents("developer3", "10.80.64.255")?;
        let res = server.post_request_from_ip(test::ADMIN_PEER_IP)
            .path("/v1/admin/peers")
            .body(serde_json::to_string(&peer)?)
            .reply(&filter)
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // The number of peer entries in the database should not change.
        let new_peers = DatabasePeer::list(&server.db().lock())?;
        assert_eq!(old_peers.len(), new_peers.len());

        Ok(())
    }

    #[tokio::test]
    async fn test_add_peer_from_non_admin() -> Result<()> {
        let server = test::Server::new()?;

        let peer = test::developer_peer_contents("developer3", "10.80.64.4")?;

        // Try to create a new developer peer from a user peer.
        let filter = crate::routes(server.context());
        let res = server.post_request_from_ip(test::USER1_PEER_IP)
            .path("/v1/admin/peers")
            .body(serde_json::to_string(&peer)?)
            .reply(&filter)
            .await;

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[tokio::test]
    async fn test_update_peer_from_admin() -> Result<()> {
        let server = test::Server::new()?;
        let old_peer = DatabasePeer::get(&server.db.lock(), test::DEVELOPER1_PEER_ID)?;

        let change = PeerContents {
            name: "new-peer-name".to_string(),
            ..old_peer.contents.clone()
        };

        // Try to create a new developer peer from a user peer.
        let filter = crate::routes(server.context());
        let res = server.put_request_from_ip(test::ADMIN_PEER_IP)
            .path(&format!("/v1/admin/peers/{}", test::DEVELOPER1_PEER_ID))
            .body(serde_json::to_string(&change)?)
            .reply(&filter)
            .await;

        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let new_peer = DatabasePeer::get(&server.db.lock(), test::DEVELOPER1_PEER_ID)?;
        assert_eq!(new_peer.name, "new-peer-name");
        Ok(())
    }

    #[tokio::test]
    async fn test_update_peer_from_non_admin() -> Result<()> {
        let server = test::Server::new()?;

        let peer = test::developer_peer_contents("developer3", "10.80.64.4")?;

        // Try to create a new developer peer from a user peer.
        let filter = crate::routes(server.context());
        let res = server.put_request_from_ip(test::USER1_PEER_IP)
            .path(&format!("/v1/admin/peers/{}", test::ADMIN_PEER_ID))
            .body(serde_json::to_string(&peer)?)
            .reply(&filter)
            .await;

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[tokio::test]
    async fn test_list_all_peers_from_admin() -> Result<()> {
        let server = test::Server::new()?;
        let filter = crate::routes(server.context());
        let res = server.request_from_ip(test::ADMIN_PEER_IP)
            .path("/v1/admin/peers")
            .reply(&filter)
            .await;

        assert_eq!(res.status(), StatusCode::OK);

        let peers: Vec<Peer> = serde_json::from_slice(&res.body())?;
        let peer_names = peers.iter().map(|p| &p.contents.name).collect::<Vec<_>>();
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
    async fn test_list_all_peers_from_non_admin() -> Result<()> {
        let server = test::Server::new()?;
        let filter = crate::routes(server.context());
        let res = server.request_from_ip(test::DEVELOPER1_PEER_IP)
            .path("/v1/admin/peers")
            .reply(&filter)
            .await;

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[tokio::test]
    async fn test_delete() -> Result<()> {
        let server = test::Server::new()?;
        let filter = crate::routes(server.context());

        let old_peers = DatabasePeer::list(&server.db().lock())?;

        let res = server.request_from_ip(test::ADMIN_PEER_IP)
            .method("DELETE")
            .path(&format!("/v1/admin/peers/{}", test::USER1_PEER_ID))
            .reply(&filter)
            .await;

        assert!(res.status().is_success());

        // The number of peer entries in the database decreased by 1.
        let all_peers = DatabasePeer::list(&server.db().lock())?;
        let new_peers = all_peers.iter().filter(|p| !p.is_disabled).count();
        assert_eq!(old_peers.len() - 1, new_peers);

        Ok(())
    }

    #[tokio::test]
    async fn test_delete_from_non_admin() -> Result<()> {
        let server = test::Server::new()?;
        let filter = crate::routes(server.context());

        let old_peers = DatabasePeer::list(&server.db().lock())?;

        let res = server.request_from_ip(test::DEVELOPER1_PEER_IP)
            .method("DELETE")
            .path(&format!("/v1/admin/peers/{}", test::USER1_PEER_ID))
            .reply(&filter)
            .await;

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // The number of peer entries in the database hasn't changed.
        let new_peers = DatabasePeer::list(&server.db().lock())?;
        assert_eq!(old_peers.len(), new_peers.len());

        Ok(())
    }

    #[tokio::test]
    async fn test_delete_unknown_id() -> Result<()> {
        let server = test::Server::new()?;
        let filter = crate::routes(server.context());

        let res = server.request_from_ip(test::ADMIN_PEER_IP)
            .method("DELETE")
            .path(&format!("/v1/admin/peers/{}", test::USER1_PEER_ID + 100))
            .reply(&filter)
            .await;

        // Trying to delete a peer of non-existing ID will result in error.
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        Ok(())
    }
}
