use std::collections::VecDeque;

use crate::{
    db::DatabaseCidr,
    util::{form_body, json_response, status_response},
    ServerError, Session,
};
use hyper::{Body, Method, Request, Response, StatusCode};
use innernet_shared::CidrContents;

pub async fn routes(
    req: Request<Body>,
    mut components: VecDeque<String>,
    session: Session,
) -> Result<Response<Body>, ServerError> {
    match (
        req.method(),
        components.pop_front().as_deref(),
        components.pop_front().as_deref(),
    ) {
        (&Method::GET, None, None) => handlers::list(session).await,
        (&Method::POST, None, None) => {
            let form = form_body(req).await?;
            handlers::create(form, session).await
        },
        (&Method::PUT, Some(id), None) => {
            let id: i64 = id.parse().map_err(|_| ServerError::NotFound)?;
            let form = form_body(req).await?;
            handlers::update(id, form, session).await
        },
        (&Method::PUT, Some(id), Some("enable")) => {
            let id: i64 = id.parse().map_err(|_| ServerError::NotFound)?;
            handlers::enable(id, session).await
        },
        (&Method::PUT, Some(id), Some("disable")) => {
            let id: i64 = id.parse().map_err(|_| ServerError::NotFound)?;
            handlers::disable(id, session).await
        },
        (&Method::DELETE, Some(id), None) => {
            let id: i64 = id.parse().map_err(|_| ServerError::NotFound)?;
            handlers::delete(id, session).await
        },
        _ => Err(ServerError::NotFound),
    }
}

mod handlers {
    use crate::util::json_status_response;

    use super::*;

    pub async fn create(
        contents: CidrContents,
        session: Session,
    ) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();

        let cidr = DatabaseCidr::create(&conn, contents)?;

        json_status_response(cidr, StatusCode::CREATED)
    }

    pub async fn update(
        id: i64,
        form: CidrContents,
        session: Session,
    ) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();
        let cidr = DatabaseCidr::get(&conn, id)?;
        DatabaseCidr::from(cidr).update(&conn, form)?;

        status_response(StatusCode::NO_CONTENT)
    }

    pub async fn list(session: Session) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();
        let cidrs = DatabaseCidr::list(&conn)?;

        json_response(cidrs)
    }

    pub async fn delete(id: i64, session: Session) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();
        DatabaseCidr::delete(&conn, id)?;

        status_response(StatusCode::NO_CONTENT)
    }

    pub async fn enable(id: i64, session: Session) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();
        let cidr = DatabaseCidr::get(&conn, id)?;

        DatabaseCidr::from(cidr.clone()).update(
            &conn,
            CidrContents {
                is_disabled: false,
                ..cidr.contents.clone()
            },
        )?;

        status_response(StatusCode::NO_CONTENT)
    }

    pub async fn disable(id: i64, session: Session) -> Result<Response<Body>, ServerError> {
        use crate::DatabasePeer;

        let conn = session.context.db.lock();
        let cidr = DatabaseCidr::get(&conn, id)?;
        let peers = DatabasePeer::list(&conn)?;

        // Check if any peers in this CIDR are enabled
        let enabled_peers: Vec<_> = peers
            .iter()
            .filter(|p| p.cidr_id == id && !p.is_disabled)
            .collect();

        if !enabled_peers.is_empty() {
            return Err(ServerError::InvalidQuery);
        }

        DatabaseCidr::from(cidr.clone()).update(
            &conn,
            CidrContents {
                is_disabled: true,
                ..cidr.contents.clone()
            },
        )?;

        status_response(StatusCode::NO_CONTENT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test, DatabasePeer};
    use anyhow::Result;
    use bytes::Buf;
    use innernet_shared::{Cidr, Error};

    #[tokio::test]
    async fn test_cidr_add() -> Result<(), Error> {
        let server = test::Server::new()?;

        let old_cidrs = DatabaseCidr::list(&server.db().lock())?;

        let contents = CidrContents {
            name: "experimental".to_string(),
            cidr: test::EXPERIMENTAL_CIDR.parse()?,
            parent: Some(test::ROOT_CIDR_ID),
            is_disabled: false,
        };

        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/cidrs", &contents)
            .await;

        assert_eq!(res.status(), 201);

        let whole_body = hyper::body::aggregate(res).await?;
        let cidr_res: Cidr = serde_json::from_reader(whole_body.reader())?;
        assert_eq!(contents, cidr_res.contents);

        let new_cidrs = DatabaseCidr::list(&server.db().lock())?;
        assert_eq!(old_cidrs.len() + 1, new_cidrs.len());

        Ok(())
    }

    #[tokio::test]
    async fn test_cidr_name_uniqueness() -> Result<(), Error> {
        let server = test::Server::new()?;

        let contents = CidrContents {
            name: "experimental".to_string(),
            cidr: test::EXPERIMENTAL_CIDR.parse()?,
            parent: Some(test::ROOT_CIDR_ID),
            is_disabled: false,
        };

        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/cidrs", &contents)
            .await;
        assert!(res.status().is_success());
        let whole_body = hyper::body::aggregate(res).await?;
        let cidr_res: Cidr = serde_json::from_reader(whole_body.reader())?;

        let contents = CidrContents {
            name: "experimental".to_string(),
            cidr: test::EXPERIMENTAL_SUBCIDR.parse()?,
            parent: Some(cidr_res.id),
            is_disabled: false,
        };
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/cidrs", &contents)
            .await;
        assert!(!res.status().is_success());

        Ok(())
    }

    #[tokio::test]
    async fn test_cidr_create_auth() -> Result<(), Error> {
        let server = test::Server::new()?;

        let contents = CidrContents {
            name: "experimental".to_string(),
            cidr: test::EXPERIMENTAL_CIDR.parse()?,
            parent: Some(test::ROOT_CIDR_ID),
            is_disabled: false,
        };

        let res = server
            .form_request(test::USER1_PEER_IP, "POST", "/v1/admin/cidrs", &contents)
            .await;
        assert!(!res.status().is_success());

        Ok(())
    }

    #[tokio::test]
    async fn test_cidr_bad_parent() -> Result<(), Error> {
        let server = test::Server::new()?;

        let contents = CidrContents {
            name: "experimental".to_string(),
            cidr: test::EXPERIMENTAL_CIDR.parse()?,
            parent: Some(test::ROOT_CIDR_ID),
            is_disabled: false,
        };
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/cidrs", &contents)
            .await;
        assert!(res.status().is_success());

        let contents = CidrContents {
            name: "experimental".to_string(),
            cidr: test::EXPERIMENTAL_SUBCIDR.parse()?,
            parent: Some(test::ROOT_CIDR_ID),
            is_disabled: false,
        };

        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/cidrs", &contents)
            .await;
        assert!(!res.status().is_success());

        Ok(())
    }

    #[tokio::test]
    async fn test_cidr_overlap() -> Result<(), Error> {
        let server = test::Server::new()?;

        let contents = CidrContents {
            name: "experimental".to_string(),
            cidr: "10.80.1.0/21".parse()?,
            parent: Some(test::ROOT_CIDR_ID),
            is_disabled: false,
        };
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/cidrs", &contents)
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        Ok(())
    }

    #[tokio::test]
    async fn test_cidr_delete_fail_with_child_cidr() -> Result<(), Error> {
        let server = test::Server::new()?;

        let experimental_cidr = DatabaseCidr::create(
            &server.db().lock(),
            CidrContents {
                name: "experimental".to_string(),
                cidr: test::EXPERIMENTAL_CIDR.parse()?,
                parent: Some(test::ROOT_CIDR_ID),
                is_disabled: false,
            },
        )?;
        let experimental_subcidr = DatabaseCidr::create(
            &server.db().lock(),
            CidrContents {
                name: "experimental subcidr".to_string(),
                cidr: test::EXPERIMENTAL_SUBCIDR.parse()?,
                parent: Some(experimental_cidr.id),
                is_disabled: false,
            },
        )?;

        let res = server
            .request(
                test::ADMIN_PEER_IP,
                "DELETE",
                &format!("/v1/admin/cidrs/{}", experimental_cidr.id),
            )
            .await;
        // Should fail because child CIDR exists.
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        let res = server
            .request(
                test::ADMIN_PEER_IP,
                "DELETE",
                &format!("/v1/admin/cidrs/{}", experimental_subcidr.id),
            )
            .await;
        // Deleting child "leaf" CIDR should fail because peer exists inside it.
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let res = server
            .request(
                test::ADMIN_PEER_IP,
                "DELETE",
                &format!("/v1/admin/cidrs/{}", experimental_cidr.id),
            )
            .await;
        // Now deleting parent CIDR should work because child is gone.
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        Ok(())
    }

    #[tokio::test]
    async fn test_cidr_delete_fail_with_peer_inside() -> Result<(), Error> {
        let server = test::Server::new()?;

        let experimental_cidr = DatabaseCidr::create(
            &server.db().lock(),
            CidrContents {
                name: "experimental".to_string(),
                cidr: test::EXPERIMENTAL_CIDR.parse()?,
                parent: Some(test::ROOT_CIDR_ID),
                is_disabled: false,
            },
        )?;

        let _experiment_peer = DatabasePeer::create(
            &server.db().lock(),
            test::peer_contents(
                "experiment-peer",
                test::EXPERIMENT_SUBCIDR_PEER_IP,
                experimental_cidr.id,
                false,
            )?,
        )?;

        let res = server
            .request(
                test::ADMIN_PEER_IP,
                "DELETE",
                &format!("/v1/admin/cidrs/{}", experimental_cidr.id),
            )
            .await;
        // Deleting CIDR should fail because peer exists inside it.
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        Ok(())
    }

    #[tokio::test]
    async fn test_cidr_disable_with_enabled_peers() -> Result<(), Error> {
        let server = test::Server::new()?;

        // Create a test CIDR
        let cidr = CidrContents {
            name: "test-cidr".to_string(),
            cidr: test::EXPERIMENTAL_CIDR.parse()?,
            parent: Some(test::ROOT_CIDR_ID),
            is_disabled: false,
        };

        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/cidrs", &cidr)
            .await;
        assert!(res.status().is_success());
        let whole_body = hyper::body::aggregate(res).await?;
        let test_cidr: Cidr = serde_json::from_reader(whole_body.reader())?;

        // Create an enabled peer in the CIDR
        let peer = test::peer_contents(
            "test-peer",
            test::EXPERIMENT_SUBCIDR_PEER_IP,
            test_cidr.id,
            false,
        )?;
        DatabasePeer::create(&server.db().lock(), peer)?;

        // Try to disable the CIDR (should fail)
        let res = server
            .request(
                test::ADMIN_PEER_IP,
                "PUT",
                &format!("/v1/admin/cidrs/{}/disable", test_cidr.id),
            )
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        Ok(())
    }

    #[tokio::test]
    async fn test_cidr_disable_with_disabled_peers() -> Result<(), Error> {
        let server = test::Server::new()?;

        // Create a test CIDR
        let cidr = CidrContents {
            name: "test-cidr2".to_string(),
            cidr: "10.80.3.0/24".parse()?,
            parent: Some(test::ROOT_CIDR_ID),
            is_disabled: false,
        };

        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/cidrs", &cidr)
            .await;
        assert!(res.status().is_success());
        let whole_body = hyper::body::aggregate(res).await?;
        let test_cidr: Cidr = serde_json::from_reader(whole_body.reader())?;

        // Create a disabled peer in the CIDR
        let mut peer = test::peer_contents("test-peer2", "10.80.3.1", test_cidr.id, false)?;
        peer.is_disabled = true;
        DatabasePeer::create(&server.db().lock(), peer)?;

        // Try to disable the CIDR (should succeed)
        let res = server
            .request(
                test::ADMIN_PEER_IP,
                "PUT",
                &format!("/v1/admin/cidrs/{}/disable", test_cidr.id),
            )
            .await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        // Verify CIDR is disabled
        let disabled_cidr = DatabaseCidr::get(&server.db().lock(), test_cidr.id)?;
        assert!(disabled_cidr.is_disabled);

        Ok(())
    }

    #[tokio::test]
    async fn test_cidr_enable() -> Result<(), Error> {
        let server = test::Server::new()?;

        // Create a disabled CIDR
        let cidr = CidrContents {
            name: "test-cidr3".to_string(),
            cidr: "10.80.4.0/24".parse()?,
            parent: Some(test::ROOT_CIDR_ID),
            is_disabled: true,
        };

        let db = server.db();
        let conn = db.lock();
        let test_cidr = DatabaseCidr::create(&conn, cidr)?;
        drop(conn);

        // Enable the CIDR
        let res = server
            .request(
                test::ADMIN_PEER_IP,
                "PUT",
                &format!("/v1/admin/cidrs/{}/enable", test_cidr.id),
            )
            .await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        // Verify CIDR is enabled
        let enabled_cidr = DatabaseCidr::get(&server.db().lock(), test_cidr.id)?;
        assert!(!enabled_cidr.is_disabled);

        Ok(())
    }
}
