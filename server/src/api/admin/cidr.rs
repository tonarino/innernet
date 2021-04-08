use crate::{db::DatabaseCidr, form_body, with_admin_session, AdminSession, Context};
use shared::CidrContents;
use warp::{
    http::{response::Response, StatusCode},
    Filter,
};

pub mod routes {
    use super::*;

    pub fn all(
        context: Context,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path("cidrs").and(
            list(context.clone())
                .or(create(context.clone()))
                .or(delete(context)),
        )
    }

    pub fn list(
        context: Context,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path::end()
            .and(warp::get())
            .and(with_admin_session(context))
            .and_then(handlers::list)
    }

    pub fn create(
        context: Context,
    ) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
        warp::path::end()
            .and(warp::post())
            .and(form_body())
            .and(with_admin_session(context))
            .and_then(handlers::create)
    }

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
        contents: CidrContents,
        session: AdminSession,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let conn = session.context.db.lock();

        let cidr = DatabaseCidr::create(&conn, contents)?;

        let response = Response::builder()
            .status(StatusCode::CREATED)
            .body(serde_json::to_string(&cidr).unwrap())
            .unwrap();
        Ok(response)
    }

    pub async fn list(session: AdminSession) -> Result<impl warp::Reply, warp::Rejection> {
        let conn = session.context.db.lock();
        let cidrs = DatabaseCidr::list(&conn)?;

        Ok(warp::reply::json(&cidrs))
    }

    pub async fn delete(
        id: i64,
        session: AdminSession,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let conn = session.context.db.lock();
        DatabaseCidr::delete(&conn, id)?;

        Ok(StatusCode::NO_CONTENT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test, DatabasePeer};
    use anyhow::Result;
    use shared::Cidr;

    #[tokio::test]
    async fn test_cidr_add() -> Result<()> {
        let server = test::Server::new()?;

        let old_cidrs = DatabaseCidr::list(&server.db().lock())?;

        let contents = CidrContents {
            name: "experimental".to_string(),
            cidr: test::EXPERIMENTAL_CIDR.parse()?,
            parent: Some(test::ROOT_CIDR_ID),
        };

        let filter = crate::routes(server.context());
        let res = server.post_request_from_ip(test::ADMIN_PEER_IP)
            .path("/v1/admin/cidrs")
            .body(serde_json::to_string(&contents)?)
            .reply(&filter)
            .await;

        assert_eq!(res.status(), 201);

        let cidr_res: Cidr = serde_json::from_slice(&res.body())?;
        assert_eq!(contents, cidr_res.contents);

        let new_cidrs = DatabaseCidr::list(&server.db().lock())?;
        assert_eq!(old_cidrs.len() + 1, new_cidrs.len());

        Ok(())
    }

    #[tokio::test]
    async fn test_cidr_name_uniqueness() -> Result<()> {
        let server = test::Server::new()?;

        let contents = CidrContents {
            name: "experimental".to_string(),
            cidr: test::EXPERIMENTAL_CIDR.parse()?,
            parent: Some(test::ROOT_CIDR_ID),
        };

        let filter = crate::routes(server.context());
        let res = server.post_request_from_ip(test::ADMIN_PEER_IP)
            .path("/v1/admin/cidrs")
            .body(serde_json::to_string(&contents)?)
            .reply(&filter)
            .await;
        assert!(res.status().is_success());
        let cidr_res: Cidr = serde_json::from_slice(&res.body())?;

        let contents = CidrContents {
            name: "experimental".to_string(),
            cidr: test::EXPERIMENTAL_SUBCIDR.parse()?,
            parent: Some(cidr_res.id),
        };
        let res = server.post_request_from_ip(test::ADMIN_PEER_IP)
            .path("/v1/admin/cidrs")
            .body(serde_json::to_string(&contents)?)
            .reply(&filter)
            .await;
        assert!(!res.status().is_success());

        Ok(())
    }

    #[tokio::test]
    async fn test_cidr_create_auth() -> Result<()> {
        let server = test::Server::new()?;

        let contents = CidrContents {
            name: "experimental".to_string(),
            cidr: test::EXPERIMENTAL_CIDR.parse()?,
            parent: Some(test::ROOT_CIDR_ID),
        };

        let filter = crate::routes(server.context());
        let res = server.post_request_from_ip(test::USER1_PEER_IP)
            .path("/v1/admin/cidrs")
            .body(serde_json::to_string(&contents)?)
            .reply(&filter)
            .await;
        assert!(!res.status().is_success());

        Ok(())
    }

    #[tokio::test]
    async fn test_cidr_bad_parent() -> Result<()> {
        let server = test::Server::new()?;

        let contents = CidrContents {
            name: "experimental".to_string(),
            cidr: test::EXPERIMENTAL_CIDR.parse()?,
            parent: Some(test::ROOT_CIDR_ID),
        };
        let filter = crate::routes(server.context());
        let res = server.post_request_from_ip(test::ADMIN_PEER_IP)
            .path("/v1/admin/cidrs")
            .body(serde_json::to_string(&contents)?)
            .reply(&filter)
            .await;
        assert!(res.status().is_success());

        let contents = CidrContents {
            name: "experimental".to_string(),
            cidr: test::EXPERIMENTAL_SUBCIDR.parse()?,
            parent: Some(test::ROOT_CIDR_ID),
        };

        let filter = crate::routes(server.context());
        let res = server.post_request_from_ip(test::ADMIN_PEER_IP)
            .path("/v1/admin/cidrs")
            .body(serde_json::to_string(&contents)?)
            .reply(&filter)
            .await;
        assert!(!res.status().is_success());

        Ok(())
    }

    #[tokio::test]
    async fn test_cidr_overlap() -> Result<()> {
        let server = test::Server::new()?;

        let contents = CidrContents {
            name: "experimental".to_string(),
            cidr: "10.80.1.0/21".parse()?,
            parent: Some(test::ROOT_CIDR_ID),
        };
        let filter = crate::routes(server.context());
        let res = server.post_request_from_ip(test::ADMIN_PEER_IP)
            .path("/v1/admin/cidrs")
            .body(serde_json::to_string(&contents)?)
            .reply(&filter)
            .await;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        Ok(())
    }

    #[tokio::test]
    async fn test_cidr_delete_fail_with_child_cidr() -> Result<()> {
        let server = test::Server::new()?;

        let experimental_cidr = DatabaseCidr::create(
            &server.db().lock(),
            CidrContents {
                name: "experimental".to_string(),
                cidr: test::EXPERIMENTAL_CIDR.parse()?,
                parent: Some(test::ROOT_CIDR_ID),
            },
        )?;
        let experimental_subcidr = DatabaseCidr::create(
            &server.db().lock(),
            CidrContents {
                name: "experimental subcidr".to_string(),
                cidr: test::EXPERIMENTAL_SUBCIDR.parse()?,
                parent: Some(experimental_cidr.id),
            },
        )?;

        let filter = crate::routes(server.context());

        let res = server.request_from_ip(test::ADMIN_PEER_IP)
            .method("DELETE")
            .path(&format!("/v1/admin/cidrs/{}", experimental_cidr.id))
            .reply(&filter)
            .await;
        // Should fail because child CIDR exists.
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        let res = server.request_from_ip(test::ADMIN_PEER_IP)
            .method("DELETE")
            .path(&format!("/v1/admin/cidrs/{}", experimental_subcidr.id))
            .reply(&filter)
            .await;
        // Deleting child "leaf" CIDR should fail because peer exists inside it.
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        let res = server.request_from_ip(test::ADMIN_PEER_IP)
            .method("DELETE")
            .path(&format!("/v1/admin/cidrs/{}", experimental_cidr.id))
            .reply(&filter)
            .await;
        // Now deleting parent CIDR should work because child is gone.
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        Ok(())
    }

    #[tokio::test]
    async fn test_cidr_delete_fail_with_peer_inside() -> Result<()> {
        let server = test::Server::new()?;

        let experimental_cidr = DatabaseCidr::create(
            &server.db().lock(),
            CidrContents {
                name: "experimental".to_string(),
                cidr: test::EXPERIMENTAL_CIDR.parse()?,
                parent: Some(test::ROOT_CIDR_ID),
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

        let filter = crate::routes(server.context());

        let res = server.request_from_ip(test::ADMIN_PEER_IP)
            .method("DELETE")
            .path(&format!("/v1/admin/cidrs/{}", experimental_cidr.id))
            .reply(&filter)
            .await;
        // Deleting CIDR should fail because peer exists inside it.
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        Ok(())
    }
}
