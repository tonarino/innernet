use std::collections::VecDeque;

use crate::{
    db::DatabaseCidr,
    util::{form_body, json_response, status_response},
    ServerError, Session,
};
use hyper::StatusCode;
use hyper::{Body, Method, Request, Response};
use shared::CidrContents;

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
        }
        (&Method::DELETE, Some(id)) => {
            let id: i64 = id.parse().map_err(|_| ServerError::NotFound)?;
            handlers::delete(id, session).await
        }
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

        json_status_response(&cidr, StatusCode::CREATED)
    }

    pub async fn list(session: Session) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();
        let cidrs = DatabaseCidr::list(&conn)?;

        json_response(&cidrs)
    }

    pub async fn delete(id: i64, session: Session) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();
        DatabaseCidr::delete(&conn, id)?;

        status_response(StatusCode::NO_CONTENT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{test, DatabasePeer};
    use anyhow::Result;
    use bytes::Buf;
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
    async fn test_cidr_name_uniqueness() -> Result<()> {
        let server = test::Server::new()?;

        let contents = CidrContents {
            name: "experimental".to_string(),
            cidr: test::EXPERIMENTAL_CIDR.parse()?,
            parent: Some(test::ROOT_CIDR_ID),
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
        };
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/cidrs", &contents)
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

        let res = server
            .form_request(test::USER1_PEER_IP, "POST", "/v1/admin/cidrs", &contents)
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
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/cidrs", &contents)
            .await;
        assert!(res.status().is_success());

        let contents = CidrContents {
            name: "experimental".to_string(),
            cidr: test::EXPERIMENTAL_SUBCIDR.parse()?,
            parent: Some(test::ROOT_CIDR_ID),
        };

        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/cidrs", &contents)
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
        let res = server
            .form_request(test::ADMIN_PEER_IP, "POST", "/v1/admin/cidrs", &contents)
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
}
