//! A table to describe which CIDRs another CIDR is allowed to peer with.
//!
//! A peer belongs to one parent CIDR, and can by default see all peers within that parent.

use std::collections::VecDeque;

use crate::{
    db::DatabaseAssociation,
    util::{form_body, json_response, status_response},
    ServerError, Session,
};
use hyper::{Body, Method, Request, Response, StatusCode};
use shared::AssociationContents;

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
        contents: AssociationContents,
        session: Session,
    ) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();

        DatabaseAssociation::create(&conn, contents)?;

        status_response(StatusCode::CREATED)
    }

    pub async fn list(session: Session) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();
        let auths = DatabaseAssociation::list(&conn)?;

        json_response(&auths)
    }

    pub async fn delete(id: i64, session: Session) -> Result<Response<Body>, ServerError> {
        let conn = session.context.db.lock();
        DatabaseAssociation::delete(&conn, id)?;

        status_response(StatusCode::NO_CONTENT)
    }
}
