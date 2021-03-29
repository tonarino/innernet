//! A table to describe which CIDRs another CIDR is allowed to peer with.
//!
//! A peer belongs to one parent CIDR, and can by default see all peers within that parent.

use crate::{db::DatabaseAssociation, form_body, with_admin_session, AdminSession, Context};
use shared::AssociationContents;
use warp::{http::StatusCode, Filter};

pub mod routes {
    use super::*;

    pub fn all(
        context: Context,
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path("associations").and(
            list(context.clone())
                .or(create(context.clone()))
                .or(delete(context)),
        )
    }

    pub fn list(
        context: Context,
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path::end()
            .and(warp::get())
            .and(with_admin_session(context))
            .and_then(handlers::list)
    }

    pub fn create(
        context: Context,
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
        warp::path::end()
            .and(warp::post())
            .and(form_body())
            .and(with_admin_session(context))
            .and_then(handlers::create)
    }

    pub fn delete(
        context: Context,
    ) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
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
        contents: AssociationContents,
        session: AdminSession,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let conn = session.context.db.lock();

        DatabaseAssociation::create(&conn, contents)?;

        Ok(StatusCode::CREATED)
    }

    pub async fn list(session: AdminSession) -> Result<impl warp::Reply, warp::Rejection> {
        let conn = session.context.db.lock();
        let auths = DatabaseAssociation::list(&conn)?;

        Ok(warp::reply::json(&auths))
    }

    pub async fn delete(
        id: i64,
        session: AdminSession,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let conn = session.context.db.lock();
        DatabaseAssociation::delete(&conn, id)?;

        Ok(StatusCode::NO_CONTENT)
    }
}
