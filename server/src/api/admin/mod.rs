use std::collections::VecDeque;

use axum::{
    body::Body,
    http::{Request, Response},
};

use crate::{ServerError, Session};

pub mod association;
pub mod cidr;
pub mod peer;

pub async fn routes(
    req: Request<Body>,
    mut components: VecDeque<String>,
    session: Session,
) -> Result<Response<Body>, ServerError> {
    if !session.admin_capable() {
        return Err(ServerError::Unauthorized);
    }

    match components.pop_front().as_deref() {
        Some("associations") => association::routes(req, components, session).await,
        Some("cidrs") => cidr::routes(req, components, session).await,
        Some("peers") => peer::routes(req, components, session).await,
        _ => Err(ServerError::NotFound),
    }
}
