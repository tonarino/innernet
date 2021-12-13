use std::convert::TryFrom;

use axum::{
    body::Body,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("unauthorized access")]
    Unauthorized,

    #[error("object not found")]
    NotFound,

    #[error("invalid query")]
    InvalidQuery,

    #[error("endpoint gone")]
    Gone,

    #[error("internal database error")]
    Database(#[from] rusqlite::Error),

    #[error("internal WireGuard error")]
    WireGuard,

    #[error("internal I/O error")]
    Io(#[from] std::io::Error),

    #[error("JSON parsing/serialization error")]
    Json(#[from] serde_json::Error),

    #[error("Generic HTTP error")]
    Http(#[from] axum::http::Error),

    #[error("Generic Axum error")]
    Axum(#[from] axum::Error),

    #[error("Generic Hyper error")]
    Hyper(#[from] hyper::Error),
}

impl<'a> From<&'a ServerError> for StatusCode {
    fn from(error: &ServerError) -> StatusCode {
        use ServerError::*;
        match error {
            Unauthorized => StatusCode::UNAUTHORIZED,
            NotFound => StatusCode::NOT_FOUND,
            Gone => StatusCode::GONE,
            InvalidQuery | Json(_) => StatusCode::BAD_REQUEST,
            // Special-case the constraint violation situation.
            Database(rusqlite::Error::SqliteFailure(libsqlite3_sys::Error { code, .. }, ..))
                if *code == libsqlite3_sys::ErrorCode::ConstraintViolation =>
            {
                StatusCode::BAD_REQUEST
            }
            Database(rusqlite::Error::QueryReturnedNoRows) => StatusCode::NOT_FOUND,
            WireGuard | Io(_) | Database(_) | Http(_) | Axum(_) | Hyper(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        Response::builder()
            .status(StatusCode::from(&self))
            .body(axum::body::boxed(axum::body::Full::from(self.to_string())))
            .unwrap()
    }
}

impl TryFrom<ServerError> for Response<Body> {
    type Error = axum::http::Error;

    fn try_from(e: ServerError) -> Result<Self, Self::Error> {
        Response::builder()
            .status(StatusCode::from(&e))
            .body(Body::empty())
    }
}
