use thiserror::Error;
use warp::{http::StatusCode, reject::Rejection};

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("unauthorized access")]
    Unauthorized,

    #[error("object not found")]
    NotFound,

    #[error("invalid query")]
    InvalidQuery,

    #[error("internal database error")]
    Database(#[from] rusqlite::Error),

    #[error("internal WireGuard error")]
    WireGuard,

    #[error("internal I/O error")]
    Io(#[from] std::io::Error),
}

impl warp::reject::Reject for ServerError {}

pub async fn handle_rejection(err: Rejection) -> Result<StatusCode, warp::Rejection> {
    eprintln!("rejection: {:?}", err);
    if let Some(error) = err.find::<ServerError>() {
        Ok(error.into())
    } else {
        Err(err)
    }
}

impl<'a> From<&'a ServerError> for StatusCode {
    fn from(error: &ServerError) -> StatusCode {
        use ServerError::*;
        match error {
            Unauthorized => StatusCode::UNAUTHORIZED,
            NotFound => StatusCode::NOT_FOUND,
            InvalidQuery => StatusCode::BAD_REQUEST,
            // Special-case the constraint violation situation.
            Database(rusqlite::Error::SqliteFailure(libsqlite3_sys::Error { code, .. }, ..))
                if *code == libsqlite3_sys::ErrorCode::ConstraintViolation =>
            {
                StatusCode::BAD_REQUEST
            },
            Database(rusqlite::Error::QueryReturnedNoRows) => StatusCode::NOT_FOUND,
            WireGuard | Io(_) | Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
